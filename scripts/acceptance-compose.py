#!/usr/bin/env python3
"""Exercise a fresh Compose install using disposable local accounts and volumes.

Requires Python 3.10+, Docker with Compose, and an already built Grantline image.
Never contacts a provider or prints credentials. Only this run's randomly named
Compose project is removed. Existing installations and images are left intact.
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Locally available application image')
    parser.add_argument('--port', type=int, default=8085)
    parser.add_argument('--compose-file', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'compose.yaml')
    args = parser.parse_args()
    require(1024 <= args.port <= 65535, 'Use an unprivileged test port')
    project = 'grantline-linux-' + uuid.uuid4().hex[:12]
    origin = f'http://127.0.0.1:{args.port}'
    env = dict(os.environ, GRANTLINE_IMAGE=args.image,
               GRANTLINE_PORT=str(args.port), GRANTLINE_PUBLIC_URL=origin)
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPCookieProcessor(jar))
    csrf = ''

    def request(method, path, body=None, want=200, html=False):
        data = None if body is None else json.dumps(body).encode()
        headers = {'Origin': origin, 'Content-Type': 'application/json',
                   'X-Grantline-CSRF': csrf}
        req = urllib.request.Request(origin + path, data=data, headers=headers, method=method)
        try:
            response = client.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.status == want, f'{method} {path}: HTTP {response.status}, expected {want}')
            result = response.read()
        return result.decode() if html else json.loads(result)

    def refresh_csrf():
        nonlocal csrf
        session = request('GET', '/api/v1/auth/session')
        csrf = session['csrf']
        return session

    def totp(secret, step):
        key = base64.b32decode(secret + '=' * (-len(secret) % 8))
        mac = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
        offset = mac[-1] & 15
        number = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7fffffff
        return f'{number % 1000000:06d}'

    # An explicit empty env file prevents a workstation .env from selecting a
    # different installation. Environment settings below belong to child commands.
    with tempfile.TemporaryDirectory(prefix=project + '-') as temporary:
        env_file = Path(temporary) / 'empty.env'
        env_file.touch()
        command = ['docker', 'compose', '--env-file', str(env_file), '-p', project,
                   '-f', str(args.compose_file.resolve())]

        def compose(*arguments, capture=False, check=True):
            return subprocess.run(command + list(arguments), env=env, check=check,
                                  capture_output=capture, text=True, timeout=300)

        def secret_fingerprints():
            fingerprints = {}
            for name in ('encryption-key', 'setup-token', 'database-url'):
                value = compose('exec', '-T', 'app', 'cat',
                                '/var/lib/grantline/secrets/' + name, capture=True).stdout
                fingerprints[name] = hashlib.sha256(value.encode()).hexdigest()
            return fingerprints

        try:
            compose('up', '-d', '--wait', '--wait-timeout', '180')
            request('GET', '/healthz')
            request('GET', '/readyz')
            status = request('GET', '/api/v1/status')
            require(status['setup_required'], 'Fresh installation must require setup')
            require('Grantline' in request('GET', '/', html=True), 'Application assets missing')
            require('Grantline' in request('GET', '/docs/', html=True), 'Embedded docs missing')
            request('GET', '/api/v1/overview', want=401)
            before = secret_fingerprints()
            app_id = compose('ps', '-q', 'app', capture=True).stdout.strip()
            inspection = json.loads(subprocess.run(['docker', 'inspect', app_id], env=env,
                                    check=True, capture_output=True, text=True).stdout)[0]
            require(inspection['Config']['User'] == '65532:65532', 'App must run non-root')
            require(inspection['HostConfig']['ReadonlyRootfs'], 'App root must be read-only')
            bindings = inspection['HostConfig']['PortBindings']['8080/tcp']
            require(all(binding['HostIp'] == '127.0.0.1' for binding in bindings),
                    'Local listener must bind loopback')
            roles = compose('exec', '-T', 'postgres', 'psql', '-XAt', '-U', 'postgres',
                            '-d', 'grantline', '-v', 'ON_ERROR_STOP=1', '-c',
                            "SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole "
                            "AND NOT rolreplication AND rolcanlogin FROM pg_roles WHERE rolname='grantline'; "
                            "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='postgres';",
                            capture=True).stdout.strip().splitlines()
            require(roles == ['t', 't'], 'Database application/bootstrap privileges are unsafe')
            print('PASS: application database owner is non-superuser; bootstrap has no network password', flush=True)
            print('PASS: clean init, migration, readiness, UI/docs and hardened runtime', flush=True)

            token = compose('exec', '-T', 'app', 'cat',
                            '/var/lib/grantline/secrets/setup-token', capture=True).stdout.strip()
            password = secrets.token_urlsafe(32)
            setup = dict(Token=token, Organization='Linux acceptance',
                         Email='owner@example.test', Name='Acceptance Owner', Password=password)
            request('POST', '/api/v1/auth/setup', setup, want=201)
            refresh_csrf()
            request('GET', '/api/v1/overview', want=403)
            enrollment = request('GET', '/api/v1/auth/mfa')
            step = int(time.time()) // 30
            request('POST', '/api/v1/auth/mfa', {'Code': totp(enrollment['secret'], step)})
            refresh_csrf()
            request('GET', '/api/v1/overview')
            request('POST', '/api/v1/auth/setup', setup, want=409)
            require(not request('GET', '/api/v1/status')['setup_required'], 'Setup did not close')

            # Disabled synthetic connection verifies encrypted persistence without
            # sending requests to a source system or scheduling collection.
            credential = secrets.token_urlsafe(32)
            request('POST', '/api/v1/integrations', {
                'name': 'Acceptance fixture', 'enabled': False,
                'config': {'auth_mode': 'token', 'source': {'kind': 'vault',
                           'scope': 'vault/acceptance', 'address': 'https://vault.example.test'}},
                'credentials': {'token': credential}}, want=201)
            connections = request('GET', '/api/v1/integrations')
            require(len(connections) == 1 and connections[0]['configured'], 'Connection not saved')
            require(credential not in json.dumps(connections), 'Credential exposed in API response')
            connection_id = connections[0]['id']
            print('PASS: first Owner, mandatory TOTP, closed setup and saved connection', flush=True)

            compose('down')  # Named volumes are deliberately retained here.
            compose('up', '-d', '--wait', '--wait-timeout', '180')
            require(before == secret_fingerprints(), 'Initialization replaced persistent secrets')
            require(not request('GET', '/api/v1/status')['setup_required'], 'Organization lost')
            request('GET', '/api/v1/overview')  # Existing server-side session survives.
            connections = request('GET', '/api/v1/integrations')
            require(len(connections) == 1 and connections[0]['id'] == connection_id
                    and connections[0]['configured'], 'Stored connection lost on recreation')
            request('POST', '/api/v1/auth/logout', {})
            jar.clear()
            csrf = ''
            request('POST', '/api/v1/auth/login', {'Email': setup['Email'], 'Password': password})
            refresh_csrf()
            request('GET', '/api/v1/overview', want=403)
            # A fresh time step is required because enrolled TOTP codes cannot be replayed.
            while int(time.time()) // 30 <= step:
                time.sleep(0.5)
            request('POST', '/api/v1/auth/mfa',
                    {'Code': totp(enrollment['secret'], int(time.time()) // 30)})
            refresh_csrf()
            request('GET', '/api/v1/overview')
            request('POST', '/api/v1/auth/logout', {})
            request('GET', '/api/v1/overview', want=401)
            print('PASS: container recreation retained keys, Owner, MFA, session and connection', flush=True)
            print('PASS: fresh password/TOTP login and session revocation after restart', flush=True)
            print('Compose acceptance passed; version: ' + status['version'], flush=True)
        except Exception:
            # These services contain only generated test credentials. Runtime logs
            # must still redact secrets; keep bounded diagnostics before cleanup.
            compose('logs', '--no-color', '--tail', '60', check=False)
            raise
        finally:
            # Only the project generated above and its disposable volumes are removed.
            compose('down', '--volumes', check=True)


if __name__ == '__main__':
    main()
