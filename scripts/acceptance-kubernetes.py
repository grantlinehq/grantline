"""Fresh Helm installation/upgrade test in an explicitly selected existing cluster.

Creates only a randomly named disposable namespace, then deletes that namespace.
The application image must already be available in the cluster's container runtime.
"""
import argparse
import base64
import json
import secrets
import subprocess
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--image', default='grantline')
    parser.add_argument('--tag', default='prelaunch')
    parser.add_argument('--chart', default=str(Path(__file__).resolve().parents[1] / 'charts/grantline'))
    parser.add_argument('--chart-version', default='')
    parser.add_argument('--image-digest', default='')
    parser.add_argument('--pull-policy', choices=['Never', 'IfNotPresent', 'Always'], default='Never')
    args = parser.parse_args()
    ns = 'grantline-check-' + uuid.uuid4().hex[:10]
    kubectl = ['kubectl', '--kubeconfig', args.kubeconfig, '--context', args.context]
    release, app = 'check', 'check-grantline'

    def run(command, data=None):
        result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=360)
        if result.returncode:
            # Never print input: it may contain generated test Secrets.
            raise RuntimeError('Command failed: ' + command[0] + '\n' + result.stderr)
        return result.stdout.strip()

    def k(*arguments):
        return run(kubectl + ['-n', ns] + list(arguments))

    def helm(extra=None):
        return run(['helm', 'upgrade', '--install', release, args.chart,
                    '--kubeconfig', args.kubeconfig, '--kube-context', args.context, '-n', ns,
                    '--set', 'existingSecret=app-secrets', '--set', 'postgresql.enabled=true',
                    '--set', 'postgresql.existingSecret=database-secrets',
                    '--set', 'publicURL=http://127.0.0.1:8080', '--set', 'image.repository=' + args.image,
                    '--set', 'image.tag=' + args.tag, '--set', 'image.digest=' + args.image_digest,
                    '--set', 'image.pullPolicy=' + args.pull_policy,
                    '--wait', '--timeout', '5m']
                   + (['--version', args.chart_version] if args.chart_version else []) + (extra or []))

    def sql(query):
        return k('exec', app + '-postgres-0', '--', 'psql', '-XAt', '-U', 'postgres',
                 '-d', 'grantline', '-v', 'ON_ERROR_STOP=1', '-c', query)

    def ready():
        result = k('exec', 'deploy/' + app, '-c', 'app', '--',
                   'wget', '-qO-', 'http://127.0.0.1:8080/readyz')
        if json.loads(result)['status'] != 'ready':
            raise RuntimeError('App is not ready')

    created = False
    try:
        run(kubectl + ['create', 'namespace', ns])
        created = True
        password = secrets.token_urlsafe(32)
        app_data = {'database-url': f'postgres://grantline:{password}@{app}-postgres:5432/grantline?sslmode=disable',
                    'encryption-key': base64.b64encode(secrets.token_bytes(32)).decode().rstrip('='),
                    'setup-token': secrets.token_urlsafe(32)}
        for name, data in [('app-secrets', app_data), ('database-secrets', {'postgres-password': password})]:
            resource = {'apiVersion': 'v1', 'kind': 'Secret',
                        'metadata': {'name': name, 'namespace': ns}, 'stringData': data}
            run(kubectl + ['apply', '-f', '-'], json.dumps(resource))
        helm()
        ready()
        role = sql("SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname='grantline'; SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='postgres';")
        if role.splitlines() != ['t', 't']:
            raise RuntimeError('Unsafe database roles')
        secret_before = json.loads(k('get', 'secret', 'app-secrets', '-o', 'json'))['data']
        deployment = json.loads(k('get', 'deployment', app, '-o', 'json'))
        if deployment['spec']['strategy']['type'] != 'Recreate' or deployment['spec']['replicas'] != 1:
            raise RuntimeError('Unexpected rollout/replica configuration')
        podspec = deployment['spec']['template']['spec']
        if podspec['automountServiceAccountToken'] or not podspec['containers'][0]['securityContext']['readOnlyRootFilesystem']:
            raise RuntimeError('Unexpected runtime permissions')
        sql("CREATE TABLE acceptance_sentinel(value text); INSERT INTO acceptance_sentinel VALUES('retained');")
        print('PASS: fresh Helm install, migrations, readiness, hardened pod and database roles', flush=True)
        helm(['--set', 'resources.requests.cpu=275m'])
        ready()
        k('rollout', 'restart', 'deployment/' + app)
        k('rollout', 'status', 'deployment/' + app, '--timeout=120s')
        ready()
        if sql('SELECT value FROM acceptance_sentinel') != 'retained':
            raise RuntimeError('Database state was not retained')
        if json.loads(k('get', 'secret', 'app-secrets', '-o', 'json'))['data'] != secret_before:
            raise RuntimeError('Upgrade changed external keys')
        print('PASS: Helm upgrade and app restart preserve data and independent Secrets', flush=True)
    finally:
        if created:
            run(kubectl + ['delete', 'namespace', ns, '--wait=true', '--timeout=120s'])
            print('Removed only this run\'s disposable namespace.', flush=True)


if __name__ == '__main__':
    main()
