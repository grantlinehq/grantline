# Docker Compose

Use Docker Engine with Compose v2, or Docker Desktop with Linux containers.
Allocate 4 vCPU and 8 GB for the planned reference workload. The acceptance record
lists platforms that have actually been tested.

## From a published release package

Download the [v0.1.0-rc.2 installation ZIP](https://github.com/grantlinehq/grantline/releases/download/v0.1.0-rc.2/grantline-install-0.1.0-rc.2.zip)
or [TAR package](https://github.com/grantlinehq/grantline/releases/download/v0.1.0-rc.2/grantline-install-0.1.0-rc.2.tar.gz).
Verify it using the release checksums and [signature guide](../operations/releases#verify-a-release).
Extract into a new private directory, then run:

```sh
docker compose up -d --wait
docker compose ps
```

The package's `.env` pins the multiarchitecture application image by digest.
Docker selects amd64 or arm64 for your host. No source checkout, Go or Node is required.

## Build from source

From a source checkout, use both Compose files for build and startup:

```sh
docker compose -f compose.yaml -f compose.build.yaml build app
docker compose -f compose.yaml -f compose.build.yaml up -d --wait
```

## First Owner

Open **http://127.0.0.1:8080**. Use `127.0.0.1`, not an interchangeable hostname:
the server checks the configured public origin.

Read the one-time setup token on your own terminal:

```sh
docker compose exec app cat /var/lib/grantline/secrets/setup-token
```

For a source build, include `-f compose.yaml -f compose.build.yaml` in that command too.

Create the organization and first Owner, then enroll a TOTP authenticator. The
setup endpoint closes after the first organization is created. Keep your
authenticator and setup files private. Subsequent users join through invitations.

## What starts

- `init` creates random secret files once. Restarts preserve them.
- `postgres` holds persistent application data, with no published database port.
- `migrate` applies the schema transactionally before the app starts.
- `app` serves the product and `/docs` as UID 65532, with a read-only root filesystem.

The quick-start uses isolated named volumes for generated secrets, mounted read-only
in consuming services. PostgreSQL receives only its database password, not the
encryption key. For operator-managed file secrets, see the external database example.
Never run `docker compose down -v` on data you want to retain.

Fresh installations create a separate `grantline` database owner without superuser,
role-creation, database-creation or replication privileges. The bootstrap `postgres`
account has no network password after initialization; local administration uses
`docker compose exec postgres psql -U postgres -d grantline` through its Unix socket.
Existing development volumes need the [upgrade check](../operations/upgrades#development-database-role-check).

## Reproduce the Linux installation test

Build the image using the source instructions above, then run with Python 3.10+:

```sh
python3 scripts/acceptance-compose.py --image grantline:development
```

The test uses a randomly named Compose project and port 8085. It checks initial
setup, required TOTP, a disabled synthetic connection, database privileges,
embedded UI/docs, container recreation, persistent keys/accounts and session
revocation. It removes only its own disposable containers and volumes. It neither
contacts an integration provider nor changes an existing installation. Change
`--port` if 8085 is already in use. See [compatibility](../reference/compatibility)
for the tested Linux environment and remaining platform coverage.

## A server with HTTPS

Point your DNS name at the server and permit inbound TCP 80/443. Add the following
public settings to the package's `.env`, preserving its `GRANTLINE_IMAGE` digest:

```dotenv
GRANTLINE_DOMAIN=grantline.example.com
GRANTLINE_PUBLIC_URL=https://grantline.example.com
```

```sh
docker compose --profile https up -d
```

Caddy obtains and renews TLS certificates. The application port remains bound to
loopback. If using your own reverse proxy, preserve the original Host, forward
`X-Forwarded-For`, and trust only that proxy's explicit IP CIDRs. HTTPS is required
for all non-loopback public URLs. Do not change the scheme to bypass TLS checks.

## External PostgreSQL and file secrets

Prepare a dedicated database and non-superuser role that owns its application
schema. Use `sslmode=verify-full` and a trusted database certificate. Prepare private
files `database-url`, `encryption-key` (base64, 32 random bytes, no padding) and
`setup-token` (at least 32 random characters). Files must be readable by UID 65532.

Use `deploy/compose.external.yaml` as a standalone Compose definition. Its Docker
Compose `secrets` map binds only the required files. Migrations run against that
database before the server starts. The file permissions are a host responsibility;
Compose file secrets do not encrypt the host files.

```sh
docker compose -f deploy/compose.external.yaml up -d
```

For direct `docker run`, use an absolute path to your private secret directory.
The database URL must resolve from inside the container:

```sh
IMAGE=ghcr.io/grantlinehq/grantline:0.1.0-rc.2
SECRETS=/private/grantline
docker run --rm --read-only --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,src=$SECRETS/database-url,dst=/run/secrets/database-url,readonly" \
  -e GRANTLINE_DATABASE_URL_FILE=/run/secrets/database-url "$IMAGE" migrate

docker run -d --name grantline --restart unless-stopped \
  --read-only --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 127.0.0.1:8080:8080 \
  --mount "type=bind,src=$SECRETS,dst=/run/secrets,readonly" \
  -e GRANTLINE_PUBLIC_URL=http://127.0.0.1:8080 \
  -e GRANTLINE_DATABASE_URL_FILE=/run/secrets/database-url \
  -e GRANTLINE_ENCRYPTION_KEY_FILE=/run/secrets/encryption-key \
  -e GRANTLINE_SETUP_TOKEN_FILE=/run/secrets/setup-token \
  "$IMAGE" server --listen 0.0.0.0:8080
```

Replace the public URL with your HTTPS origin when placing the application behind
a server reverse proxy. The [configuration reference](../operations/configuration)
lists proxy, SMTP, CA and observer secret settings.
