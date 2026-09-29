# Server configuration

`grantline server --listen 0.0.0.0:8080` starts the HTTP server and one durable worker.
Run `grantline migrate` before starting it. Container distributions do this for you.

| Variable | Purpose |
| --- | --- |
| `GRANTLINE_PUBLIC_URL` | Exact public origin; HTTPS except loopback development |
| `GRANTLINE_DATABASE_URL_FILE` | File containing the PostgreSQL connection URL |
| `GRANTLINE_ENCRYPTION_KEY_FILE` | Base64 encoding of 32 random bytes, without padding |
| `GRANTLINE_SETUP_TOKEN_FILE` | First-owner token; setup closes after initialization |
| `GRANTLINE_SECRET_DIR` | Optional directory of explicitly named JSON observer credentials |
| `GRANTLINE_CA_FILE` | Additional PEM CA bundle for provider HTTPS |
| `GRANTLINE_TRUSTED_PROXIES` | Comma-separated exact trusted proxy CIDRs; none by default |
| `GRANTLINE_OIDC_ISSUER` | HTTPS OIDC issuer for product sign-in |
| `GRANTLINE_OIDC_CLIENT_ID` | Product sign-in client ID |
| `GRANTLINE_OIDC_CLIENT_SECRET_FILE` | Product sign-in client secret file |
| `GRANTLINE_SMTP_ADDRESS` | Optional implicit-TLS SMTP server, normally `mail.example.com:465` |
| `GRANTLINE_SMTP_FROM` | Sender mailbox without a display name |
| `GRANTLINE_SMTP_USERNAME` | Optional authenticated SMTP account |
| `GRANTLINE_SMTP_PASSWORD_FILE` | Optional SMTP password file |

For the database, encryption key, setup token and OIDC secret, a same-name variable
without `_FILE` is accepted, but private mounted files are preferred. Never include
secret values in Compose files, charts, shell history, tickets or source control.

Private provider addresses are supported for internal infrastructure. Destination
resolution rejects link-local, multicast and unspecified addresses, and production
connections reject loopback. Redirects are not followed by provider HTTP clients.
Configure network egress controls appropriate for your environment.

`/healthz` reports process health. `/readyz` requires the expected database schema
and the active worker lease. SIGTERM stops accepting requests and cancels collection
gracefully. Only one server may hold the database worker lock. A second instance
fails instead of creating competing collection workers.

Owners can configure product SSO in **Settings → SSO**. A saved configuration
overrides the environment bootstrap values, including when disabled. Changing
providers requires a new secret and invalidates pending OIDC exchanges. Collector
Entra credentials are separate from this sign-in configuration.

SMTP is optional. Administrators can always create time-limited account links.
With SMTP enabled, invitations and public recovery requests enter an encrypted
mail queue with three delivery attempts. Verified implicit TLS is required;
plaintext SMTP and STARTTLS-only relays are not supported in v0.1. Delivery failures
appear in Activity. Mail links and passwords are not written to logs.
