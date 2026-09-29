# Metadata and credential handling

This describes the current v0.1.0 release candidate. Grantline collects identity
and credential metadata. Provider collectors do not intentionally retrieve secret
payloads or credential values for inventory reports. Credentials supplied to let
Grantline connect to a provider are a separate category: they may be encrypted in
PostgreSQL or supplied through an operator-managed secret file.

## Collected inventory and evidence

Depending on the connector and configured scope, reports contain identity IDs,
credential IDs and types, creation and expiry dates, owner references, authentication
methods, permissions, trust relationships and evidence provenance. A credential
reference or secret name is not its value. GitHub secret contents, Vault KV values,
Vault SecretIDs, Kubernetes Secret contents and SPIRE private keys are not requested
by the metadata collectors. SPIRE server integration consumes a validated metadata
export; it does not connect to an administration socket.

Metadata can still reveal internal topology, tenant identifiers, application names,
repository names and ownership. Treat reports, exports and backups as private data.
Source permissions, configured scopes and missing observations limit coverage.

## Credentials used by Grantline

| Data | Current handling |
| --- | --- |
| Connector tokens, client secrets, GitHub App private keys and inline kubeconfig credentials supplied in the UI | Encrypted using AES-256-GCM in PostgreSQL; the master key is configured separately from the database |
| Named connector secret references | Loaded from a private JSON file under `GRANTLINE_SECRET_DIR`; the reference is stored in the database, while the operator controls the file and its protection |
| Access tokens obtained from Entra or GitHub during a collection | Used by the running collector, not saved as inventory evidence |
| Grantline user passwords | Salted Argon2id hashes, not recoverable plaintext passwords |
| TOTP enrollment secrets | Encrypted in PostgreSQL; enrollment material is shown during setup |
| Session/invitation/recovery credentials | Session and ticket verification uses digests; delivery links can exist in the encrypted email queue |
| Database password, setup token and master encryption key | Private mounted configuration/secret files or explicitly configured environment inputs; these are operational secrets, not collected inventory |

Saved connector credentials are not returned by the integration API. Collection
jobs receive credentials for their own connections rather than changing a shared
process environment. Credential replacement and key rotation are supported; see
the [backup and rotation guide](./backup).

## Boundaries of the guarantee

“Metadata only” does **not** mean that Grantline never handles or stores a secret.
An encrypted connector credential is deliberately recoverable by the application
when it has the master key. A mounted secret file may contain plaintext credential
material; a Docker volume or Kubernetes Secret does not by itself establish
encryption at rest. Protect those files, host storage, backups and runtime access.
The application must use credentials in memory to authenticate to providers.

Do not place secrets in names, comments, policy text, screenshots or uploaded
reports. These fields are not a general secret scanner or data-loss-prevention
system. Provider metadata and manually imported material can contain sensitive
operator-supplied text. Review and sanitize exports before sharing them. There is
no blanket guarantee that arbitrary user-provided text cannot contain a secret.

Report retention defaults to 30 days and is configurable. Removing a connection
removes its stored credentials while preserving historical reports. Review
decisions, comments and audit history have their own persistence; deleting a
connection is not a request to erase all associated history. Backup retention is
the operator's responsibility.

The approved model retains encrypted connector storage and external secret-file
references. It does not require all deployments to use an external secrets manager.
