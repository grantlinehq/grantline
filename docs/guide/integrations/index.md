# Connect your sources

Use **Integrations → Add integration**. Choose provider, connection and explicit
scope, save, test access, then enable and collect. New connections remain paused
until you enable them. A failed or incomplete test is not a healthy source.
Credentials are encrypted with a key stored outside PostgreSQL. The API never
returns saved credentials. Replacing credentials replaces the complete credential
set; leaving fields blank preserves it. Removing a connection removes its stored
credentials while retaining historical reports.

Mounted references point to a single JSON file in `GRANTLINE_SECRET_DIR`. Names
cannot contain directories. The file's keys are the same as the credential fields
below; keep permissions and mounts private. Custom CA certificates can be supplied
through `GRANTLINE_CA_FILE`. TLS verification cannot be disabled in the web wizard.

## Kubernetes

Provide an observer kubeconfig with embedded CA and token or client certificate
data. Select its context and a stable `cluster/<name>` scope. Permit `get,list` on
namespaces, serviceaccounts, pods, deployments, roles, rolebindings, clusterroles
and clusterrolebindings. No Secrets permissions are required.

Executable plugins, auth-provider plugins, impersonation, certificate paths,
token files, proxy URLs and insecure TLS options are rejected. Credential reference
key: `kubeconfig`. Rotate short-lived observer tokens through your normal process.

## Vault

Use an HTTPS address and observer token. List exact policy names and auth roles
with `mount`, `name`, and `type` (`approle` or `kubernetes`). Grant metadata read on
those exact policies/role paths. Do not grant access to KV secrets or secret values.
Map a Kubernetes connection ID explicitly where Vault Kubernetes trust is analyzed.
Credential key: `token`.

## Jenkins

Use an HTTPS address, observer username and API token with Overall/Read and
Job/Read on explicitly listed full job paths. Select a bounded build metadata
limit. Credential keys: `username`, `token`; replace both together.
For Jenkinsfile relationships, add a linked GitHub source and keep it enabled.
Each mapping specifies `job`, `github_source_id`, `repository`, `repository_id`,
the full 40-character `commit` SHA, and `path`. The repository must belong to the
linked source's explicit scope. Grantline verifies the repository ID, commit,
tree and regular file blob before reading the bounded Jenkinsfile; symlinks and
submodules are rejected. Build scripts are never executed. The legacy CLI retains
its commit-pinned local repository method.

## Entra

Use a dedicated collector app with admin-consented Microsoft Graph
`Application.Read.All` application permission. Provide tenant ID, application
client ID and client secret, then list exact **object IDs** for applications and
service principals. These are not interchangeable with client IDs. Credential key:
`client_secret`. The collector does not change permissions or create credentials.

## GitHub

Use a GitHub App installed only on selected repositories, or a fine-grained token
with Metadata, Contents and Actions read permissions. For an App provide App ID,
installation ID and RSA private key; credential key `private_key`. Token mode uses
`token`. Repository entries require `name`, native `repository_id`, and explicit
full refs such as `refs/heads/main`. IDs protect against mistaken renames.

Identity declarations may map workflow references to tenant/client IDs, pinned to
workflow path, ref, commit SHA, job and step. They are declarations, not observations
of secret values. Grantline never reads GitHub secret contents.

## SPIRE

Provide a trust domain, explicit parent SPIFFE IDs and a Grantline metadata export.
Credential key: `export`, containing the JSON export text. Exports are bounded to
10 MiB and validated. The web server never opens a SPIRE admin socket. Reports
preserve export provenance and timestamps; imported metadata is not represented
as a current live observation. Inherited effective TTL may remain **UNKNOWN**.

## Failure handling

The last attempted collection, the last saved report and the access-test result
are different records. Permission gaps, expired credentials and outages produce
incomplete coverage or explicit errors; they do not produce empty healthy reports.
Review **Activity**, source coverage and the permission guide before retrying.
