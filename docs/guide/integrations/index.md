# Connect your sources

Use **Integrations → Add integration**. Choose provider, connection and explicit
scope, save, test access, then enable and collect. New connections remain paused
until you enable them. A failed or incomplete test is not a healthy source.
Expand **Before you connect: permissions & preparation** in the wizard for the
provider's setup steps, collected metadata and access boundaries. Kubernetes and
Vault include copyable permission examples to adapt in your own change process.
Grantline does not apply those permissions or widen provider access automatically.

The catalog contains **six provider types**. A saved connection is one scoped
instance of a provider, with its own ID, credentials and collection history. The
server supports up to 20 saved connections, including paused ones; this does not
mean 20 provider adapters. Choose a distinct connection ID for each instance.

Use **Add repository**, **Add auth role**, or **Add Jenkinsfile mapping** to enter
scope as structured rows; no JSON is needed for these forms. GitHub's optional
identity declarations and existing-run checks are nested under each repository
and are retained when editing it. Related Kubernetes/GitHub connections use
pickers, including paused-state labels. A source access test can still find an
expiry, permission or availability problem after the fields validate.

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

In rc.5, IL009 also reviews these references against exact collected
Vault AppRoles and declared job environments. Enable the rule in a custom policy,
declare credential-to-role bindings and include both sources in collection.
Matching credential labels alone is insufficient. See the
[pipeline investigation](../policies/pipeline-investigation.md) and
[policy reference](../policies/index.md#jenkins-pipeline-role-sharing-il009).
This rule is not included in the earlier rc.4 package.

## Entra

The IDs come from different places in the Entra admin center:

| Form field | Where to copy it |
| --- | --- |
| Tenant ID | Collector app registration → Overview → Directory (tenant) ID |
| Collector application (client) ID | Collector app registration → Overview → Application (client) ID |
| Client secret | Collector app → Certificates & secrets → Client secrets → **Value**, not Secret ID |
| Application object IDs | Each target app registration → Overview → **Object ID** |
| Service principal object IDs | Each target Enterprise application → Overview → **Object ID** |

Use a collector application separate from the applications being inspected and
from product SSO. Choose **Application permissions**, not Delegated permissions,
for unattended collection and grant tenant admin consent. The Graph permission
is tenant-wide; the selected object IDs bound Grantline's collection requests.
The guided form derives `tenant/<tenant-id>` automatically. Select at least one
application or service principal. An application/client ID is not its Object ID.

Use a dedicated collector app with admin-consented Microsoft Graph
`Application.Read.All` application permission. Provide tenant ID, application
client ID and client secret, then list exact **object IDs** for applications and
service principals. These are not interchangeable with client IDs. Credential key:
`client_secret`. The collector does not change permissions or create credentials.

Choose **Authentication → Application credentials (recommended)** for scheduled
collection. Grantline obtains a fresh app-only access token before each collection;
no user sign-in is required during a scan. Set up the application permission and
admin consent once, and rotate the client secret before it expires. When switching
an existing token connection, enter the new client secret or select a mounted JSON
file containing `client_secret`; an old access-token file is not interchangeable.

**Temporary access token** is intended for one-time connection checks. Its
credential key is `token`; it expires and cannot renew itself. Do not use a user's
browser session as the authentication mechanism for unattended collection.

See Microsoft's [app-only access guide](https://learn.microsoft.com/en-us/graph/auth-v2-service)
for the application registration, permission and admin-consent steps.

## GitHub

For each repository, supply `owner/repository`, its numeric repository ID and
1–10 full refs such as `refs/heads/main` or `refs/tags/v1.0.0`. Obtain the ID with
`gh api repos/OWNER/REPO --jq .id` or GitHub's `GET /repos/OWNER/REPO` API; do not
substitute a repository name. Optional identity declarations require a pinned
commit, workflow/job/step, the exact reference and a tenant/client UUID. These
UUIDs are identifiers, not secret values. Existing-run checks do not dispatch a
workflow or prove access to every downstream resource.

Use a GitHub App installed only on selected repositories, or a fine-grained token
with Metadata, Contents and Actions read permissions. For an App provide App ID,
installation ID and RSA private key; credential key `private_key`. Token mode uses
`token`. Repository entries require `name`, native `repository_id`, and explicit
full refs such as `refs/heads/main`. IDs protect against mistaken renames.

Identity declarations may map workflow references to tenant/client IDs, pinned to
workflow path, ref, commit SHA, job and step. They are declarations, not observations
of secret values. Grantline never reads GitHub secret contents.

In rc.5, **Findings → Source** can also show Entra application findings
related to collected GitHub workflows through evidenced federation. The row is
labeled **Related via** the Entra source. It is the same original finding, with
the same triage record, rather than a standalone GitHub vulnerability. No matching
relationship or Entra finding means there is no related finding to show. See the
[pipeline investigation](../policies/pipeline-investigation.md#github-related-findings).

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
