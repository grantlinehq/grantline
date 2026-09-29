# Connector permissions

This matrix describes current collectors, not a request to grant every provider
permission. Use a dedicated observer and the smallest supported resource scope.
A read-only collector may still possess credentials with broader provider-side
authority; verify those permissions separately.

| Source | Authentication and minimum scope | Purpose | Missing access and blind spots |
| --- | --- | --- | --- |
| Kubernetes | Observer token or client certificate in a restricted inline kubeconfig; `get,list` on namespaces, serviceaccounts, pods, deployments, roles, rolebindings, clusterroles and clusterrolebindings | Resolve service accounts, workloads, RBAC rules and bindings | Missing lists mean incomplete coverage. Configured RBAC is not effective access, external authorization or runtime credential use. No Secrets, exec, logs, watch, write or TokenRequest requirement. |
| Vault | Dedicated token with `read` on configured `auth/<mount>/role/<name>` and `sys/policies/acl/<name>` paths | Selected AppRole/Kubernetes auth roles, policies and explicit Kubernetes trust | Denied paths remain incomplete. No KV payloads, token accessors, RoleIDs, SecretIDs, full mount discovery or effective-access proof. Do not supply a root token. |
| Jenkins | Observer username/API token; Overall/Read and Job/Read on selected jobs and ancestor folders | Bounded job/build metadata; Jenkinsfile content comes from a linked scoped GitHub source at a pinned commit | Unreadable jobs are incomplete. Job/Read may permit more than the collector uses, including log viewing; Grantline does not request logs. No Build, Configure, Create, Delete, ExtendedRead or Administer requirement. Dynamic pipeline execution is not inferred. |
| Entra | Server: client credentials with admin-consented Graph `Application.Read.All` application permission. CLI: operator-supplied application or delegated token | Selected app/SP objects, credential metadata, owner references, federation and app-role assignments/resource definitions | Consent is tenant-wide although object selection is narrower. Unreadable subresources remain unknown. Owner ID/type is sufficient; delegated grants and effective access are not fully modeled. No Directory.ReadWrite.All or AppRoleAssignment.ReadWrite.All requirement. |
| GitHub | App installation limited to selected repos, or fine-grained PAT with Metadata, Contents and Actions read | Repo/ref/commit/tree content, workflows and bounded workflow metadata; explicit identity declarations | Unavailable repos/refs/files stay incomplete. Static analysis does not prove execution or reveal secret values. No secrets, logs, dispatch, administration or content-write requirement. Token expiry and App installation scope remain operator responsibilities. |
| SPIRE | Web server: validated metadata export/file reference, with no admin socket | Registration entries, selectors, parent IDs and explicit lifetime metadata | Export age/provenance limit conclusions; inherited TTL may be UNKNOWN. A separate operator exporter can use local admin socket ListEntries, but that socket conveys broader authority than a read-only credential. Never expose it through the web app. |

## Preparation and validation

1. Create and approve the provider-side observer through your normal process.
2. Restrict its resources. Optional chart observer RBAC uses a separate identity
   from the application's own ServiceAccount.
3. Set exact scope in [the integration wizard](./index). Place credentials only
   in designated encrypted fields or private secret references.
4. Test, then enable collection. Last test, last attempt, last success and report
   completeness are different records. Never broaden privileges automatically.

The full live server matrix (success, denied scope, expired credentials and outage)
remains a release gate. Earlier CLI labs, especially broader developer OAuth
sessions, do not prove minimum-scope acceptance in every scenario.

References: [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
[Vault policies](https://developer.hashicorp.com/vault/docs/concepts/policies),
[Jenkins access control](https://www.jenkins.io/doc/book/security/access-control/),
[Graph application reads](https://learn.microsoft.com/en-us/graph/api/application-get),
[Graph app-role lists](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments),
[GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app),
[SPIRE administration](https://spiffe.io/docs/latest/deploying/spire_server/).
