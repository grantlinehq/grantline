# Supported sources and boundaries

The v0.1.0 candidate implements six source adapters. “Implemented” describes code
and UI flows, not validation of every provider version, tenant policy or failure.

| Source | Available now | Boundary |
| --- | --- | --- |
| Kubernetes | Service accounts, namespaces, Pods/Deployments, Roles/ClusterRoles and bindings; restricted kubeconfig | No secret values, command execution or comprehensive runtime/effective-access analysis |
| Vault | Selected AppRole/Kubernetes auth roles and ACL policies; explicit Kubernetes association | No KV values, SecretIDs or discovery of every mount |
| Jenkins | Selected job/build metadata, immutable Jenkinsfile references and IL009 shared Vault AppRole review | Server uses a scoped GitHub connection at a full commit SHA; CLI also supports pinned local files. Requires exact job environments and credential-to-AppRole declarations. Pipelines are not executed. |
| Entra | Selected apps/SPs, credential validity, owners, federation and application-role assignments | Object scope is explicit. Metadata is not proof of actual credential use; product SSO is separate. |
| GitHub | Selected repos, refs, workflows and explicit cross-provider identity declarations; related Entra application findings through evidenced federation | Related findings retain their Entra root cause. No standalone GitHub vulnerability rule, secret contents, workflow dispatch or runtime OIDC-token validation. |
| SPIRE | Validated registration/workload metadata export with provenance | Import is not a live admin API integration; no admin socket exposed to the web product |

All six appear in the wizard. Access tests use collection paths and can produce
partial/error coverage. Historical imports do not create active connections.
Environment/business mappings are explicit declarations, not name-based inference.

Invitations, passwords/TOTP, OIDC linking, API roles, manual/scheduled jobs,
historical reports, evidence review, assignment, comments and expiring risk
acceptance are implemented. PostgreSQL and one active instance are required. SMTP
is optional; administrators can create expiring account links without email.

Multi-tenant hosting, horizontal/HA app deployment, automatic remediation, complete
NHI coverage, real-time activity monitoring and universal effective-access analysis
are outside this candidate. Full provider/IdP acceptance and WCAG evaluation remain
open. See [measured compatibility](../reference/compatibility),
[permissions](./permissions) and [selected OWASP mapping](../policies/owasp-nhi-mapping).
