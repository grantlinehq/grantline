# Investigate pipeline identity configuration

This walkthrough describes rc.5, including additions since the earlier rc.4 package.
See [release versions](../operations/releases.md). The case uses controlled
objects collected from real lab APIs and selected repository files. Names are
sanitized; no credential values, private identifiers or raw reports are included.

## Jenkins and Vault: one role across separated environments

**Question:** do development and production jobs map to the same Vault AppRole
when our policy requires their environments to be separate?

The selected jobs `delivery-dev` and `delivery-prod` contain literal Jenkinsfile
credential references. Each file is selected from a scoped GitHub repository at
a full immutable commit. Operator declarations map the references to
`approle/delivery` in the same Vault connection and place the jobs in `development`
and `production`. Vault collection confirms the AppRole metadata exists. IL009
matches this exact configuration when that environment pair is separated by policy.

### Set up the review

1. Configure and test GitHub, Jenkins and Vault connections with the explicit
   scopes in [the integration guide](../integrations/index.md). Keep the linked
   GitHub connection enabled; include the selected jobs and Vault AppRole.
2. In each Jenkinsfile mapping, select the exact job, linked GitHub connection,
   repository name and numeric ID, full commit SHA and regular file path. The
   selected file must have supported literal credential references; dynamic
   expressions and an unpinned branch name cannot substitute for that evidence.
3. In **Settings → Policies → Advanced business context & relationship
   declarations**, declare the jobs' environment membership and exact
   credential-reference-to-AppRole bindings. Copy native IDs from collected
   evidence. The [IL009 reference](./index.md#jenkins-pipeline-role-sharing-il009)
   contains the context and rule examples.
4. If using a custom policy, explicitly enable IL009, its separated environment
   pair and the required connections. A custom policy replaces defaults; adding
   a new rule to the product does not silently extend an existing custom policy.
5. **Validate & preview** checks the policy against saved evidence. Collect after
   changing connections or source mappings to obtain fresh provider/file evidence.
   Preview does not fetch a new Jenkinsfile or change a provider.
6. In **Findings**, select the Jenkins connection and IL009. Open the finding and
   inspect **Why this was flagged**, recorded policy and supporting evidence.

### Read the evidence

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| Observed Jenkins job metadata | The selected job was readable in the collected scope | Which file revision the job actually executed |
| Configured pinned Jenkinsfile references | Literal reference IDs and line evidence in the exact selected file | Secret values, dynamic references or authentication success |
| Declared job environments and role bindings | The operator's exact environment and credential-to-role mapping | Automatic discovery of credential contents or runtime use |
| Observed Vault AppRole metadata | The exact role exists in that Vault source | Which job authenticated or its effective runtime access |

The verified lab case produced one IL009 finding with **zero native principals,
seven configuration objects and 15 evidence records**. Jobs, credential references
and an AppRole are not seven accounts. One finding covers the exact shared Vault
role and separated environment pair; matching credential labels alone would not
produce it. These are case-specific counts, not a rule output guarantee.

**Decision:** validate the declared mapping with the pipeline owner. If separation
is required, plan distinct roles and source-side credential changes through your
normal process, then collect and review again. If sharing is intentional, use an
exact `allowed_shared_vault_roles` exception with the Vault source, role, environment
pair and reason. An **Accepted risk** review also requires a future expiry; review
state and policy exceptions are separate decisions.

Missing pinning, unsupported parsing or unresolved role mappings can leave the
rule UNKNOWN. Known conflicts remain visible when other coverage is incomplete.
Jobs without declared environments and non-Vault credentials are outside IL009's
scope. The rule does not claim leaked secrets or proven runtime boundary crossing.

## GitHub-related findings

**Question:** which collected workflow is connected to an Entra application that
already has a policy finding?

An exact configured or operator-declared federation relationship can connect a
collected GitHub workflow to an Entra application. For example, an IL004 finding
on a selected application with zero collected directory owners can appear when
filtering **Findings → Source** to the GitHub connection.

The row says **Related via** the Entra source. In its detail, **Related GitHub
workflows** links to the exact relationship. Inspect the workflow revision,
tenant/client mapping, federation configuration and original application evidence.
The Entra application remains the root cause; the finding ID, assignment,
comments and review state are shared across both views. Totals are not duplicated.

This is not a standalone GitHub vulnerability, proof of successful federation or
proof that an uncollected workflow is safe. No matching relationship or Entra
application finding means there is no related result to display. Check the
connection scope, pinned declarations, enabled policy targets and collection
coverage before interpreting an empty source filter.

Continue with the [policy reference](./index.md),
[permissions matrix](../integrations/permissions.md) and
[selected OWASP mapping](./owasp-nhi-mapping.md).
