# Investigations and policy

Start with [three investigations](./three-investigations.md) and the
[ten-finding evidence review](./review-example.md). Details show the named subject,
identity/configuration-object counts, known fields and recorded policy. Imported
reports without original policy omit unavailable thresholds. The exported report
stays unchanged.

The built-in policy checks IL001–IL009. Default duration limits are seven days for
Entra client secrets, 24 hours for X.509 SVIDs, and one hour for JWT SVIDs. IL008
separates the exact environment names `production`/`development` and
`production`/`staging`. These are policy defaults, not inferred environment labels:
declare your actual mappings and customize the policy before drawing conclusions.

Findings link to stable identities, affected relationships and the exact evidence
used by the analyzer. Filter identities and findings on the server; share the
detail address with another workspace member. Expand evidence to inspect source,
native ID, observed time and field names. Collection completeness is part of every
report, not a guarantee that a missing object was removed from its source.

## Review decisions

Analysts can assign a responsible person, add comments and select Open, In review,
Accepted risk or Resolved. Risk acceptance requires a reason and future expiry.
Expired acceptance returns to In review. Concurrent edits use revision checks;
reload rather than silently overwriting another person's decision.

Review state never changes a policy engine result. Findings are not automatically
resolved when a later collection misses an object. Review decisions and comments
survive report retention and remain in the audit trail.

## Policy configuration

Settings stores a validated, versioned policy and explicit context bindings.
Each collection records the configuration revision. Historical reports are immutable.
Default severities are medium, except IL006 (high). All enabled sources are required
for complete default coverage. Default maximum lifetimes are 168 hours for client
secrets, 24 hours for X.509-SVIDs and one hour for JWT-SVIDs.

| Rule | Review |
| --- | --- |
| IL001 | Broad Kubernetes permissions |
| IL002 | Unreviewed Vault subjects |
| IL003 | Long-lived client credentials |
| IL004 | Missing application owners |
| IL005 | Unreviewed application roles |
| IL006 | Broad workload selectors |
| IL007 | Long-lived workload identities |
| IL008 | Identity shared across environments |
| IL009 | Jenkins jobs in separated environments mapped to the same Vault AppRole |

Open **Settings → Policies** as an Owner or Admin. The guided editor shows the
effective configuration, including defaults: all nine rules, severity, duration
limits, required connections and exact exception lists. Use the connection picker
and copy native IDs from an identity's evidence details. Display names do not
replace native IDs. IL004's owner requirement applies only to its listed targets;
an empty target list does not require owners on every object.

1. Adjust the rules, sources, thresholds or exact exceptions in the guided form.
2. Select **Validate & preview**. Errors identify the field and, for YAML syntax,
   the line. The preview compares rule outcomes and findings with the latest saved
   report, showing its time and whether it was imported or synthetic.
3. Review the change, acknowledge any disabled rules or removed required sources,
   then select **Save new revision**. A concurrent settings edit requires reloading.

Preview uses saved evidence only: it does not test provider credentials, collect
fresh data, overwrite reports, change triage or resolve findings. Existing
collection gaps remain. If no reusable snapshot exists, configuration validation
still works and the preview explains how to obtain one. A lower finding count can
mean reduced detection coverage; it is not proof that the risks were fixed.
Changes take effect on the next collection.

**Use built-in defaults** restores dynamic defaults, including all enabled
connections. Custom configuration is a **complete replacement**, not a patch:
omitted rules do not run, and newly enabled connections are not automatically
added to a custom required-source list. The API also rejects an unacknowledged
rule/source coverage reduction. Exact exceptions and weaker thresholds can also
reduce detection; review their preview carefully.

**Advanced YAML** remains available. Switching editors validates and preserves
supported exception lists; unsupported syntax is rejected rather than discarded.
The CLI and server use the same strict parser: block lists, two-space indentation,
plain single-line scalars and duration units such as `168h`, `24h` or `15m` (not
`7d`). Do not use flow arrays, anchors, multiline values or inline comments.

This example keeps the original eight checks enabled; add IL009 using the pipeline example below. Replace `production-cluster` with an
actual connection ID and add your other required connection IDs:

```yaml
schema_version: 1
required_sources:
  - production-cluster
limits:
  max_client_secret_validity: 168h
  max_x509_svid_ttl: 24h
  max_jwt_svid_ttl: 1h
rules:
  IL001:
    severity: high
  IL002:
    severity: medium
  IL003:
    severity: medium
  IL004:
    severity: medium
  IL005:
    severity: medium
  IL006:
    severity: high
    forbid_namespace_only: true
  IL007:
    severity: medium
  IL008:
    severity: medium
    separated_environments:
      - first: production
        second: staging
```

## Context declarations

Expand **Advanced business context & relationship declarations** beneath the
rules. Context uses a separate, validated YAML document. This complete example
declares that the same native service account is used by two application contexts.
Replace the connection and native IDs with your actual evidence. The declarations
are operator assertions; they do not prove runtime use.

```yaml
schema_version: 1
applications:
  - id: payments-production
    name: Payments production
    owner_hint: Payments security team
    members:
      - source_id: production-cluster
        kind: service_account
        native_id: replace-with-service-account-uid
        environment: production
  - id: payments-staging
    name: Payments staging
    owner_hint: Payments security team
    members:
      - source_id: production-cluster
        kind: service_account
        native_id: replace-with-service-account-uid
        environment: staging
```

For IL008, configure the same exact environment pair in the rule. A missing
connection, unresolved native identity or incomplete evidence is a coverage gap,
not evidence of absence. Removing context in a preview removes only the previous
context-derived relationships; provider evidence and workflow declarations keep
their provenance.

Use exact connection and native object IDs in context declarations. Names alone
never establish cross-system identity. Evidence remains marked as provider
observation, controlled export, explicit operator declaration or synthetic fixture.

## Jenkins pipeline role sharing — IL009

Available in the current `main` source; not included in the published
`v0.1.0-rc.4` package.

Add a Jenkinsfile mapping for each reviewed job in **Integrations → Jenkins**:
select an enabled GitHub connection, its exact repository name/numeric ID, a full
commit SHA and regular file path. Reading the selected file is an operator
declaration of that job's source, not proof that the running job uses that revision.
The parser records literal credential reference IDs and line evidence, never values.

IL009 follows only `job → references_credential → bound_to → Vault AppRole`.
It needs collected Jenkins job metadata, configured reference evidence from the
pinned file, an explicit credential-to-role declaration and observed Vault role
metadata. The same credential label in two jobs does **not** establish identity.

Add IL009 to your custom policy (existing custom policies are not extended
automatically):

```yaml
  IL009:
    severity: medium
    separated_environments:
      - first: production
        second: development
```

For example, add these entries to your context document, preserving its other
applications and bindings. Replace every source/job/role ID with reviewed scope:

```yaml
schema_version: 1
jenkins_vault:
  - jenkins_source_id: jenkins-team
    credential_native_id: deploy-dev/credentials/vault-role
    vault_source_id: vault-team
    role_native_id: approle/deploy
  - jenkins_source_id: jenkins-team
    credential_native_id: deploy-prod/credentials/vault-role
    vault_source_id: vault-team
    role_native_id: approle/deploy
applications:
  - id: delivery
    name: Delivery
    members:
      - source_id: jenkins-team
        kind: job
        native_id: deploy-dev
        environment: development
      - source_id: jenkins-team
        kind: job
        native_id: deploy-prod
        environment: production
```

One finding is emitted per exact Vault role and separated environment pair,
including both jobs/references and the supporting edges. Missing pinning,
unsupported parsing or missing role mappings remain UNKNOWN; known conflicts
survive partial coverage. An intentionally shared role can use
`allowed_shared_vault_roles` with `first`, `second`, `vault_source_id`,
`role_native_id` and `reason`; the report records the exact exception. This rule
does not establish identical secret values, authentication success or effective
access. Jobs without environment declarations and non-Vault credentials are
outside its scope.

## GitHub-related findings

The GitHub source filter includes Entra application findings connected to a
collected workflow by an evidenced configured or declared federation relationship.
Explicit tenant/client mappings remain operator declarations. The row
is labeled **Related via** its Entra source; detail shows the workflow and a link
to the exact relationship. The original finding's source, ID, evidence and triage
remain unchanged, and the total across all sources is not duplicated. A linked
Entra owner finding is not a separate GitHub vulnerability or proof of runtime
access. No standalone GitHub vulnerability rule is currently provided.
