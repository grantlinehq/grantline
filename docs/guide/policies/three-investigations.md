# Understand Grantline with three investigations

Grantline answers: **which non-human identity configurations violate our policy, what evidence supports that conclusion, and who will review them?** It collects selected metadata, applies deterministic rules and records decisions. It does not simulate attacks or automatically change source permissions.

Start in **Overview → Your review queue**. Open a finding to see its named subject, observed values, recorded policy revision, evidence and limitations. **Findings** supports subject search and source, rule and review-status selectors. Addresses retain filters and the selected historical collection.

## What the engine does

1. Collect selected source API metadata, or consume a validated SPIRE export.
2. Preserve identities, configuration objects, relationships and evidence. Configured, observed and operator-declared relationships remain distinct. Native identifiers determine identity; names aid investigation.
3. Evaluate the enabled checks IL001–IL009 against the collection's policy and context declarations. Severity, limits, targets and exact exceptions are organization choices, rather than a universal compliance standard or exploitability score.
4. Preserve an immutable report. Review state, assignee, comments and risk acceptance are separate records.

**PASS** means no violating condition was found within the evidence and scope needed by that rule. **FAIL** means a violating condition was found. **UNKNOWN** means evidence is insufficient for a complete rule conclusion; known findings can still be present. **Not applicable** means the rule does not apply to the selected configuration. PASS and source completeness do not prove that an entire organization is secure. See the [rule reference](./index.md).

These examples use controlled objects in real lab systems. Names are replaced for publication. Values come from a lab policy, not built-in defaults or customer results.

## 1. Kubernetes: wildcard application permissions

**Question:** does this workload need every operation on ConfigMaps?

ServiceAccount `sample-worker` is bound to a Role with `apiGroups: [""]`, `resources: ["configmaps"]`, `verbs: ["*"]`. IL001 flags the wildcard unless an exact exception applies. The lab policy assigns critical severity.

This is **one native identity and two configuration objects**, not three accounts. Inspect the Role, RoleBinding subject, scope and observation time. Confirm the required operations with the workload owner.

**Decision:** action needed for this application fixture. Record **In review**, assign responsibility and explain the wildcard. Remediation belongs in Kubernetes: constrain the source grant, collect again and verify. A lower finding count alone is not proof of remediation.

**Boundary:** the same check flagged the lab's default HPA controller role. Matching native role, bootstrapping label and controller rules support an expected platform configuration interpretation. Verify that controller and exact grant before approving an exception; do not exclude all `system:*` roles. Kubernetes documents [default and controller roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/). The finding alone does not prove compromise or effective permission use.

## 2. Entra: a secret configured for 180 days

**Question:** does the application's secret validity meet our policy?

The collected start and end dates are **180 days** apart; the recorded lab maximum is **720h, or 30 days**. IL003 flags this validity interval. The UI shows the parent application name instead of an opaque credential identifier. The example policy severity is medium.

Compare dates, observed duration and recorded threshold under **Why this was flagged**, then inspect the exact application evidence. Imported reports without their original policy cannot reconstruct the threshold; current settings are not substituted.

**Decision:** action needed for this configured-policy violation. Ask the app owner to confirm the purpose and plan the source-side lifecycle change. Consider dependencies before rotating credentials.

**Boundary:** configured validity is not credential age, remaining lifetime, last rotation or proof of use. The collector's access credential and application credential under review are different things. Reports contain metadata, not secret values. Microsoft describes [password credential metadata and secret-value behavior](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0).

Allowing 180 days in policy changes the requirement, not the credential. **Settings → Policies → Validate & preview** simulates a policy change on saved evidence. Collect again after source changes.

## 3. Environment reuse: a declared boundary

**Question:** is one native account associated with environments our policy separates?

The same collected ServiceAccount is explicitly mapped to `production` and `development`. IL008 compares those declarations with the policy pair. Matching display names in different clusters would not suffice. The lab policy severity is medium.

Inspect the two declared-context records and native-identity evidence. Confirm who maintains the mappings and whether they represent real deployment boundaries. Environments are not guessed from names.

**Decision:** the declared-policy condition is known; evidence is insufficient to claim runtime boundary crossing. Keep **In review** and document the missing context. Correct mistaken declarations, separate principals where required, or approve an exact shared-service exception with a reason.

**Boundary:** this does not prove authentication in both environments, production data access or bypass of a runtime control. Other unresolved correlations make the lab's overall IL008 result UNKNOWN. Known findings and incomplete rule coverage can coexist.

## Review without hiding uncertainty

For each finding: check time, scope and provenance; identify the native subject and related objects; compare known fields with recorded policy; state what remains unproven; assign responsibility and record the next decision.

**Accepted risk** requires a reason and future expiry. **Resolved** should follow verification. Review states do not rewrite rule outcomes. Missing evidence does not automatically resolve a finding.

## Check your understanding

Explain each example without a script: *which native subject, observed fields, policy condition, limitation and next decision?* Explain why a controller wildcard needs context; validity does not establish rotation; UNKNOWN can contain findings; and an exception is a policy decision rather than a source fix. Continue with the [ten-finding review](./review-example.md).
