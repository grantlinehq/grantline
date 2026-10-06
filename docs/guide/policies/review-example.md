# A ten-finding evidence review

This sample reviews ten findings from controlled objects in real lab systems. Five providers used APIs; SPIRE used a provider export. Names are replaced for publication. Private native IDs, tenant identifiers and full reports are omitted.

| # | Rule / subject | Collected condition | Classification | Next decision |
| --- | --- | --- | --- | --- |
| 1 | IL001 / application account | ConfigMaps, wildcard verbs, Role and RoleBinding | Action needed | Confirm required operations and constrain the source grant. |
| 2 | IL001 / HPA controller | Scale/metrics wildcards; native role matches default bootstrapping metadata | Expected configuration, pending exact approval | Verify controller and exact exception; no blanket system-role exclusion. |
| 3 | IL002 / Vault role A | Bound account names `*`; one selected namespace | Action needed | Identify intended accounts and constrain the binding. |
| 4 | IL002 / Vault role B | Bound account names `*`; one selected namespace | Action needed | Review this independent role and its accounts. |
| 5 | IL003 / legacy application | Configured validity 180 days; recorded maximum 30 days | Action needed | Plan credential lifecycle changes with the app owner. |
| 6 | IL004 / legacy application | Directory owner count 0 on a required-owner target | Action needed | Confirm responsibility and set directory ownership. |
| 7 | IL006 / SPIRE registration | Namespace-only Kubernetes selector | Action needed | Identify intended workloads and constrain selectors. |
| 8 | IL007 / SPIRE registration | Explicit JWT TTL 1,800s; recorded maximum 900s | Action needed | Review the explicit TTL in the provider configuration. |
| 9 | IL007 / SPIRE registration | Explicit X.509 TTL 7,200s; recorded maximum 3,600s | Action needed | Review the separate TTL; do not infer inherited defaults. |
| 10 | IL008 / shared account | Same native principal declared in production and development | Insufficient evidence for runtime boundary use | Validate declarations and obtain workload context before claiming runtime violation. |

The result is **eight action-needed reviews, one expected-configuration candidate and one review needing more evidence for a runtime claim**. All ten remain **In review**. No source configuration was changed; no risk was automatically accepted or marked resolved.

These are analyst assessments. IL008's declared-policy condition remains valid although runtime use is unproven. The HPA wildcard is still a detected condition pending an exact decision. IL007 and IL008 were UNKNOWN overall because other evaluations lacked evidence; their known findings remain. An owner-count check establishes directory metadata, not absence of every organizational owner.

This historical sample's snapshot contains 95 findings across 116 native identities.
Those counts describe that saved report, not today's workspace. A later lab
collection added the IL009 Jenkins/Vault case described in the
[pipeline investigation](./pipeline-investigation.md); it does not alter this
ten-item review. The ten items are selected for varied conditions, not randomly
sampled or a false-positive-rate measurement. All six sources reported complete
collection in their selected scope. Rule-level correlation and inherited-default
gaps still exist.

Grantline joins source configuration, stable identity, policy and evidence in one review. It helps explain a configuration question, track responsibility and reach a defensible decision. This demonstrates a workflow, not prevented incidents or measured time savings. Customer pilots should measure actionable reviews, expected exceptions, unresolved evidence and time to a decision.

See [three investigations](./three-investigations.md) and the [policy reference](./index.md).
