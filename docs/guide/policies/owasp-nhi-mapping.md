# OWASP NHI mapping

Grantline is **mapped to selected OWASP Non-Human Identities Top 10 risks** in the
[2025 edition](https://owasp.github.io/www-project-non-human-identities-top-10/2025/table-of-contents/).
This is Grantline's evidence-based mapping, not OWASP certification, endorsement,
compliance assessment or complete category coverage.

| Risk | Rules / required source | Evidence | Limits and false positives | False negatives / missing evidence |
| --- | --- | --- | --- | --- |
| NHI5:2025 — Overprivileged NHI | IL001: Kubernetes; IL005: Entra | Wildcard RBAC rule bound to a service account outside the exact allowlist; resolved SP app-role assignment outside its allowlist | Policy deviation is not proof of unnecessary effective access. Legitimate service grants need exact reviewed exceptions. | Non-wildcard excess permissions, custom authorization, delegated grants and unselected SPs are outside these checks. Incomplete lists or resolution yield limitations/UNKNOWN. |
| NHI7:2025 — Long-Lived Secrets | IL003: Entra; IL007: SPIRE export | Client-secret record validity and explicit configured X.509/JWT SVID TTL versus policy thresholds | Configured duration does not establish current use, rotation success or exposure. Justified durations or unsuitable thresholds may require review. SPIRE maps the lifetime aspect of workload credentials. | Other credential types/sources, absent dates and inherited effective TTL are not inferred. Missing/inconsistent evidence can remain UNKNOWN. |
| NHI8:2025 — Environment Isolation | IL008: explicit environment bindings plus collected identity relationships | The same stable native principal associated with a policy-separated environment pair | Declared membership is not runtime traffic or proof of boundary crossing. Incorrect mappings and intended shared services require exact exceptions. | Undeclared environments, unobserved links and out-of-scope principals can hide reuse. Similar names do not establish identity. |

IL002 reviews Vault subject bindings, IL004 reviews directory ownership and IL006
reviews broad SPIRE selectors. Those useful controls are not stretched into claims
of detecting offboarding failures, third-party compromise or all insecure deployment.
No direct release-level detection claim is made for NHI1, NHI2, NHI3, NHI4, NHI6,
NHI9 or NHI10. Grantline is not a secret-leak scanner and does not prove human use
of every NHI. Source-code secret scanning is a development control, not a product
NHI2 detector.

Findings link rule versions, affected objects/relationships and evidence IDs. FAIL
means the implemented condition matched; PASS is scoped to assessed evidence.
UNKNOWN preserves uncertainty and NOT_APPLICABLE means no applicable target was
assessed. Triage never rewrites those outcomes. New mappings require synthetic
positive, negative and incomplete-evidence tests and explicit boundary review.
