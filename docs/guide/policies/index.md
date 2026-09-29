# Investigations and policy

The built-in policy checks IL001–IL008. Default duration limits are seven days for
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

The CLI and server use the same strict policy parser. Example:

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
  IL003:
    severity: medium
```

Use exact connection and native object IDs in context declarations. Names alone
never establish cross-system identity. Evidence remains marked as provider
observation, controlled export, explicit operator declaration or synthetic fixture.
