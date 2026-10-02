# Offline analyzer catalog

This optional development tool evaluates six **synthetic** metadata sources with
the real IL001–IL008 analyzer. It makes no provider requests, creates no workload
credentials and is never called by the server worker. **Collect now** always uses
the configured collectors. These fixtures are not customer data or deployable lab
manifests; imported reports retain their sample-data label.

The catalog includes 36 business scenarios, 128 findings and negative controls.
Severity is chosen by the fixture policy, not a universal risk score. Jenkins and
GitHub supply metadata and relationships; no standalone Jenkins/GitHub detection
rule is claimed.

| Severity | Scenario | Findings |
| --- | --- | ---: |
| Critical | IL001: wildcard Kubernetes RBAC | 20 |
| Critical | IL005: Entra app role absent from the explicit allowlist | 12 |
| High | IL002: wildcard or undeclared Vault trust | 18 |
| High | IL006: namespace-only SPIRE selectors | 14 |
| Medium | IL003: credential metadata lifetime exceeds the policy | 20 |
| Medium | IL008: shared native identity across declared environments | 12 |
| Low | IL004: required application/service principal has no owner | 20 |
| Low | IL007: SPIRE lifetime exceeds the fixture limit | 12 |

From the repository root, with the Go version in `go.mod`:

```sh
go run ./scripts/demo-catalog --out bin/demo-catalog
go test ./internal/demolab
```

The ignored output directory contains `report.json`, `snapshot.json`, `policy.yaml`,
`bindings.json` and `manifest.json`. Every entity and source carries synthetic
provenance. The manifest lists counts and negative controls. No secret values or
live tenant identifiers are embedded. IDs remain stable across collection times;
repeating generation at the same fixed time produces the same report.
