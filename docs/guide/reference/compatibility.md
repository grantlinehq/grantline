# Compatibility and acceptance

Verified on 29 September 2026. This records measured results, not a general
production-readiness certification. Public image/chart publication is pending.

| Area | Status |
| --- | --- |
| Docker Desktop / Windows, Linux amd64 containers | Compose clean installation, persistent secrets, schema 1 → 3 upgrade, restart and restore passed |
| Ubuntu 24.04.5 / WSL2, independent Linux Docker Engine 29.7.2 / Compose 5.5.0 | Clean ext4 source package, init/migration, first Owner/TOTP, saved connection, container recreation, persistent keys/accounts/sessions, logout and database privilege checks passed |
| Standalone Linux server / VM | Not tested separately; the Linux run used the WSL2 kernel, not Docker Desktop's daemon |
| macOS Docker Desktop | Deferred by maintainer; unverified |
| Kubernetes 1.37.0 | kind 0.33.0 / Helm 4.3.0: installation, Recreate upgrade, retained independent Secrets, readiness and restore passed |
| Helm chart | Production/evaluation lint and render passed; invalid replica count and insecure public URL rejected |
| linux/arm64 | Multiarch build, non-root read-only runtime, init, migration, readiness and initial setup state passed under Docker emulation |
| Real ARM64 host | Pending; emulation is not a hardware validation |
| Accounts and data | PostgreSQL account lifecycle, roles, TOTP, session revocation, key rotation, recovery and immutable reports passed |
| OIDC / SMTP | Controlled TLS fixtures passed; customer identity provider and SMTP service acceptance remains pending |
| Accessibility | Desktop/narrow layout and keyboard spot checks; full WCAG 2.2 AA audit remains pending |

The Linux test found and fixed bootstrap database role initialization. Its fresh
database verified that `grantline` is not a superuser and the bootstrap account
has no network password. A fresh Kubernetes namespace and PVC also passed those
role checks, migration, readiness, Helm upgrade and application restart; persisted
data and independently managed Secrets were retained.
Earlier Windows/Kubernetes runtime checks do not establish the corrected role
configuration on existing volumes. See the development database role check in
the upgrade guide. Linux acceptance is reproducible with
`scripts/acceptance-compose.py`; it uses isolated synthetic data and no providers.

## Capacity measurement

An isolated application process was limited to 2 CPUs / 6 GiB and PostgreSQL to
2 CPUs / 2 GiB, totaling the 4 vCPU / 8 GiB reference budget. The host was shared
Windows Docker Desktop; this is not a dedicated production-server benchmark.

- 50 users, 20 configured connections, 10,000 synthetic native identities.
- Ten concurrent clients, 1,000 authenticated list/search requests, 50-row pages.
- p50 **113.652 ms**, p95 **201.892 ms**, maximum **288.642 ms**.
- The p95 ≤ 500 ms list/search target passed. Report import took **715.756 ms**.
- This measures list/search and report persistence; provider collection latency,
  WAN behavior, larger reports and sustained soak traffic require separate tests.

## Security and regression checks

`go test -race ./...` passed with PostgreSQL acceptance enabled. `go vet`, frontend
build/render checks, OIDC state/nonce/PKCE tests, verified-TLS SMTP delivery and
bounded mail retries passed. Dependency scans found no reachable Go advisory and
no high/critical vulnerability in either runtime image at scan time. One advisory
exists in an unused module dependency; it is not an imported or reachable package.
The frontend dependency audit and public-source secret scan passed.

Historical report round-trip preserved 288 objects, 189 relationships, 340 evidence
records, 14 findings and one UNKNOWN result. The private report itself is excluded
from all distribution artifacts. Collector fixtures cover incomplete permissions,
authentication failures and unavailable sources; a full six-provider live server
matrix is still a release gate.

The local release ledger is `docs/PRODUCTION_WORK.md`. A production-ready label
requires its outstanding gates to close, including live provider and SSO checks,
accessibility review, and public CI/signature
validation. Standalone Linux and macOS coverage remain explicitly unverified.
