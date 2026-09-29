# Grantline v0.1.0 implementation and acceptance

Updated: 2026-09-29. Target: Apache-2.0, `github.com/grantlinehq/grantline`.
The local candidate is implemented and testable. **It is not yet approved as
production ready.** Private GitHub preparation is authorized; public source and
registry publication remain separate steps. See the prelaunch record below.

## Implemented

- Approved vector logo system (symbol, outlined wordmark, light/dark, monochrome
  and favicon), locally served IBM Plex fonts, pine navigation and warm workspace.
  All product screens use the shared design; development labels are removed.
- `grantline server`, PostgreSQL migrations, encrypted credentials and secret file
  references, configuration revisions, one active worker, durable collection jobs,
  cancellation, bounded restart recovery, hourly schedules and 30-day retention.
- Single-use initial setup; invited users; recovery; Owner/Admin/Analyst/Viewer
  API roles; last Owner protection; Argon2id; privileged local TOTP; revocable
  sessions; OIDC with explicit account linking and MFA claim checks.
- Optional verified-TLS SMTP, encrypted mail queue and three delivery attempts;
  manual expiring invitation/recovery links when SMTP is absent.
- Six integration wizards and per-job credential injection. Kubernetes rejects
  executable/file-based kubeconfig authentication. Entra uses app credentials;
  GitHub supports App or token; Jenkinsfiles use a scoped linked GitHub source and
  immutable commit; SPIRE accepts only bounded validated metadata exports.
- Paginated/searchable inventory, source/kind/review filters and shareable URLs;
  immutable historical reports; evidence detail with truncation indicators;
  assignments, comments and expiring reasoned risk acceptance independently of
  PASS/FAIL/UNKNOWN. Missing coverage does not automatically resolve a finding.
- Owner SSO/organization settings, account/session controls, policy and explicit
  relationship configuration with revision history. Advanced policy/binding
  editing currently uses validated YAML rather than a visual mapping editor.
- Non-root, read-only application image, embedded frontend/docs, Compose init /
  PostgreSQL / migration / app and HTTPS profile; external database file secrets.
- Helm production/evaluation profiles, existing Secrets, optional database PVC,
  one replica / Recreate, readiness, schema validation, no default cluster access.
- English VitePress docs, OpenAPI 3.1, report schemas, Docker/Kubernetes, accounts,
  permissions, backup, upgrade, CLI and troubleshooting guides. Apache-2.0,
  contribution/security policies, changelog and third-party license inventory.
- CI test/security workflow and separate manual release workflow for multiarch
  image, SBOM/provenance, signature and chart publication. Publication defaults off.

## Verified locally

| Check | Result / boundary |
| --- | --- |
| Full Go suite + race detector | Passed, including disposable PostgreSQL account, RBAC, OIDC, SMTP, job, encryption, triage and recovery tests |
| Static/dependency checks | go vet and govulncheck: no reachable vulnerability; one advisory in an unused module remains visible |
| Frontend | TypeScript, production/docs build, provider text escaping passed; desktop and narrow/keyboard spot checks |
| Secret/dependency scan | Gitleaks public scope clean; pnpm audit clean; amd64/arm64 runtime Trivy high/critical clean |
| Compose on Windows Docker Desktop | Clean install, persistent key files, schema 1 → 3 upgrade, restart, readiness and database restore passed |
| Ubuntu 24.04.5 / WSL2 Linux | Independent Docker Engine 29.7.2, Compose 5.5.0, ext4 and kernel 6.18.33.2-microsoft-standard-WSL2: clean install, migration, Owner/TOTP, disabled connection persistence, container recreation, sessions and non-superuser database role checks passed |
| Kubernetes | kind 0.33.0, Kubernetes 1.37.0, Helm 4.3.0; real cluster install/upgrade, existing Secret retention, readiness and restore passed |
| Helm | Production/evaluation lint/template; schema rejects replicaCount=2 and non-loopback HTTP |
| Backup | Synthetic Owner/TOTP, encrypted connection, report sentinel and triage restored into an independent PostgreSQL from each deployment |
| Multiarch | linux/amd64 and linux/arm64 OCI build + SBOM/provenance; ARM64 init/migrate/server readiness under emulation |
| Capacity | 50 users / 20 connections / 10k identities / 10 concurrent clients / 1k list/search requests; capped 4 CPU / 8 GiB combined: p95 201.892 ms (target ≤500 ms), shared Windows host |
| Historical M7 regression | Semantic import/export preserved 288 objects / 189 relationships / 340 evidence / 14 findings / 1 UNKNOWN; no active integration created |

Reproducible local acceptance harnesses: `scripts/acceptance-race.ps1`,
`scripts/acceptance-capacity.ps1`, `scripts/acceptance-backup.ps1`, and
`scripts/acceptance-image.ps1`. The portable `scripts/acceptance-compose.py` checks
clean installation and account/data persistence on Linux and is included in CI.
They isolate disposable test data. Private keys,
kubeconfig, real historical reports and local outputs stay outside public artifacts.

## Remaining release gates

- [x] Ubuntu Linux installation under WSL2 with an independent Docker Engine and
  fresh data volumes. This is Linux kernel/filesystem/runtime coverage, not a
  standalone server/VM claim. macOS is deferred by the maintainer and unverified.
- [x] Fresh Kubernetes acceptance after the database bootstrap role correction:
  isolated namespace/PVC, application and bootstrap role checks, migration,
  readiness, Helm upgrade, restart, retained data and independent Secrets passed.
- [ ] Full live server matrix across all six providers: success, denied permissions,
  expired credentials and interruption. Collector fixtures and prior CLI lab runs
  are not a replacement for this matrix.
- [ ] Actual organization IdP invitation/link/MFA and SMTP service acceptance.
  Controlled issuer and SMTP fixtures pass, but tenant-specific claims vary.
- [ ] Full WCAG 2.2 AA evaluation, including assistive technology, every wizard,
  focus/contrast/error flow and zoom; responsive spot checks alone are insufficient.
- [x] Private repository CI and fresh clone: Checks run `36506984328` passed on
  commit `b8712a5`, including Ubuntu Compose acceptance. A separate clean HTTPS
  clone passed README build/up, UI/docs/readiness and initial setup-token access.
- [ ] Enable protections unavailable on the private Free plan at public launch
  (or after a separately chosen plan change), run public CodeQL, enable private
  vulnerability reporting, and validate published image/chart signatures.

## Release material and local context

### Linux acceptance follow-up (29 September 2026)

At the end of the initial Linux-only task, no repository had been created or
pushed. The maintainer subsequently authorized private preparation and HTTPS push
to `grantlinehq/grantline`. Module, image and documentation references now use that
namespace. Existing local application and Kubernetes data were preserved.

The first native Linux install exposed an invalid attempt to remove superuser
privileges from PostgreSQL's bootstrap role. Compose and the evaluation chart now
create `grantline` separately as the database owner, then remove the bootstrap
`postgres` network password. Only the database container's local Unix socket is
used for bootstrap administration. A TCP readiness check avoids declaring the
temporary initialization server ready. Fresh Linux tests verify these privileges,
first Owner/TOTP and persistence; old development volumes are not auto-migrated.
The upgrade guide documents their role check and safe backup/restore path.

The Linux source tree was extracted onto Ubuntu ext4. The application was built
from that source with the Linux Docker client; runtime acceptance then used a
separate native Ubuntu daemon, fresh data root and named volumes. Docker Desktop
provided neither the test database nor the test container filesystem. A new
disabled synthetic connection was saved without contacting a provider. The test
removed its volumes after passing; the temporary daemon was stopped afterward.

The local delivery bundle was regenerated after this correction and the private
prelaunch work. Previously copied bundles with an older image index are obsolete.
Public publishing remains on hold, as requested.

Local delivery: `bin/release-0.1.0-rc.1/` contains the multiarch OCI image,
installation tarball, Helm chart, allowlisted source ZIP, README-FIRST and SHA256SUMS.
Current image index: `sha256:dda8c6acfcb9f004fc89ce665d5625c0039c117d6a9ddf6e087e20b3856f55e8`.
The updated image passed a fresh ARM64 init/migrate/server check under emulation.
Each architecture has runtime and frontend SPDX SBOMs and SLSA provenance. Explicit
amd64 and arm64 artifact scans found no high/critical vulnerability. Existing
development installations were preserved. Kubernetes acceptance uses the locally loaded
version tag: kind's archive import does not retain the registry digest reference.
Registry digest-pull/signature verification remains part of the publication gate.
The narrow-screen menu now excludes hidden links from focus, traps focus while
open and returns it on Escape; this behavior was verified at a 543px viewport.

`scripts/package-source.py` creates an explicit-allowlist source archive under
`bin/`. It excludes legacy workstation notes, lab secrets, reports, tools, build
outputs and dependency directories. The Docker build context is also allowlisted.
Legacy `docs/*.md` and `lab/` files remain on this workstation and are ignored by
the future public repository; the English `docs/guide/` tree is the product manual.
Do not publish the entire workspace by copying it indiscriminately.

The design preview is development-only and uses fictional data. It is excluded
from the product build and does not bypass product authentication. The real product
requires the user to create their own initial Owner and enroll an authenticator.
Source collection remains metadata-only; no provider permissions are expanded by
the application. Deployment supports one organization and one active instance.

### Private prelaunch preparation (29 September 2026)

The source allowlist includes product documentation, architecture, connector
permissions and blind spots, conservative OWASP NHI 2025 mappings, issue/PR
templates, contribution and conduct policies. Workstation notes, provider reports,
credentials, generated dependencies and binaries are excluded. Git history is
scanned without path exemptions. CI checks the full fetched history; CodeQL is
configured for the future public repository and does not claim coverage when
skipped on a private repository. Registry publication additionally requires the
maintainer-controlled `ALLOW_REGISTRY_PUBLISH=true` setting.

Go race tests with PostgreSQL and frontend/docs builds passed after the namespace
change. The corrected chart passed a clean Kubernetes installation, restricted
database role checks, upgrade and restart. The private repository is
`https://github.com/grantlinehq/grantline`; its Apache-2.0 license is detected.
Dependabot alerts and security updates, Issues, Discussions and topics are enabled.
Workflow tokens default to read permissions, and registry publication is disabled.
No dependency alerts were open when checked. Automated dependency-update PRs are
review proposals, not approved upgrades.

GitHub rejected rulesets, secret scanning/push protection and required environment
reviewers for the current private Free-plan repository. CodeQL is explicitly
skipped there, and private vulnerability reporting is unavailable until public
launch. These are outstanding controls, not successful scans or protections.
One organization owner and no outside collaborators were observed. Owner 2FA and
recovery-code custody require the maintainer's own verification; organization-wide
2FA enforcement is currently off and was not changed automatically.

The initial history contains only the reviewed 463-file source allowlist (about
2.83 MB; largest file about 163 KB). Gitleaks scanned that source and the entire
initial Git history without findings. This is bounded scanner evidence, not a
guarantee that all sensitive data is discoverable. Real provider reports and known
workstation identifiers are excluded. Actual Overview/finding/evidence navigation
was checked with synthetic imported data. A reliable publication screenshot was
not produced by the current browser capture; the README does not substitute a
design mockup for a real screenshot.
