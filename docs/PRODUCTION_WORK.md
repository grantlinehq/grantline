# Grantline v0.1.0 implementation and acceptance

Updated: 2026-10-06. Target: Apache-2.0, `github.com/grantlinehq/grantline`.
The local candidate is implemented and testable. **It is not yet approved as
production ready.** The release process produces versioned Docker and Helm
distribution packages. The historical prelaunch record below separates measured
acceptance from remaining product and publication checks.

## Current publication status

The rc.4 publication is verified: all 16 public assets, checksums and signatures,
anonymous image/chart pulls, clean Compose Owner/TOTP/restart and Helm
install/upgrade persistence passed on 6 October. The published package remains
v0.1.0-rc.4; subsequent source changes below are not a retag of that release.

## Investigation clarity

Jenkins source mappings now read credential references from selected immutable
GitHub files. IL009 reviews exact collected Vault AppRoles shared by jobs in
explicitly separated environments; unknown metadata, unassigned jobs and runtime
use are not promoted to observed identity sharing. Exact reasoned exceptions are
recorded. A fresh six-source lab collection established one such Jenkins/Vault
configuration finding while preserving the earlier findings. All source scopes
completed; no pipelines were executed to produce this finding.

GitHub source filters also include Entra application findings connected through
evidenced federation relationships. Related-source labels and relationship links
keep the Entra root cause separate; no standalone GitHub vulnerability is invented
or duplicated in report totals. The three selected Jenkinsfiles were added to the
maintainer-authorized demo repository without secret values or workflow changes.

Go race, PostgreSQL, policy serialization and negative evidence tests passed;
frontend/docs compilation and public documentation link checks passed. These
source additions are not included in the immutable rc.4 distribution.
Source-filtered findings evaluate matching application sets once and return their
total/page together. Schema migration 4 adds federation-key indexes. On the shared
Windows Docker Desktop host with aggregate 4 CPU / 8 GiB container caps, the
10,000-identity/10-user acceptance measured p95 about 290 ms; a separate stored
projection fixture with 1,000 related findings and 10 concurrent requests measured
p95 about 383 ms. These fixture measurements are not customer deployment results.

Finding APIs now project named subjects, known observed fields and the recorded
collection policy without changing report IDs, evidence or exported reports.
Counts separate native principals from configuration objects. Source/rule selectors
and affected-subject search support review, including credential parent names and
SPIFFE identifiers. Imported reports do not borrow today's policy thresholds.

Ten findings from real controlled lab systems were reviewed against saved evidence:
eight action-needed configurations, one expected HPA controller configuration
candidate and one declared environment-reuse finding needing further evidence
before claiming runtime crossing. All remain In review with reasons. This is a
selected lab sample, not customer validation or a false-positive-rate estimate.
The public docs contain sanitized cases; private report IDs and raw snapshots stay
outside the source package. The local workspace is named Grantline; deployment
documentation presents technical scope rather than a launch-stage UI badge.

Full provider failure/expiry coverage, customer IdP/SMTP and full accessibility
acceptance remain open. Removing a stage label does not close those gates.

## Earlier publication record

The repository, rc.3 multiarchitecture GHCR image, OCI chart and signed installation
packages are public. Public Checks and CodeQL run on main; secret scanning, push
protection and private vulnerability reporting are enabled. The private-preparation
and publication-on-hold statements below are historical, not current blockers.

The rc.2 candidate repairs embedded documentation builds, integration layout and
collection reporting, and verifies the exact release tag before publishing assets.
It adds no generated-data mode to the server. Optional analyzer fixtures remain
offline and are always labeled synthetic. Provider collection uses the configured
APIs, with SPIRE explicitly recorded as a provider export.

The rc.3 candidate adds the guided effective-policy editor, saved-evidence preview,
coverage-reduction acknowledgement and guided integration scope forms. Its public
Checks, CodeQL and release workflows passed. Anonymous asset downloads, checksum
and image/chart signature verification, clean Compose setup with Owner/TOTP and
persistence, and public-chart Kubernetes installation/upgrade/restart passed on
4 October. The rc.4 announcement candidate refreshes the security-support policy,
compatibility record and actual-product screenshots; its publication must pass
the same release gates before it is described as available.

The three initial CodeQL findings were reviewed: one inventory-ID false positive
and two loopback HTTP viewer exceptions. The rationale is recorded in
[static analysis review](guide/reference/security-review.md). This does not disable
any query or exempt the persistent HTTPS server.

Each candidate still requires successful CI, signed artifact verification and fresh
Compose/Helm installation against its exact published digests. Live-provider
failure/expiry matrices, a customer IdP/SMTP run and full WCAG review remain required
before any production-ready claim. macOS and real ARM64 hardware are unverified.

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
  relationship configuration with revision history. The guided policy editor
  includes validation and a saved-evidence preview; advanced policy and business
  context/relationship declarations also accept validated YAML.
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
No dependency alerts were open when checked. Routine dependency version-update
PRs are disabled during prelaunch; the initial eight proposals were closed and
their branches removed at the maintainer's request. Security alerts and security
updates remain enabled; a security fix may still generate a review proposal.

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

### Release distribution preparation

The maintainer authorized GHCR image, OCI chart and ready installation-package
publication for v0.1.0-rc.1, and reported that Owner 2FA/recovery preparation is
complete. The release workflow now creates versioned installation ZIP/TAR files,
source, chart, release metadata and signed checksums. It verifies both registry
architectures, a fresh Compose installation, image/chart signatures and chart
download before creating the GitHub prerelease. Registry and anonymous download
results are recorded separately from the earlier local-only artifact tests.
