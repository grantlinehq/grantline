# Changelog

## Unreleased

## v0.1.0-rc.5 — Pipeline evidence and investigation guidance

- Synchronize embedded documentation with all nine rules, pipeline investigations,
  related-source finding responses and schema-4 upgrade boundaries. Separate current
  source from the published rc.4 packages and clarify provider/connection counts.
- Add IL009: review Jenkins jobs mapped to the same collected Vault AppRole across
  explicitly separated environments, with pinned-file evidence and exact reasoned
  exceptions. Missing metadata remains UNKNOWN; credential names are not identities.
- Show related Entra application findings under GitHub source filters using an
  evidenced federation relationship, labeled separately from the root cause.
- Show named subjects, known values and recorded policy thresholds in findings;
  distinguish native identities from related configuration objects.
- Search findings by affected subject, credential parent application or SPIFFE ID,
  and select source, rule and review status without entering internal identifiers.
- Keep historical policy context separate from current settings and explain rule
  coverage, UNKNOWN and policy-assigned severity alongside supporting evidence.
- Add three investigation walkthroughs and a sanitized ten-finding lab review.
- Clarify that six supported provider types are distinct from saved connections.

## v0.1.0-rc.4 — Announcement candidate

- Make security support follow the latest published preview instead of naming an
  obsolete candidate.
- Refresh the compatibility and implementation records with independently
  verified public-package results and the guided policy editor.
- Add actual-product investigation screenshots using explicitly labeled
  synthetic imported evidence; no private workspace data is published.
- Refresh versioned Docker, Helm and download references for the announcement.

## v0.1.0-rc.3 — Early access

- Add an effective-policy editor for all eight rules, required sources, lifetime
  thresholds and exact exception lists, with an advanced YAML view.
- Validate and preview policy changes on saved evidence without changing reports,
  connections or triage; require acknowledgement when disabling rules or removing
  required sources, with revision and role checks enforced by the API.
- Replace GitHub, Vault and Jenkins JSON scope inputs with guided row forms,
  provider preparation steps, permission examples and connection pickers.
- Clarify Entra identifier types, derive tenant scope automatically, and return
  field-level configuration errors without echoing submitted credential values.
- Expand policy/context examples and document the validation API.

## v0.1.0-rc.2 — Preview

- Preserve embedded documentation on every frontend build; verify installation
  guides as part of clean Compose acceptance.
- Align integration status columns and improve finding details and responsive layouts.
- Explain unattended Entra application credentials and cover token acquisition
  and provider-response redaction with tests.
- Record per-source collection method, timing and completeness without exposing
  connection configuration; commit reports and terminal run states together.
- Fix a collection cancellation watcher race while attaching per-run credentials.
- Correct default Entra owner policy targets and retain real collector behavior
  on denied access; offline fixtures remain explicitly synthetic.
- Verify release tags before registry publication and create releases from existing
  tags, preserving signed artifacts if GitHub publication is interrupted.
- Document the bounded static-analysis exceptions and contributor hot reload flow.

## v0.1.0-rc.1 — Preview

- Persistent, single-organization Go/React/PostgreSQL server alongside the existing CLI.
- Grantline brand assets, warm workspace design and English investigation interface.
- Setup, passwords, mandatory local privileged-account TOTP, invitations, recovery,
  OIDC identity linking, roles and session revocation.
- Encrypted connection credentials and named secret-file references for six metadata sources.
- Durable collections, immutable reports, paginated inventory, triage and audit history.
- Docker Compose and Helm packages, embedded VitePress documentation and operational guides.
- Multiarchitecture GHCR image and OCI Helm chart; ready Docker installation ZIP/TAR,
  signed checksums, source archive and digest-pinned installation configuration.

This candidate is not labeled production ready. Acceptance results and remaining
gates are recorded in `docs/PRODUCTION_WORK.md`.

## M7 baseline

Six source collectors, stable identity/evidence contracts, IL001–IL008 analysis,
explicit context bindings and the authenticated single-report viewer. Existing CLI
and report compatibility remain part of the v0.1.0 regression suite.
