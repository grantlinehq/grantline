# Changelog

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
