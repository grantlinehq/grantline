# Contributing to Grantline

Use small, reviewable changes with a clear problem statement and validation.
Discuss contract changes before changing stable identity IDs, evidence provenance,
coverage semantics or report formats. Do not infer cross-provider identity from names.

## Development

Build the web application and embedded docs with Node 24 and pnpm 11.19.0:

```sh
cd web
corepack enable
pnpm install --frozen-lockfile
pnpm build:all
cd ..
go test ./...
go vet ./...
go build ./cmd/grantline
```

The Go version is declared in `go.mod`. `web/dist` must exist before compiling
the Go binary. For a local database use the product Compose files. Database tests
require `GRANTLINE_TEST_DATABASE_URL` pointing at a disposable PostgreSQL database
with no running Grantline server; tests use random schemas and exercise the
database-wide single-worker lease. Never point tests at a production database.

The design preview is a separate Vite development entry at `/design-preview.html`.
It uses fictional data and is excluded from the shipped build. Never enter real
credentials into it. Product flows must also pass tests against the real API.

## Required checks

Run relevant Go tests, frontend build and component render checks. For chart changes
run Helm lint/template with both example profiles and verify invalid values fail.
Authentication and persistence changes need PostgreSQL integration tests. Schema
changes need migration/restore testing. Update English product docs for behavior changes.

Provider collectors must keep bounded reads, explicit scope, credential isolation,
accurate unknown/partial states, and secret-free snapshots. Use synthetic fixtures
and in-process HTTP test servers; never include personal tenant IDs, observer tokens,
live reports, credentials, local browser profiles or private test outputs in commits.

By contributing, you agree to license your contribution under Apache-2.0. Do not
submit code or data you are not authorized to share. Report security issues privately
as described in SECURITY.md.

## Issues and pull requests

Use the bug, feature, connector or false-positive issue form. Discuss changes to
public contracts before implementation. Branch from `main`, keep one coherent
change per PR, and fill in the validation/security/compatibility template. Never
claim a test passed if it was not run. Follow [community conduct](CODE_OF_CONDUCT.md).

## New collectors and rules

Document provider versions, exact read permissions, authentication mode, stable
native identifiers, scope limits, pagination and expiry/permission/outage behavior.
Credentials belong in per-job inputs or secret references, never reports or logs.
Do not introduce executable authentication plugins or automatic permission grants.

A detection rule needs stable ID/version semantics, the exact matched condition,
linked evidence, a remediation recommendation and honest limitations. Include
positive, negative, missing/denied/incomplete evidence and exact-exception cases.
Document likely false positives and false negatives. Preserve UNKNOWN when the
required evidence is unavailable; a missing object is not proof of remediation.
Update the selected OWASP mapping only when the implemented evidence supports it.

## Release work

Follow [release operations](docs/guide/operations/releases.md). Public visibility,
registry publication and stable/production-ready claims are separate decisions.
