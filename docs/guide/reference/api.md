# API and CLI

Download the [OpenAPI 3.1 contract](./openapi.json), also served at
`GET /api/v1/openapi.json`. The [report](./report.schema.json) and
[snapshot](./snapshot.schema.json) JSON Schemas document immutable exports.

The persistent product API is rooted at `/api/v1`. It uses the same server-side
session and roles as the browser. Authenticate, obtain a CSRF value from
`GET /api/v1/auth/session`, and include `X-Grantline-CSRF` plus the configured
`Origin` for mutations. There is no unauthenticated data API or long-lived API key.

Inventory endpoints paginate on the server with `page` (zero-based), 50 records
per page, `q`, `source`, and `kind` filters. Findings also accept `state`:
`open`, `in_review`, `accepted_risk`, `resolved`, or `active` (open and in review).
A `run` query selects a historical
report; omitting it selects the latest saved report. Object IDs and provenance
remain stable according to the report contract.

Detail responses include at most 100 evidence records, affected identities and
recent comments, with explicit `*_truncated` flags. Export the immutable report
for the complete evidence set. Collection history shows the latest 100 runs;
activity shows the latest 200 audit events.

| Resource | Routes |
| --- | --- |
| Workspace | `GET /status`, `GET /overview` |
| Sign-in | `POST /auth/setup`, `/auth/login`, `/auth/mfa`, `/auth/logout` |
| Accounts | `GET /users`, `PATCH /users/{id}`, `POST /invitations`, `/recovery` |
| Connections | `GET,POST /integrations`, `PUT,DELETE /integrations/{id}`, `POST /integrations/{id}/test` |
| Collections | `GET,POST /runs`, `POST /runs/{id}/cancel` |
| Evidence | `GET /objects/{category}`, `GET /objects/{category}/{id}`, `GET /graph` |
| Reports | `GET /report`, `POST /reports/import` |
| Review | `PUT /triage/{id}`, `POST /comments/{id}` |
| Administration | `GET,PUT /settings`, `GET /activity` |

Errors return a bounded JSON error code. Configuration and review writes use a
revision to prevent lost updates. Credentials are accepted only on explicit
connection writes and are never returned on reads.

## Existing CLI workflows

`grantline collect`, `grantline analyze`, and `grantline serve --report` remain
supported with their existing report contracts. The report viewer is an independent
single-report workflow; it does not create accounts or active integrations in the
persistent server. New commands are `server`, `migrate`, `init`, and `rotate-key`.

Use `grantline help` for flags and the repository's synthetic fixtures for examples.
Do not publish private collection reports or observer configuration with credentials.
