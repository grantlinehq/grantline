# API and CLI

Download the [OpenAPI 3.1 contract](./openapi.json), also served at
`GET /api/v1/openapi.json`. The [report](./report.schema.json) and
[snapshot](./snapshot.schema.json) JSON Schemas document immutable exports.

The persistent product API is rooted at `/api/v1`. It uses the same server-side
session and roles as the browser. Authenticate, obtain a CSRF value from
`GET /api/v1/auth/session`, and include `X-Grantline-CSRF` plus the configured
`Origin` for mutations. There is no unauthenticated data API or long-lived API key.

## List and investigation responses

`GET /api/v1/objects/{category}` supports `identities`, `findings`, `relationships`
and `evidence`. Lists return `run_id`, `items`, `total`, `page` and `page_size`.
Pagination is server-side, zero-based and fixed at 50 records per page.

| Query | Meaning |
| --- | --- |
| `page` | Page index, from 0 to 100000 |
| `q` | Search text, at most 256 UTF-8 bytes. Findings also search affected subject names, native IDs and credential parent applications in rc.5. |
| `source` | Exact connection ID, not a provider type |
| `kind` | Object kind, or a rule ID such as `IL009` for findings |
| `native=true` | Restrict identity results to native principals, excluding configuration objects |
| `state` | Finding review state: `open`, `in_review`, `accepted_risk`, `resolved`, or `active` (open and in review) |
| `run` | Historical report ID; omission selects the latest saved report |

For example, after authenticating:

```text
GET /api/v1/objects/findings?source=jenkins-team&kind=IL009&state=active&page=0
GET /api/v1/objects/findings?q=delivery&run=REPORT_ID&page=0
```

Finding items in rc.5 include `context`: named subject, root `source_ids`,
native-principal and configuration-object counts, known `facts`, rule outcome and
limitations, observation time and recorded policy availability/revision. Facts
carry `assertion_kind`; configured and declared values are not runtime observations.
An imported report without recorded policy does not borrow current settings.

GitHub source filters also include Entra application findings through exact
evidenced federation relationships. `context.related_sources` identifies the
workflow, source and relationship IDs; the original finding ID, root source and
triage remain unchanged. All-source totals do not count a related finding twice.
There is no standalone GitHub vulnerability rule. These context and related-source
additions are included in rc.5 and were absent from rc.4; use the OpenAPI
contract served by your installed binary and see
[release versions](../operations/releases.md).

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
| Policy preview | `GET /settings/policy`, `POST /settings/policy/validate` |

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
