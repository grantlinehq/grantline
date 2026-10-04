# Your identities, with their evidence

Grantline collects metadata about non-human identities and their permissions,
connects explicit relationships, and presents evidence-backed policy findings.
Data stays in your environment. Telemetry is disabled; the application has no
analytics or telemetry sender.

The first version supports **one organization and one active application instance**.
PostgreSQL stores accounts, connections, reports, review decisions and the durable
collection queue. Redis is not required. Kubernetes does not add application HA.

::: warning Preview release
v0.1.0-rc.3 is an early-access release candidate with ready Docker and Helm installation packages.
Full live-provider/IdP/SMTP and accessibility acceptance remains open; this version
is not labeled production ready. See [compatibility](./reference/compatibility).
:::

Start with [Docker Compose](./install/docker), or use the official
[Helm chart](./install/kubernetes). Both run the same application image and embedded
documentation. Go and Node.js are only needed when building from source.

## A typical investigation

1. Connect an observer identity with an explicit source scope.
2. Test access, review coverage, then enable the connection and collect.
3. Open a finding, inspect the affected identities and supporting evidence.
4. Assign an analyst, add context and record a review decision.
5. Revisit accepted risks before their expiry dates.

**PASS**, **FAIL** and **UNKNOWN** are policy outcomes. **Open**, **In review**,
**Accepted risk** and **Resolved** are human review states. Accepting a risk does
not make the underlying rule pass. Missing collection data never automatically
resolves a finding. Metadata and declared relationships do not prove credential use.

Reports are immutable snapshots. Importing a historical report preserves its
collection time and provenance; it does not create a functioning connection.
