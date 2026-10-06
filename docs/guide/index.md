# Your identities, with their evidence

Grantline collects metadata about non-human identities and their permissions,
connects explicit relationships, and presents evidence-backed policy findings.
Data stays in your environment. Telemetry is disabled; the application has no
analytics or telemetry sender.

The first version supports **one organization and one active application instance**.
PostgreSQL stores accounts, connections, reports, review decisions and the durable
collection queue. Redis is not required. Kubernetes does not add application HA.

::: info Deployment scope
Docker Compose and Helm use the same application package. Run one active instance
per organization. Review the tested environments and remaining provider, IdP,
SMTP and accessibility verification in [compatibility](./reference/compatibility).
:::

Start with [Docker Compose](./install/docker), or use the official
[Helm chart](./install/kubernetes). Both run the same application image and embedded
documentation. Go and Node.js are only needed when building from source.

## Documentation and installed version

This documentation follows the source revision embedded in your application.
The **v0.1.0-rc.5** package includes IL001–IL009, related GitHub findings and
expanded finding explanations. Earlier rc.4 packages lack those additions and
use an older database schema. See
[release versions](./operations/releases.md) and the
[schema-4 upgrade boundary](./operations/upgrades.md) before changing versions.

Grantline supports **six provider types** and up to **20 saved connections**.
You can connect multiple instances of the same provider. Connection count is not
the number of available integrations. SPIRE uses a validated metadata export.

## A typical investigation

Learn the engine, policy choices and evidence boundaries through
[three practical investigations](./policies/three-investigations.md).
For cross-provider review, continue with the
[Jenkins/Vault and GitHub/Entra investigation](./policies/pipeline-investigation.md).

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
