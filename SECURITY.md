# Security policy

Grantline is being prepared for its first public release. The current candidate
is `v0.1.0-rc.1`; it is not approved as production ready. No stable release has a
security-support commitment yet. Fixes currently target the latest development
candidate; older milestone builds do not receive separate maintained branches.

## Private vulnerability reports

The selected public-launch reporting channel is GitHub private vulnerability
reporting for `grantlinehq/grantline`:
[Report a vulnerability](https://github.com/grantlinehq/grantline/security/advisories/new).
The repository must be public and this feature enabled before that link is usable.
Enabling and verifying the channel is a public-launch gate, not a completed action.
No security email address has been designated.

Do not disclose vulnerabilities, secret values or private identity reports in a
public issue, discussion or pull request. During the private pre-launch phase,
use an existing private communication channel with the maintainer. If the public
reporting link is unavailable later, request restoration of the reporting channel
without publishing vulnerability details or credentials.

Reports are handled on a best-effort basis; no response-time SLA is promised.
Please coordinate disclosure with the maintainer while a report is investigated
and a fix or mitigation is prepared. An acknowledgement is not permission to test
third-party deployments.

## Scope and useful evidence

In scope: Grantline source, authentication/authorization, credential handling,
collectors, API, shipped installation definitions and the release pipeline.
Source-provider vulnerabilities, other organizations' deployments and private lab
infrastructure are outside the Grantline project's authorization to test. General
feature requests and policy-tuning disagreements belong in ordinary issues unless
they demonstrate a security defect.

A useful report includes affected version, deployment type, expected/observed
behavior and a minimal sanitized demonstration using synthetic data. Do not access
other organizations, broaden source privileges, extract secrets or disrupt services
to demonstrate an issue.

The application is single-organization and single-active-instance. Protect its
public endpoint with HTTPS, restrict database/network access, encrypt Kubernetes
Secrets at rest, and keep encryption keys separate from database backups. The
application never needs a Docker socket, privileged mode, or a SPIRE admin socket.

Connector credentials are encrypted separately from reports, or loaded from
operator-managed secret files. Read the [metadata handling contract](docs/metadata-handling.md)
for the distinction between inventory, encrypted credentials and operational files.
A database backup paired with
the master encryption key is security-sensitive. Review restored sessions and
pending invitations after incident recovery. See the embedded operations guide.
