# Static analysis review

This records narrow, reviewed CodeQL exceptions. Queries and scans remain enabled;
an exception does not apply to new call sites or weaken the deployment defaults.

## Stable inventory IDs

`go/weak-sensitive-data-hashing` follows Entra's `passwordCredentials` metadata
into `internal/model.stableID`. The collector's `credential` type accepts only
`keyId`, start/end timestamps and type. The hashed native identifier contains a
validated GUID and a resource path, never the credential value. `secretText`,
`hint` and certificate key payloads have no destination in that type. Collector
canary tests verify that these fields and authorization tokens do not reach reports.

SHA-256 provides deterministic inventory IDs; this finding is a false positive
for password storage. Actual account passwords use salted Argon2id in
`internal/platform/crypto.go`. Changing the inventory hash would break stable IDs
without improving password protection.

## Legacy HTTP report viewer

The two `go/cookie-secure-not-set` findings in `internal/viewer/server.go` concern
login and logout for `grantline serve --report`. This command accepts only literal
`127.0.0.1`, checks the exact Host and Origin, and serves HTTP on that local address.
Its host-only cookies use HttpOnly, SameSite=Strict and server-side expiry/revocation.
The viewer tests reject alternate hosts, remote listen addresses and cross-origin
requests and exercise authentication and logout.

Omitting Secure is an accepted exception for this local HTTP compatibility path.
Do not expose it through a network proxy. Remote access must use `grantline server`
with HTTPS, whose cookie handling enables Secure and enforces its configured public
origin. Expanding the viewer's listener or deployment scope requires reopening
this review and adding TLS; this exception is not a general cookie recommendation.
