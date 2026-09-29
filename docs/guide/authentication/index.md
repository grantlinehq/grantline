# Accounts and sign-in

The first Owner is created once using a setup token stored outside the database.
There is no public sign-up. Owners and Admins invite people from **Settings → People**.
Invitation links last 24 hours; recovery links last 30 minutes and work once.
Share them only with the intended recipient. Issuing a new link invalidates earlier
links of the same kind for that email address.

| Role | Authority |
| --- | --- |
| Owner | Organization, SSO, all administration, Owner changes |
| Admin | Connections, policy, schedules, non-Owner user administration |
| Analyst | Investigation, collection using existing connections, assignment and comments |
| Viewer | Reports, identities, findings and evidence |

Authorization is enforced by the API. Disabling a user or changing their role
revokes existing sessions. The last active Owner cannot be demoted or disabled.
Password changes revoke every session. Local passwords require 15–256 bytes and
are stored with Argon2id (64 MiB, 3 iterations, parallelism 2).

Local Owner and Admin sign-in requires a TOTP authenticator. The initial setup
session cannot access the workspace until enrollment is verified. Codes are
time-based, six digits, and cannot be replayed. Keep system clocks synchronized.
Recovery links reset the password; they do not bypass an enrolled authenticator.

## OIDC SSO

Product SSO and the Entra collector are independent applications and configurations.
An Owner configures the issuer, client ID and client secret in **Settings → SSO**.
Server environment settings are also supported for initial configuration. Saved
workspace settings take precedence. Register this exact redirect URI:

```text
https://grantline.example.com/api/v1/auth/oidc/callback
```

Grantline uses authorization code flow with PKCE, state and nonce. Issuer, audience,
signature and expiry are verified. An existing local account must explicitly link
its organization identity while signed in. An invitation can create a new SSO
account only when its verified email matches the invitation. Email alone never
merges two accounts.

Owner/Admin SSO requires the provider to include `mfa` in the ID token's `amr` claim.
Configure MFA and the claim in your provider, and test with a separate account
before relying on SSO. Keep at least one protected local Owner as a recovery path.

## Session protection

Server-side sessions expire after eight hours. The browser receives an HttpOnly,
SameSite=Lax cookie; HTTPS deployments also use Secure. Mutations require matching
Origin and a session-bound CSRF header. Authentication is rate-limited. Proxy
forwarding headers are ignored unless the immediate proxy is explicitly trusted.
