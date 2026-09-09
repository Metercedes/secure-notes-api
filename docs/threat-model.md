# Threat model

Scope: the HTTP API and its data store. Deployment infrastructure, TLS termination and host
hardening are out of scope and are assumed to be handled by whatever fronts the service.

## Assets

| Asset | Why it matters |
| --- | --- |
| Note content | The only user data of value; confidentiality is the product |
| Password hashes | Disclosure enables offline cracking against reused passwords |
| Refresh tokens | Long-lived; possession grants continued access |
| JWT signing key | Possession allows forging any identity, including ROLE_ADMIN |

## Trust boundaries

1. **Client to API.** Everything in the request is attacker-controlled: body, headers, path
   variables, query parameters. Nothing from the request is used as identity.
2. **API to database.** Access is through Spring Data JPA with bound parameters. No string-built
   SQL exists in the codebase.
3. **Build to dependencies.** Third-party artifacts are resolved from Maven Central and inventoried
   in an SBOM scanned on every push.

## Controls, and what they actually cover

| Threat | Control | Verified by |
| --- | --- | --- |
| Credential stuffing | BCrypt cost 12; 10 auth requests/minute per address | `AuthIntegrationTest` |
| Account enumeration | Identical 401 body for unknown user and wrong password | `Login.doesNotDistinguishUnknownUser` |
| Token forgery | HS256 with a >=256-bit key, issuer verified, `alg: none` rejected | `JwtServiceTest` |
| Stolen refresh token replayed | Single-use rotation; replay revokes the whole family | `Rotation.replayRevokesEntireTokenFamily` |
| Refresh tokens read from a database dump | Only a SHA-256 digest is stored | `RefreshToken.tokenHash` |
| IDOR on notes | Ownership checked in the service layer; 404 not 403 | `AccessControlIntegrationTest.CrossUser` |
| Privilege escalation at registration | Role is assigned server-side, never read from the body | `Roles.registrationCannotElevate` |
| Password hash disclosure via admin API | Fixed projection, entity never serialised | `Roles.adminListingOmitsPasswordHash` |
| Rate-limit bypass via spoofed headers | `X-Forwarded-For` ignored unless explicitly trusted | `ClientAddressResolver` |
| Memory exhaustion of the limiter | Bucket map bounded at 100k entries | `RateLimitingFilter` |
| Stack traces and SQL in responses | `server.error.include-*=never`; catch-all returns a fixed message | `rejectsMalformedJsonWithoutStackTrace` |

## Why CSRF protection is disabled

CSRF protection defends against a browser attaching an ambient credential — a cookie or HTTP
authentication — to a cross-site request. This API accepts credentials only in an `Authorization`
header that the client must set explicitly, holds no session, and issues no cookies. A cross-site
form post therefore arrives unauthenticated.

This stops being true if a future change stores the access token in a cookie. If that happens,
CSRF protection has to come back.

## Known limitations

These are real and are not claimed to be solved.

- **Rate-limit state is per-instance and in memory.** Two replicas mean two independent counters,
  and a restart clears them. A shared store is needed for a multi-instance deployment.
- **Access tokens cannot be revoked before they expire.** Logout revokes refresh tokens; an access
  token issued moments earlier stays valid for up to 15 minutes. This is the normal trade-off for
  stateless JWTs and is acceptable only because the lifetime is short.
- **No account lockout.** Rate limiting slows credential stuffing per address but a distributed
  attempt spread across many addresses is not stopped.
- **No email verification.** Addresses are validated for format and uniqueness only.
- **No audit trail as a queryable record.** Security-relevant events go to a `SECURITY` logger, not
  to a store that can be searched or retained independently.
- **H2 is the default store.** It is chosen so the project runs with no external services. It is
  not a production database.
- **TLS is not terminated by the application.** An earlier version generated a self-signed
  certificate and committed the keystore to the repository. That keystore has been removed and
  HTTPS is expected to be provided by a reverse proxy or platform.
- **Refresh-token replay detection revokes by account, not by token family.** A user with sessions
  on several devices loses all of them when one token is replayed. That is the safe direction to
  fail, but it is a usability cost worth naming.
