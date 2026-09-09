# secure-notes-api

A Spring Boot REST API for personal notes, built to exercise the authentication, authorisation
and supply-chain controls that a small production service needs. Users register, receive a short
access token and a rotating refresh token, and can only ever read or modify their own notes.

The interesting part is not the notes. It is the security behaviour around them, and the tests
that prove it: refresh-token rotation with replay detection, per-owner access control verified by
negative tests, and a build that fails when a dependency has a known critical vulnerability.

## Running it

Requires JDK 25. The Gradle wrapper downloads everything else.

```bash
export SECURITY_JWT_SECRET="$(openssl rand -base64 48)"
./gradlew bootRun
```

The application refuses to start without `SECURITY_JWT_SECRET`. That is deliberate: an earlier
version of this project shipped a default signing key in `application.properties`, which meant any
deployment that forgot to override it signed tokens with a value published in this repository.

Storage is an H2 file database under `./data` by default. Flyway owns the schema and Hibernate is
set to `validate`, so a mapping that drifts from the migrations fails at startup instead of
silently altering tables.

```bash
./gradlew test          # 98 tests
./gradlew build         # test + 70% instruction coverage gate
./gradlew cyclonedxDirectBom   # writes build/reports/sbom/sbom.json
```

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | none | Create an account, returns a token pair |
| POST | `/api/auth/login` | none | Exchange credentials for a token pair |
| POST | `/api/auth/refresh` | refresh token | Rotate the refresh token, issue a new access token |
| POST | `/api/auth/logout` | access token | Revoke the caller's refresh tokens |
| GET | `/api/notes` | access token | List the caller's notes |
| POST | `/api/notes` | access token | Create a note |
| GET/PUT/PATCH/DELETE | `/api/notes/{id}` | access token | Operate on a note the caller owns |
| GET | `/api/admin/users` | ROLE_ADMIN | List accounts, without password hashes |
| PATCH | `/api/admin/users/{id}/role` | ROLE_ADMIN | Assign ROLE_USER or ROLE_ADMIN |

A worked example:

```bash
BASE=http://localhost:8080

TOKENS=$(curl -sS -X POST $BASE/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.test","password":"SecureP@ss1"}')

ACCESS=$(echo "$TOKENS" | jq -r .accessToken)

curl -sS -X POST $BASE/api/notes \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"title":"First note","content":"hello"}'
```

## Security behaviour

**Access tokens.** HS256 JWTs with a 15 minute lifetime, carrying an issuer that is verified on
every parse. The signing key must decode from Base64 to at least 256 bits or the application will
not start.

**Refresh tokens.** 256 bits from `SecureRandom`, returned to the client once and stored only as a
SHA-256 digest, so a database disclosure cannot be replayed against `/api/auth/refresh`. Each
rotation revokes the token it replaces. Presenting an already-revoked token is treated as evidence
that the token leaked, and revokes every outstanding token for that account.

That last behaviour has a subtlety worth calling out, because getting it wrong is silent: the
revocation runs in its own transaction. The rotation attempt ends by throwing, which rolls its own
transaction back, and a revocation written inside that transaction would be rolled back with it.

**Authorisation.** Ownership is checked in `NoteService` rather than in controllers, so every read
and write path shares one check. A note owned by someone else returns 404 rather than 403, so the
API does not confirm which note ids exist.

**Rate limiting.** Fixed per-minute windows, tighter on the authentication endpoints. The client
address comes from `getRemoteAddr()` and `X-Forwarded-For` is ignored unless
`security.rate-limit.trust-forwarded-for` is set, because an attacker who can vary that header can
otherwise defeat the limit entirely. The bucket map is bounded so a spoofed-address flood cannot
exhaust the heap.

**Passwords.** BCrypt at strength 12, with a policy requiring length, mixed case, a digit and a
symbol, and rejecting a list of common passwords.

Limitations, and what is deliberately not claimed, are in [docs/threat-model.md](docs/threat-model.md).

## Supply chain

`./gradlew build` produces a CycloneDX 1.6 SBOM. CI generates it on every push and scans it with
Grype, failing on high or critical findings.

This is not decorative. The current build pins `org.apache.tomcat.embed` to 11.0.25 because the
version Spring Boot 4.1.1 manages, 11.0.24, is affected by GHSA-9xv2-5v5q-p794,
GHSA-h3x4-894j-xpx5 and GHSA-gcx9-497g-6cp6. The override in `build.gradle.kts` records why and
when it can be removed.

## Layout

```
src/main/java/com/metercedes/securenotes/
├── config/       Spring Security filter chain, password encoder, authentication provider
├── controller/   REST endpoints and the exception-to-status mapping
├── dto/          Request and response records with Bean Validation constraints
├── exception/    Domain exceptions
├── model/        JPA entities
├── repository/   Spring Data repositories
├── security/     JWT issuing and parsing, bearer filter, rate limiting
├── service/      Account, note and refresh-token logic
└── validator/    Username and password policy constraints
```

## Testing

98 tests. The ones that matter are the negative cases:

- `AccessControlIntegrationTest` — a second account attempting to read, replace, patch and delete
  another user's note; a normal user attempting admin endpoints; a registration body that tries to
  set its own role; unauthenticated and forged-token requests.
- `AuthIntegrationTest` — refresh rotation, reuse of a rotated token, revocation of the whole token
  family after a replay, unauthenticated logout, and account enumeration through login responses.
- `JwtServiceTest` — short keys, non-Base64 keys, foreign signatures, `alg: none` tokens, expiry
  and subject mismatch.

## History

This started as a university lab exercise and was rebuilt: package renamed, Lombok removed
(`@Data` on JPA entities generates `equals`/`hashCode` over mutable fields), Spring Boot upgraded
3.2.3 to 4.1.1, the committed keystore and default signing key removed, coursework controllers
deleted, and refresh tokens changed from plaintext UUIDs to hashed random tokens with replay
detection.
