# Security

## Reporting a vulnerability

**Do not open a public issue.** A public issue discloses the vulnerability to
everyone who has access to this repository.

Report privately through GitHub's security advisory form
(`Security` → `Report a vulnerability`), or by email to the maintainers listed
in `git log`.

Please include:

- What the flaw is, and which component is affected
- Steps to reproduce, ideally as a test against `test/integration`
- What an attacker gains
- Whether any real data was affected

Please give us **90 days** before public disclosure.

## Supported versions

Only the latest commit on `main` is supported. There are no backported security
fixes for older revisions.

| Version | Supported |
|---|---|
| `main` | Yes |
| Anything older | No |

## Security status

**This software has not been audited.** No third party has reviewed it. It has
also not been certified against the OpenID Foundation conformance suite. Treat it
as a reference implementation.

Known limitations are listed in [`README.md`](README.md) under *Project status*.

## Cryptographic choices

### Password hashing — Argon2id

| Parameter | Value | Rationale |
|---|---|---|
| Memory | 65536 KiB (64 MiB) | OWASP first recommendation |
| Iterations | 3 | Second parameter, adjusted as hardware improves |
| Parallelism | 4 | Matches typical core counts |
| Salt length | 16 bytes | Per password, random |
| Key length | 32 bytes |

Stored in PHC string format with the parameters embedded:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
```

Embedding the parameters means cost can be raised later without invalidating
existing passwords: the verifier reads the parameters from the hash and
re-hashes on successful login if they are below the current policy.

Argon2id is used **only** for user-chosen passwords. It is deliberately not used
for anything else.

### Everything else — SHA-256 or HMAC-SHA256

| Value | Entropy | Primitive | Why |
|---|---|---|---|
| Password hash | low | Argon2id | Must resist offline guessing |
| Client secret hash | 256 bits | SHA-256 | No guessing resistance to protect; Argon2 would cost 100ms of CPU per `/token` call, reachable by anyone holding a public `client_id` |
| MFA backup code hash | 128 bits | SHA-256 | Same reasoning |
| Authorization code hash | 256 bits | SHA-256 | Lookup key, never a credential |
| Refresh token hash | 256 bits | SHA-256 | Lookup key |
| Email in audit log | low | HMAC-SHA256 + pepper | A bare SHA-256 of an email is reversible from a rainbow table |

All opaque tokens and codes are **32 bytes from `crypto/rand`**, base64url
encoded without padding. Not UUIDs, not truncated UUIDs.

### Encryption at rest — AES-256-GCM

Used for TOTP secrets and signing key private halves.

- 32-byte key, from `OAUTH_KEY_ENCRYPTION_KEY`, or a KMS in production
- Fresh random 96-bit nonce per record
- Additional authenticated data binds the row identifier, so a ciphertext
  cannot be transplanted from one user to another
- The key is never in `config.yaml`, never in the repository, and never in an
  example file

The loader refuses to start if the key is missing, malformed, or equal to a
value shipped in an example file.

### Signing — RS256

RSA 2048 minimum. `kid` is present on every token. The JWKS publishes the
active key plus any key still inside its retention window.

Rotation publishes the new key, waits at least the JWKS cache lifetime plus
clock skew, and only then begins signing with it. Retirement destroys the
private half while keeping the public half long enough for outstanding tokens to
expire.

### Randomness

`crypto/rand` exclusively. `math/rand` is banned and `gosec` rule G404 is
explicitly enabled to enforce it.

### Timing

- Authentication responses include uniform jitter to defeat response-time
  enumeration.
- An unknown account verifies against a fixed dummy Argon2 hash, so a miss costs
  the same as a hit.
- PKCE, TOTP counters and backup codes use `subtle.ConstantTimeCompare`.

## Password policy

Minimum 12 characters. No complexity rules, no forced rotation, no
expiry. Length is the property that matters; composition rules push users
toward predictable substitutions.

Breached-password screening is not implemented and should be added.

## Password recovery

Self-service recovery is implemented. It is account recovery, not the OAuth
resource-owner password grant (`grant_type=password` remains unsupported).

`GET /forgot-password` is the HTML form linked from `/login`.
`POST /forgot-password` is a public JSON endpoint. Every caller receives
`202 Accepted` with the same body, including unknown and malformed addresses,
so the endpoint is not an account oracle. A reset mail is sent only when an
enabled account exists; a lockout still receives mail so the user can recover.
The request shares the registration rate-limit key (`3/hour` per IP).

The mailed link points at `GET /reset-password?token=...`. The token is 32
bytes from `crypto/rand`, stored as a SHA-256 hash, single-use, and expires
after 30 minutes by default. The page script removes the token from the
address bar and never writes it to browser storage.

`POST /reset-password` redeems the token, hashes the new password with
Argon2id, consumes the token with a conditional `UPDATE`, then revokes every
session and refresh token for that user. The password must meet
`security.password_min_length` (12). Unknown, expired, used, and
wrong-purpose tokens all return `401` with `{"error":"invalid_token"}`.
Access tokens are self-contained JWTs, so they remain acceptable until
`tokens.access_ttl` unless the resource server introspects.

## Session cookies

```
Name:     __Host-oauth_session
Secure:   true
HttpOnly: true
SameSite: Lax
Path:     /
Domain:   (absent)
```

The `__Host-` prefix is not decoration. A conforming browser rejects the cookie
unless all three of these hold, which is exactly what prevents a subdomain from
injecting or overwriting it. Without the prefix, any subdomain can set
`oauth_session` for the parent domain — which is login CSRF.

Session identifiers are 32 bytes from `crypto/rand`.

Sessions expire on both an idle timeout and an absolute timeout, and carry the
assurance level (`acr`, `amr`) established at login or MFA.

## Rate limiting

Two tiers, both backed by Redis with Lua for atomicity:

| Endpoint | Per IP | Per account / client |
|---|---|---|
| `/login` | 5/min | 10/hour per email |
| `/mfa` | — | 3/min per pending challenge, 5 total attempts |
| `/token` | 10/min unauthenticated | 60/min per client |
| `/par` | — | 60/min per client |
| `/users/register`, `POST /forgot-password`, `POST /reset-password` | 3/hour | — |
| `/register` | 3/hour | — |

Fails **closed** by default: if Redis is unavailable, the authorization and
token endpoints deny rather than allow.

Client address resolution trusts `X-Forwarded-For` only when the immediate peer
is inside `server.trusted_proxies`. An empty list means forwarded headers are
ignored entirely, which is the correct default.

## CSRF

Cookie-authenticated browser endpoints (`/authorize`, `/login`, `/mfa`,
`/consent`) require a CSRF token bound to the flow. Machine endpoints
(`/token`, `/revoke`, `/introspect`, `/par`, `POST /forgot-password`,
`POST /reset-password`) do not — they are not cookie-authenticated, and
wrapping them in cookie-based CSRF breaks non-browser clients.

The skip list is a positive allowlist by route group, not a denylist.

## Secrets handling

- `config.yaml` contains no secrets and never will.
- `.env` is gitignored. `.env.example` holds placeholders only.
- `.dockerignore` excludes `.env`, `*.pem` and `*.key` from the build context, so
  they cannot reach an image layer.
- Production secrets come from a secret manager or KMS.
- Signing keys are encrypted at rest and their private halves are destroyed on
  retirement.
- The application database role is `INSERT`-only on `audit_log`.

## Audit logging

Events are typed structs, not free-form maps, so no code path can place
unnecessarily identifying data into a record by accident. Email addresses are
stored as peppered HMACs.

Retention is enforced by dropping monthly partitions, not by ad-hoc `DELETE`.

Erasure nulls `actor`, `ip_address` and `user_agent`. It does **not** attempt to
rewrite arbitrary JSONB, which cannot be done soundly by removing top-level keys.

## Known risks

1. **No security audit has been performed.**
2. **OpenID conformance is not certified.** Expect gaps.
3. **Revocation is not real-time** for self-contained access tokens.
4. **Single MFA factor** (TOTP). No WebAuthn, no passkey, no second factor slot.
5. **Back-channel logout is best-effort.** No durable delivery guarantee across a
   process restart.
6. **Pairwise subjects are not implemented.** `sub` is public, so two clients can
   correlate a user. This matters for privacy and is a FAPI requirement.
7. **No proof-of-work or CAPTCHA** on registration, so volumetric signup abuse is
   only slowed by rate limiting.
8. **No DPoP or mTLS.** A bearer token is replayable if it leaks.
9. **Admin endpoints** (`DELETE /users/{id}`, `POST /keys/rotate`) require an
    admin session but do not yet require recent re-authentication or a reason
    reference.
10. **The audit partition maintenance job is not implemented**, so retention is
    currently unenforced.