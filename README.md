# OAuth 2.1 + OIDC Authorization Server

A production-grade OAuth 2.1 and OpenID Connect authorization server built from scratch in Go.

## Standards Implemented

* RFC 6749 (OAuth 2.0)
* RFC 6750 (Bearer Token)
* RFC 7009 (Token Revocation)
* RFC 7591 (Dynamic Client Registration)
* RFC 7636 (PKCE)
* RFC 7662 (Token Introspection)
* RFC 9126 (Pushed Authorization Requests)
* RFC 9207 (Authorization Server Issuer Identification)
* OAuth 2.1 Draft (PKCE required, implicit removed, refresh rotation)
* OpenID Connect Core 1.0
* OIDC Back-Channel Logout 1.0
* OIDC RP-Initiated Logout 1.0

## Quickstart

```bash
git clone <repo>
cd oauth-server
cp .env.example .env   # optional in development; required in production
docker compose up -d   # builds the app and starts postgres, redis and mailhog
curl http://localhost:8080/.well-known/openid-configuration
```

The server applies its embedded migrations on startup, so there is no separate
migrate step. `cmd/migrate` is a stub; the `make schema-*` targets drive `psql`
directly and exist to test the SQL in isolation, not to run the application.

In development (`OAUTH_ENV=development`, set by `docker-compose.yml`) the server
generates ephemeral key material when `OAUTH_KEY_ENCRYPTION_KEY` and
`OAUTH_AUDIT_PEPPER` are unset, so a fresh checkout boots without any setup.
Encrypted rows do not survive a restart with generated secrets. Set both to 32
bytes of hex (`openssl rand -hex 32`) in any real deployment.

## Security Features

1. **Email scope check at consent, not authorize** — scope eligibility is re-evaluated at every consent decision, so revoked email verification cannot silently grant `email`.
2. **MFA enrollment via session cookie** — TOTP enrolment requires an authenticated browser session, preventing a recovered CSRF token from enrolling a factor.
3. **Refresh token reuse detection (atomic conditional UPDATE)** — rotation is detected with a single `UPDATE ... RETURNING` that checks `revoked_at IS NULL` in the predicate, eliminating the TOCTOU race.
4. **Tracking tables for logout** — `client_sessions` and `issued_access_tokens` link sessions to clients, enabling scoped back-channel logout.
5. **Auth code reuse cascade** — a reused authorization code revokes the entire token family it seeded, not just that one code.
6. **Session ID on auth_codes** — `auth_codes` stores `session_id` and `sid` so a token exchange can be traced back to a browser session.
7. **auth_requests table** — validated authorization parameters survive the `/authorize` → `/login` → `/mfa` → `/consent` redirect chain and PAR reference URIs.
8. **"none" client auth method** — public clients can authenticate without a secret, with security resting on PKCE.
9. **token_endpoint_auth_method column** — per-client method selection (`none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`) enforced by CHECK constraint.
10. **Session-scoped logout** — `/logout` (POST) terminates only the calling session's tokens, not every session on the account.
11. **Atomic conditional UPDATE for reuse detection** — single-statement consumption of single-use rows prevents concurrent replay.
12. **Client ownership check before cascade** — the caller is authorized against the token's own client before any revocation cascades.
13. **revocation_reason distinguishes rotation from logout** — `rotated` triggers family revocation; `logout`, `explicit`, `gdpr`, `admin` do not.
14. **GDPR erasure collects notification list before deletion** — back-channel logout targets are captured before the user row is removed.
15. **Access token revocation via introspection** — self-contained JWTs cannot be instantly withdrawn; `/introspect` is the documented mechanism (latency bounded by `tokens.access_ttl`).
16. **Rate limit per authenticated client** — `/token` and `/par` are limited per client identity, not just per unauthenticated `client_id`.
17. **Consent auto-skip, GET/POST logout, return URL validation, registration timing, audit anonymization** — consent auto-skip avoids the UI when scopes already cover the request; logout redirects are validated against a server-side allowlist; registration timing is equalized; audit actor fields are pseudonymised.

## Project Structure

```
oauth-server/
├── cmd/
│   ├── server/          # HTTP server entry point
│   └── migrate/         # Migration runner
├── internal/
│   ├── app/             # Application graph (wiring)
│   ├── audit/           # Audit log types
│   ├── authn/           # Authentication
│   ├── authz/           # Authorization
│   ├── backchannel/     # Back-channel logout delivery
│   ├── cache/           # Redis views
│   ├── client_auth/     # Client authentication methods
│   ├── config/          # Configuration loader
│   ├── consent/         # Consent management
│   ├── crypto/          # Password hashing, key encryption, TOTP
│   ├── domain/          # Entities, errors, scope
│   ├── email/           # Email sending + templates
│   ├── flows/           # Grant logic (authorize, token, revoke, etc.)
│   ├── handlers/        # HTTP handlers
│   ├── httpapi/         # Router, response helpers
│   ├── keys/            # Signing key management + rotation
│   ├── middleware/      # Recovery, headers, audit, session, rate limit
│   ├── oautherr/        # OAuth error types (leaf package)
│   ├── sessions/        # Session management
│   ├── storage/         # Repositories (pgx)
│   ├── tokens/          # JWT builders and verifiers
│   └── ui/              # HTML templates + static assets
├── migrations/          # SQL migrations (up/down pairs)
├── test/
│   ├── integration/     # Integration tests
│   ├── fixtures/        # Test fixtures
│   └── conformance/     # Conformance test scaffolding
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── config.yaml
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
└── API.md
```

## Configuration

All non-secret configuration lives in [`config.yaml`](config.yaml). Secrets come from the environment; see [`.env.example`](.env.example).

Key sections in `config.yaml`:

* `server` — host, port, issuer URL, trusted proxies
* `database` — connection URL, pool sizes, statement timeout
* `redis` — URL, revocation TTL padding, fail-closed on introspection
* `tokens` — TTLs for access, refresh, ID tokens, auth codes, PAR, etc. (all **integer seconds**)
* `keys` — algorithm, key size, rotation interval, retention window, clock skew
* `rate_limit` — per-endpoint limits (per IP, per account, per client)
* `security` — password policy, Argon2 parameters, audit pepper env var, session cookie settings, allowed internal paths
* `registration` — dynamic client registration (disabled by default)
* `email` — SMTP settings, enumeration-safe responses
* `backchannel_logout` — delivery retry policy
* `audit` — retention days
* `logging` — level, format

## Running Tests

```bash
make test
```

This runs `go test ./... -count=1 -p 1` with the race detector and shuffled test order.

## Project status

This is a reference implementation, not audited production software. It has not
been certified against the OpenID Foundation conformance suite, and access
tokens are self-contained JWTs, so revocation is not real-time — it is bounded
by `tokens.access_ttl` seconds. Device authorization (RFC 8628), DPoP (RFC
9449), mTLS (RFC 8705), and pairwise subjects are not implemented.
See [`SECURITY.md`](SECURITY.md) for the full list.

## License

MIT — see [`LICENSE`](LICENSE).
