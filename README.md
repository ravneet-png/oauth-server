# OAuth Server

An OAuth authorization server in Go with OAuth 2.1-aligned practices (mandatory
PKCE, no implicit grant, refresh-token rotation). It also covers related RFCs
and OpenID Connect features used by the developer console. It is not
production-grade software and is not a fully compliant OAuth 2.1 or OpenID
Connect implementation.

## Standards Implemented

The following specifications are partially implemented with OAuth 2.1-aligned
practices. This list is not a claim of full compliance or certification.

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
git clone https://github.com/ravneet-png/oauth-server.git
cd oauth-server
cp .env.example .env   # optional in development; required in production
docker compose up -d   # builds the app and starts postgres, redis and mailhog
```

Open **`http://localhost:8080`** in your browser to use the interactive **OAuth 2.1 + OIDC Developer Console**:

1. Create an account at `/signup`, verify the address from the email, and sign in. The login page links to `/forgot-password`; reset links open a working `/reset-password` form backed by the existing JSON recovery endpoints.
2. On `/`, the console builds a cryptographically random WebCrypto S256 PKCE pair, generates fresh `state` and `nonce`, and pushes the request to `POST /par` by default. You can turn PAR off to compare the direct `/authorize` route. The public demo client uses no client secret.
3. Approve the unchanged consent screen (`/consent`). The callback at `/callback` checks that `state` matches the pending tab transaction and that the returned RFC 9207 `iss` exactly matches the configured issuer before enabling a manual `POST /token` code exchange. It can call `/userinfo`, `/introspect`, refresh rotation, replay detection, and `/revoke` for the issued token. JWT headers and claims are decoded for inspection only; the browser does **not** verify signatures or claims.

Password recovery is self-service account recovery, not the OAuth resource-owner password grant. `POST /forgot-password` always returns the same `202` message so it cannot be used to probe whether an address is registered; a one-time mail is sent only when an eligible account exists. `GET /reset-password` strips the token from the address bar and submits `POST /reset-password`, which updates the password and revokes that account's sessions and refresh tokens. Unusable tokens return `401` with `invalid_token`.

The console also exposes the existing `client_credentials` grant for a pre-registered confidential client. A secret is accepted only for that one request, is never persisted to local/session storage, and the input is cleared after submission. A browser cannot protect a confidential secret, so use this only with a throwaway development client; use server-to-server authentication in production. There is no UI for dynamic client registration, which remains disabled by default, and the OAuth resource-owner password grant remains unsupported.

The server applies its embedded migrations automatically on startup, and also provides `cmd/migrate` (`make migrate-up`, `make migrate-down`, `make migrate-status`) for standalone schema management. In development (`OAUTH_ENV=development`), it also auto-seeds a public PKCE client (`client_id: demo-client`, `redirect_uri: http://localhost:8080/callback`) so the authorization-code browser flow works out of the box without manual `psql` or `curl` commands.

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

This runs `go test -race -shuffle=on -count=1 ./...`: the full suite with the
race detector, randomized test order, and test-result caching disabled.

## Project status

This is an OAuth 2.1-aligned reference implementation, not a production-grade
or fully compliant OAuth 2.1 or OpenID Connect server. It has not been audited
or certified, and it has not passed the OpenID Foundation conformance suite.
Access tokens are self-contained JWTs, so revocation is not real-time — it is
bounded by `tokens.access_ttl` seconds. Device
authorization (RFC 8628), DPoP (RFC 9449), mTLS (RFC 8705), and pairwise
subjects are not implemented. Self-service password recovery is implemented;
see [`SECURITY.md`](SECURITY.md) for that flow and the full limitations list.

## License

MIT — see [`LICENSE`](LICENSE).
