# API Reference

Base URL in development: `http://localhost:8080`

## Endpoint classes

Two classes of endpoint, with different rules. Conflating them is the source of
most OAuth server bugs.

**Browser-interactive** — reached by top-level navigation or a form post from
our own pages. Authenticated by a session cookie. CSRF-protected.

`/authorize`, `/login`, `/mfa`, `/consent`, `/signup`, `/verify-email`,
`GET /forgot-password`, and `GET /reset-password`

**Machine** — called by a client or resource server. Authenticated by
credentials in the request, never by a cookie. **Not** CSRF-protected.
`Cache-Control: no-store` on every response.

`/par`, `/token`, `/revoke`, `/introspect`, `/userinfo`, `/register`,
`/users/register`, `POST /forgot-password`, and `POST /reset-password`

**Public** — no authentication, no side effects beyond caching.

`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/health`

CORS is never applied to `/authorize`. It is a browser navigation, not a
fetch. CORS applies only to `/userinfo` and `/par`.

## Response headers

Every machine endpoint returns:

```
Cache-Control: no-store
Pragma: no-cache
```

All endpoints return `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and a content security
policy that permits no inline script.

---

## Discovery

### `GET /.well-known/openid-configuration`

No authentication. CORS: `Access-Control-Allow-Origin: *` is safe here — the
document contains no secrets.

```bash
curl http://localhost:8080/.well-known/openid-configuration | jq
```

### `GET /.well-known/jwks.json`

No authentication. `Cache-Control: max-age=3600`.

Publishes the active key plus every key still inside its retention window.
Resource servers cache this; the rotation interval is chosen to exceed the
cache lifetime.

```bash
curl http://localhost:8080/.well-known/jwks.json | jq '.keys[].kid'
```

### `GET /health`

Liveness and readiness. Checks database and Redis reachability. Returns `503`
when a dependency is down.

---

## Authorization

### `GET /authorize`

Browser navigation. No CORS.

| Parameter | Required | Notes |
|---|---|---|
| `response_type` | yes | `code` only. `token`, `id_token` and any combination are rejected. |
| `client_id` | yes | Must be registered |
| `redirect_uri` | yes | Exact string match against a registered value |
| `scope` | no | Must be a subset of the client's registered scopes |
| `state` | no | Echoed verbatim. Opaque to the server |
| `code_challenge` | yes | S256 only |
| `code_challenge_method` | yes | Must be `S256` |
| `nonce` | recommended | Required when `openid` is requested |
| `prompt` | no | `none`, `login`, `consent`, `select_account` |
| `max_age` | no | Seconds. Forces re-authentication if `auth_time` is older |
| `response_mode` | no | `query` only |
| `login_hint` | no | Pre-fills the login form |
| `ui_locales` | no | |
| `claims` | no | |
| `acr_values` | no | |
| `request_uri` | no | A PAR reference URI. Mutually exclusive with inline parameters |

`prompt=none` never renders a page. It redirects with `login_required`,
`consent_required`, `interaction_required` or `account_selection_required`.

On success, redirects to the validated `redirect_uri` with `code`, `state` and
`iss` (RFC 9207):

```
Location: https://client.example/cb?code=8xK...&state=xyz&iss=http%3A%2F%2Flocalhost%3A8080
```

On failure before a redirect URI is validated, the error is rendered directly.
After validation, errors are returned as query parameters to the client's
registered URI.

---

## Pushed authorization requests

### `POST /par`

Machine endpoint. Client authentication required. Public clients may authenticate
with `client_id` only (`token_endpoint_auth_method=none`). PKCE is **mandatory** —
a request without `code_challenge` is rejected here, not later.

CORS applies.

```bash
curl -u client_id:client_secret http://localhost:8080/par \
  -d response_type=code \
  -d client_id=client_id \
  -d redirect_uri=https%3A%2F%2Fclient.example%2Fcb \
  -d scope=openid+email \
  -d code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
  -d code_challenge_method=S256
```

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
  "expires_in": 60
}
```

Single use. A second presentation of the same `request_uri` is
`invalid_request_uri`. Lifetime is 60 seconds.

---

## Token

### `POST /token`

Machine endpoint. Client authentication required. All three grants at one
endpoint.

#### Grant type `authorization_code`

```bash
curl -u client_id:client_secret http://localhost:8080/token \
  -d grant_type=authorization_code \
  -d code=8xK... \
  -d redirect_uri=https://client.example/cb \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

#### Grant type `refresh_token`

```bash
curl -u client_id:client_secret http://localhost:8080/token \
  -d grant_type=refresh_token \
  -d refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
```

#### Grant type `client_credentials`

```bash
curl -u client_id:client_secret http://localhost:8080/token \
  -d grant_type=client_credentials \
  -d scope=read
```

Public clients (`token_endpoint_auth_method=none`) send only `client_id`.
The `none` method is refused for `client_credentials`.

#### Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid email"
}
```

`id_token` is present only when `openid` was granted. `refresh_token` is present
only when `offline_access` was granted. Access tokens carry the `at+jwt` type
header (RFC 9068).

A refresh rotates. Presenting a rotated token again revokes the entire family.

#### Rejected grant types

`implicit` and `password` return `unsupported_grant_type`. There is no code path
for them.

---

## Client authentication

All four methods. The request must use exactly one.

| Method | Credentials |
|---|---|
| `client_secret_basic` | `Authorization: Basic base64(urlencode(id):urlencode(secret))` |
| `client_secret_post` | `client_id` and `client_secret` in the body |
| `private_key_jwt` | `client_assertion_type` and `client_assertion` in the body |
| `none` | `client_id` only. Public clients. Security rests on PKCE |

Credentials are form-url-decoded before base64 decoding. A request carrying two
`Authorization` headers is rejected.

`private_key_jwt` assertions are validated for `alg`, `iss == sub == client_id`,
`aud`, and `exp` within a 60-second window. The `jti` is single-use: a replayed
assertion is rejected.

---

## Userinfo

### `GET /userinfo` and `POST /userinfo`

Machine endpoint. Bearer token. CORS applies.

Claims are filtered by the granted scope set. `sub` is always present.

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." http://localhost:8080/userinfo
```

---

## Revocation

### `POST /revoke`

Machine endpoint. Client authentication required.

```bash
curl -u client_id:client_secret http://localhost:8080/revoke \
  -d token=tGzv3JOkF0XG5Qx2TlKWIA \
  -d token_type_hint=refresh_token
```

**Always returns `200 OK`**, whether or not the token existed, whether or not it
belonged to the caller. Anything else is a token-scanning oracle. A caller may
revoke its own tokens only.

Revoking a refresh token revokes the whole family.

---

## Introspection

### `POST /introspect`

Machine endpoint. Client authentication required. Public clients may use the
registered `none` method and send `client_id` in the form body; as with every
client, they receive active claims only for tokens belonging to themselves.

```bash
curl -u client_id:client_secret http://localhost:8080/introspect \
  -d token=eyJhbGciOi...
```

```json
{
  "active": true,
  "scope": "openid email",
  "client_id": "client_id",
  "username": "user_id",
  "token_type": "Bearer",
  "exp": 1750000000,
  "iat": 1749999100,
  "sub": "user_id",
  "aud": ["api.example"],
  "iss": "http://localhost:8080"
}
```

Inactive:

```json
{ "active": false }
```

**The caller is authorised against the token's own client.** A client
authenticated to this endpoint cannot introspect a token belonging to a
different client.

This is the only way to observe real-time revocation. A resource server that
verifies JWTs locally accepts a revoked access token for up to
`tokens.access_ttl` seconds.

---

## Logout

### `GET /logout`

RP-initiated logout. Browser navigation.

| Parameter | Notes |
|---|---|
| `id_token_hint` | A previously issued ID token. Signature is verified; expiry is **not**. |
| `post_logout_redirect_uri` | Honoured **only** when `id_token_hint` validly identifies the client |
| `state` | Echoed on a validated redirect only |

If the client cannot be unambiguously identified, `post_logout_redirect_uri` is
**ignored** and a confirmation page is rendered. This is deliberate: the allowed
list is per-client, so without a client there is nothing to validate against,
and honouring it would be an open redirect.

### `POST /logout`

Session-scoped. Requires a session cookie. No CSRF token (this is a direct API
call, not a form post from our pages).

Revokes only the tokens of the calling session. Other sessions on other devices
are unaffected.

Back-channel `LogoutToken`s are delivered to every attached client with a
registered `backchannel_logout_uri`, asynchronously, with bounded retry.

---

## User registration

### `POST /users/register`

Public. Rate limited to 3 per hour per IP.

```bash
curl -X POST http://localhost:8080/users/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"...","name":"User"}'
```

```json
{ "message": "Check your email to verify your account" }
```

**Always returns `201` with the same body**, whether or not the address was
already registered. An existing user receives a different notification email;
the caller learns nothing. Response time is equalised, because the register path
performs the same password hashing on both branches.

### `GET /users/verify-email?token=...`

Consumes the token atomically and marks the address verified. `/verify-email` is an
alias used in generated mail links.

---

## Password recovery

The account pages link to `GET /forgot-password` and render the one-time reset form
at `GET /reset-password?token=...`. Those GET routes are HTML pages; submissions
use the JSON machine endpoints below. The browser UI removes the reset token from
the address bar and does not persist it in browser storage.

### `POST /forgot-password`

Public JSON endpoint. Rate limited. The response is enumeration-safe and does not
depend on whether the email address exists:

```bash
curl -X POST http://localhost:8080/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com"}'
```

Returns `202 Accepted` with the same message for unknown and registered addresses.
A reset link is emailed only when an eligible account exists.

### `POST /reset-password`

Public JSON endpoint that redeems a one-time reset token, sets the new password,
and revokes the account's existing sessions and refresh tokens:

```bash
curl -X POST http://localhost:8080/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"token":"<one-time-token>","password":"a-new-long-password"}'
```

A successful reset returns `200`. An unknown, expired, used, or wrong-purpose
token returns `401` with `{"error":"invalid_token"}`; all unusable tokens have
the same response. The password must meet the configured minimum length.

This is account recovery, not the OAuth resource-owner password grant. The
`grant_type=password` flow remains unsupported.

---

## Dynamic client registration

### `POST /register`

**Disabled by default.** Returns `404` unless
`registration.client_registration_enabled` is `true`, and then requires an
initial access token.

```bash
curl -X POST http://localhost:8080/register \
  -H 'Authorization: Bearer <initial-access-token>' \
  -H 'Content-Type: application/json' \
  -d '{
        "client_name": "Example",
        "redirect_uris": ["https://client.example/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid email"
      }'
```

```json
{
  "client_id": "6f3c...",
  "client_secret": "Mz9v...",
  "client_id_issued_at": 1750000000,
  "client_secret_expires_at": 0,
  ...
}
```

`client_secret` is returned **once**. There is no retrieval endpoint for it.

`implicit` and `password` are rejected. `private_key_jwt` requires `jwks` or
`jwks_uri`. `redirect_uris` must be HTTPS, must not contain a fragment or a
userinfo component, and must be non-empty for the `authorization_code` grant.

---

## Admin

Both require an admin session. Both are audited.

### `DELETE /users/{id}`

Erasure. Revokes all tokens, deletes the user's records, and pseudonymises the
audit log. Back-channel logout tokens are built **before** the transaction and
delivered after it commits. Returns `204`.

### `POST /keys/rotate`

Forces a signing key rotation. The new key is published before it is used.

---

## Errors

Every error response is:

```json
{
  "error": "invalid_grant",
  "error_description": "authorization code has already been used",
  "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2"
}
```

### Codes

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Missing, repeated or malformed parameter |
| `invalid_client` | 401 | Client authentication failed |
| `invalid_token` | 401 | Bearer or one-time reset token is invalid |
| `invalid_grant` | 400 | Code, refresh token, or PKCE verification failed |
| `unauthorized_client` | 400 | Client is not permitted to use this grant type |
| `unsupported_grant_type` | 400 | `implicit`, `password`, or anything unknown |
| `unsupported_response_type` | 400 | Anything other than `code` |
| `invalid_scope` | 400 | Requested scope exceeds what the client may have |
| `invalid_request_uri` | 400 | PAR reference is unknown, expired, or already used |
| `access_denied` | 400 | The user denied consent |
| `login_required` | 400 | `prompt=none` and no session |
| `consent_required` | 400 | `prompt=none` and no consent |
| `interaction_required` | 400 | `prompt=none` and interaction is needed |
| `account_selection_required` | 400 | `prompt=none` with multiple accounts |
| `request_not_supported` | 400 | `request` parameter is not supported |
| `request_uri_not_supported` | 400 | `request_uri` parameter is not supported |
| `registration_not_supported` | 400 | Client registration is disabled |
| `server_error` | 500 | Unexpected failure |
| `temporarily_unavailable` | 503 | Dependency unavailable |

### Where errors are returned

| Endpoint | Form |
|---|---|
| `/authorize`, `/login`, `/mfa`, `/consent` | Query parameters on the validated `redirect_uri`, plus `state` and `iss` |
| `/token`, `/revoke`, `/introspect`, `/par`, `/register`, `/users/register`, `/forgot-password`, `/reset-password` | JSON body |
| Before `redirect_uri` is validated at `/authorize` | JSON body, because there is nowhere safe to redirect to |

`error_description` never contains a client secret, token, or anything that
would help an attacker. Login failures return the same generic message whether
or not the account exists.
