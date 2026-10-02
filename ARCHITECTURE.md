# Architecture

## Layering

```
                 ┌──────────────────────────────────────────┐
   browser ─────▶│ handlers      HTTP parsing, rendering    │
   client  ─────▶│ httpapi       router, respond, paramguard│
                 ├──────────────────────────────────────────┤
                 │ flows         grant logic, no HTTP       │
                 ├──────────────────────────────────────────┤
                 │ authn authz   credential + scope logic   │
                 │ sessions consent keys tokens clientauth  │
                 ├──────────────────────────────────────────┤
                 │ storage       repositories (pgx)         │
                 │ cache         Redis views                │
                 ├──────────────────────────────────────────┤
                 │ domain        entities, errors, scope    │
                 └──────────────────────────────────────────┘
                        oautherr (leaf, no internal imports)
                        crypto   (leaf, stdlib + argon2)
```

### Dependency rules

These are enforced by review, not by the compiler. They are the reason the tree
is shaped this way.

1. `handlers` may import `flows`, `httpapi`, `middleware`, `oautherr`, `domain`.
2. `flows` may import `storage`, `cache`, `domain`, `oautherr`, `tokens`, `keys`.
3. `flows` must **not** import `middleware` or `httpapi`.
4. `middleware` contains no business logic. It resolves a client address, checks
   a rate limit, loads a session, or renders an error. Nothing else.
5. `storage` and `cache` know nothing about HTTP.
6. `domain` has **no internal imports at all**. It cannot import `oautherr`,
   which is why `oautherr` depends on `domain` and not the reverse.
7. `tokens` → `keys` is one-directional. `keys` never imports `tokens`.

Rule 7 matters. Key lifecycle and JWT signing are both about cryptography, and
it is very easy to end up with `keys` calling a builder that itself needs a key.
Splitting them means `keys.Manager` can be tested in isolation and the JWKS
endpoint has exactly one source of truth.

## Invariants

These are the properties the design exists to guarantee. Each has a test.

### Single-use consumption is one statement

Every single-use row is consumed with a conditional `UPDATE ... RETURNING`:

```sql
UPDATE auth_codes SET used = TRUE, used_at = clock_timestamp()
WHERE code_hash = $1 AND used = FALSE AND expires_at > clock_timestamp()
  AND client_id = $2
RETURNING *;
```

Zero rows returned means unknown, already used, expired, or belonging to a
different client. A `SELECT` followed by an `UPDATE` is a time-of-check
time-of-use race, and two concurrent requests will both pass the check.

The predicate **must** carry `client_id` and `expires_at`. If the ownership
check happens after the mutation, any caller who obtains a code can destroy it
without ever being the legitimate client: the code is consumed, the real client
receives `invalid_grant`, and the attacker's own request is rejected, leaving no
trace. That is a repeatable denial of service against any client.

Applies to: `auth_codes`, `auth_requests`, `par_requests`, `email_verifications`,
`mfa_backup_codes`, `refresh_tokens` (rotation).

### Refresh token rotation distinguishes theft from a race

`revocation_reason` exists so that a replay can be told apart from an
administrative revocation:

- `rotated` — the token was already exchanged. Presenting it again is reuse,
  so the **entire family** is revoked.
- `logout`, `explicit`, `gdpr`, `admin` — the token was revoked deliberately.
  Presenting it again is expected, so **nothing** is cascaded.

Getting this backwards in either direction is bad: cascading on a logout logs
users out constantly, and not cascading on real theft leaves a stolen family
alive.

`rotated` is also **not sufficient** on its own. Benign concurrent refreshes are
routine (a browser tab waking, a retried request, two components fetching in
parallel). A family revocation fires on all of them and logs the user out
mid-session. A grace window returns the already-issued successor instead of
cascading; without it, `concurrent_consume_test.go` passes and production is a
support queue.

### Token families have an absolute ceiling

`token_families.absolute_expires_at` is separate from each token's idle expiry.
A client that rotates every 29 days would otherwise hold one session open
indefinitely. `sessions` has the same pair (`expires_at`, `absolute_expires_at`);
refresh families simply needed the same treatment one level down.

### Scope is represented once

`scope` is `TEXT[]` in **every** table. It becomes a space-delimited string only
at the HTTP boundary, in one place. Mixed representations mean two parsers, and
the failure is silent: the consent screen shows `openid email` while the issued
token contains something else.

### Grantable scopes are recomputed on every authorization

Not only at the consent screen. The auto-skip path, where existing consent
already covers the requested scopes, skips the consent UI entirely — and if the
`email_verified` check lives only in the consent handler, a user whose
verification was revoked keeps receiving the `email` scope forever.

### ID token claims are gated on the granted scope set

Not on the user's fields. A client without the `profile` scope must not receive
`name`, and a client without `email` must not receive `email` even when the
address is verified.

### Login performs identical work on a lookup miss

An unknown email returns a generic error, which is not sufficient. If the
handler returns before reaching the Argon2 verification, the response is roughly
100× faster and the whole user base is enumerable with one request per guess.
Argon2's cost **is** the mitigation. The handler must verify against a fixed
dummy hash, then add uniform jitter to absorb the residual difference.

The same applies to registration, where the insert-conflict path takes a
different route through the database than the insert-success path.

### Email addresses in the audit log are HMACs, not hashes

Audit records store `HMAC-SHA256(pepper, lower(email))`. A bare SHA-256 of an
email address is reversible from any rainbow table, so hashing it produces a
stable pseudonym that links every action of one person without pseudonymising
anything.

### The audit API cannot hold personal data

`audit.Event` is a struct, not `map[string]any`. Erasure can therefore be
*provably* complete, because the set of fields that might contain personal data
is closed and known.

Redacting arbitrary JSONB by removing keys is unsound: `details - 'email'`
removes a **top-level** key only, so `{"ctx":{"email":...}}` survives intact.
The fix belongs upstream, in the type that writes the row.

### Erasure pseudonymises, it does not delete

`users` uses `ON DELETE RESTRICT` almost everywhere. Nothing cascades a user's
tokens, sessions, consents or codes away silently. Erasure is an explicit
transaction in application code, in a defined order, and `RESTRICT` makes a
forgotten table **fail loudly** at boot or on first use rather than quietly
destroying the evidence trail.

`issued_access_tokens.user_id` is `ON DELETE SET NULL`: the token must remain
revocable after the user is gone.

### Forwarded headers require a trust list

`X-Forwarded-For` is ignored unless the immediate peer is inside
`server.trusted_proxies`. Trusting it unconditionally lets any caller forge
their address and bypass every IP-based rate limit.

## Why `auth_requests` exists

An authorization request has to survive a redirect chain: `/authorize` →
`/login` → `/mfa` → `/consent`. Parameters in the query string are fragile
across that chain. A pushed authorization request makes it worse, because the
`request_uri` is single-use: once consumed at `/authorize`, a refresh of the
login page finds nothing.

So the resolved, validated parameters are written to `auth_requests`, and every
later step addresses them by id. The full validated parameter set is held in
`ParamsJSON`, not in hand-picked columns, because every parameter that was
validated at `/authorize` and then dropped is a bug waiting to happen — `prompt`
and `max_age` in particular must survive to the login decision or `prompt=none`
becomes impossible to honour.

## Key rotation

```
day 0    generate K2, status=active, K1 -> retiring
         publish {K1, K2} in JWKS
         wait >= jwks cache lifetime + clock skew
day 0+ε  begin signing with K2
day 30   K1 retire_at = now + retention
day 30+h retire K1: remove from JWKS, destroy private half
```

Order matters. Signing with a key that no relying party has seen yet means every
RS with a cached JWKS rejects new tokens for up to the cache lifetime.
Retention must be derived as `max(access_ttl, id_token_ttl) + skew`, not
hardcoded, so that raising `access_ttl` cannot silently invalidate live tokens.

A retired key keeps its public half only as long as needed. The private half is
destroyed; the schema enforces this with a `CHECK`.

## Data model

```
clients ──┬──< auth_codes >── auth_requests
          ├──< refresh_tokens >── token_families >── users
          ├──< issued_access_tokens
          ├──< client_sessions >── sessions >── users
          ├──< par_requests
          └──< consents >── users

users ──┬──< sessions ──< client_sessions
        ├──< auth_codes
        ├──< refresh_tokens
        ├──< mfa_backup_codes
        ├──< email_verifications
        └──< consents

revoked_tokens        (standalone, keyed by jti, TTL-driven)
signing_keys          (standalone)
audit_log             (partitioned by created_at)
```

`auth_codes.session_id` and `auth_codes.sid` are denormalised from the session
precisely so that a token derived from a code can be traced back to the browser
session that authorised it. Without them, scoped logout cannot find anything to
revoke.

`sessions.amr` and `sessions.acr` record **how** the session was authenticated,
not just when. `auth_time` alone cannot prove that a user passed a second factor,
which is what a `LogoutToken`, an ID token `amr` claim, or a FAPI assurance query
needs.

## The 17 Security Fixes

Each fix exists because a specific attack was identified and a specific design
change stops it. They are numbered here for audit, but the implementation is
scattered across the codebase and documented where it matters.

1. **Email scope check at consent, not authorize** — scope eligibility is
   re-evaluated at the consent screen (see "Grantable scopes are recomputed on
   every authorization"), not only at `/authorize`. This prevents a revoked
   email verification from silently granting `email` on token refresh.
2. **MFA enrollment via session cookie** — TOTP enrolment requires an
   authenticated browser session. A recovered CSRF token cannot enroll a factor
   for another user.
3. **Refresh token reuse detection order** — reuse is detected with a single
   atomic `UPDATE ... RETURNING` whose predicate carries `revoked_at IS NULL`.
   A `SELECT` then `UPDATE` would allow two concurrent replays to both pass the
   check before either is marked.
4. **Tracking tables for logout** — `client_sessions` and
   `issued_access_tokens` link browser sessions to clients, so scoped logout
   can find every token that needs revoking.
5. **Auth code reuse cascade** — presenting a consumed authorization code
   revokes the entire token family it seeded, not just that one code.
6. **Session ID on auth_codes** — `auth_codes` stores `session_id` and `sid`
   so a server-to-server token exchange can be traced back to the browser
   session that authorised it, enabling scoped logout.
7. **auth_requests table** — validated authorization parameters survive the
   `/authorize` → `/login` → `/mfa` → `/consent` redirect chain and PAR
   reference URIs. Single-use `request_uri` would otherwise lose parameters
   on any refresh.
8. **"none" client auth method** — public clients authenticate with `client_id`
   only. Security rests on PKCE, not on a secret that can be forgotten.
9. **token_endpoint_auth_method column** — per-client method selection
   (`none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`) is
   a CHECK-constrained column, so a client registered for `none` cannot
   authenticate with a secret.
10. **Session-scoped logout (not global)** — `POST /logout` terminates only
    the calling session's tokens. Other sessions on the same account are
    unaffected.
11. **Atomic conditional UPDATE for reuse detection** — every single-use row
    (auth codes, auth requests, email verifications, MFA backup codes, refresh
    tokens) is consumed by a conditional `UPDATE ... RETURNING`, never by
    `SELECT` + `UPDATE`.
12. **Client ownership check before cascade** — revocation and introspection
    verify that the caller is authorised against the token's own client before
    any cascade fires. A client cannot touch another client's tokens.
13. **revocation_reason distinguishes rotation from logout** — `rotated`
    triggers family revocation; `logout`, `explicit`, `gdpr`, `admin` do not.
    This prevents cascading a benign logout across a family, and prevents
    ignoring a real theft.
14. **GDPR collects notification list before deletion** — back-channel logout
    targets are captured before the user row is removed, so delivery can still
    proceed after the user is erased.
15. **Access token revocation via introspection (documented trade-off)** —
    self-contained JWTs cannot be instantly withdrawn. `/introspect` is the
    documented mechanism; revocation latency is bounded by `tokens.access_ttl`.
    This is stated, not hidden.
16. **Rate limit per authenticated client (not unauthenticated client_id)** —
    `/token` and `/par` are limited per client identity, so a bot spinning
    `client_id`s cannot bypass per-client limits.
17. **Consent auto-skip, GET/POST logout, return URL validation, registration
    timing, audit anonymization** — consent auto-skip avoids the UI when
    existing grants cover the request; logout redirects are validated against
    a server-side allowlist (`security.allowed_internal_paths`); registration
    timing is equalized; audit actor fields are HMAC-pseudonymised.

## Request Flow Diagrams

### Authorization code flow

```
Browser          Server          Client
   |               |               |
   | GET /authorize  |               |
   |--------------->|               |
   |               | verify params  |
   |               | store auth_req |
   |<--------------| redirect to    |
   |  /login       | login          |
   |               |               |
   | POST /login   |               |
   | (session+cookie)             |
   |--------------->|               |
   |               | bind session   |
   |               | resume auth_req|
   |<--------------| redirect to    |
   |  /mfa         | consent        |
   |               |               |
   | POST /mfa     |               |
   |               | verify MFA     |
   |               | update auth_req|
   |<--------------| redirect to    |
   |  /consent     |                |
   |               |               |
   | POST /consent |               |
   |               | check scopes   |
   |               | create code    |
   |<--------------| redirect to    |
   |  /cb?code=..  | client_creds   |
   |               |               |
   |               | POST /token    |
   |               |<--------------|
   |               | exchange code  |
   |               | issue tokens   |
   |               |--------------->|
   |               |  access+refresh|
   |               |  + id_token    |
```

### Client credentials flow

```
Client          Server
   |               |
   | POST /token   |
   | client_creds  |
   |--------------->|
   |               | verify client|
   |               | issue tokens  |
   |<--------------|  access_token |
   |               |  (no user)    |
```

### Refresh flow

```
Client          Server
   |               |
   | POST /token   |
   | refresh_token |
   |--------------->|
   |               | lookup token |
   |               | family check |
   |               | atomic UPDATE|
   |               | (rotated?)   |
   |<--------------|  new access   |
   |               |  new refresh  |
   |               |  (rotated:   |
   |               |  family revoked)|
```

### Logout flow

```
Browser/Client    Server
   |                |
   | GET /logout   |
   | (id_token_hint)|
   |---------------->|
   |                | identify client|
   |                | validate redirect|
   |<----------------| confirm page |
   |                |                |
   | POST /logout  | (session cookie)|
   |---------------->|                |
   |                | revoke session |
   |                | tokens only    |
   |                | this session   |
   |                | build BCLT     |
   |                | deliver async  |
```

## Storage API deviations

The storage layer was built against a prompt that specified repository method
signatures. Six of them are implemented differently, deliberately. Each
difference exists because the prompt's version is either unsafe or throws away
information the caller needs, and the code is the specification of record. This
section exists so the divergence is recorded rather than discovered later by
someone reading the prompt and assuming the code is incomplete.

**`SigningKeyRepo.MarkRotating(kid, retireAt)` instead of `MarkRotated(kid)`.**
An immediate full retirement would pull a key out of the JWKS the moment it was
marked, invalidating every unexpired token it signed — including access tokens
with a 1 hour lifetime that a resource server may not have seen yet. The split
into retire-then-destroy exists so a retiring key keeps publishing until its
retention window closes, and only then loses its private half, which is what
makes a rollover non-disruptive. An `MarkRotated` alias would be a footgun that
skips that window.

**`AuditRepo.AnonymizeUser(...) (int, error)` instead of `error`.** The affected
row count is free to return and is the useful part during erasure: zero means
there was nothing to anonymise, which is a meaningfully different outcome from
"it worked". Callers that do not care ignore it. Reducing this to `error` would
delete information rather than add safety.

**`AuthRequestRepo.MarkCompleted(...) (bool, error)` and
`EmailVerificationRepo.MarkUsed(...) (bool, error)` instead of `error`.** These
are single-use transitions, so the caller needs to distinguish "this request
consumed it" from "someone already did". The boolean comes from the same
statement that performs the write, so the answer cannot go stale between the
check and the write. The prompt's `error` signature can only express this by
returning a sentinel value, which is a less direct way of saying the same thing.

**`UserRepo.UpdateMFA(...)` takes `secretEnc []byte`.** The prompt's `string`
would force a []byte → string → []byte round trip for a column that is `BYTEA`.
The secret is encrypted ciphertext, not text, and treating it as a string invites
the assumption that it is printable when it is not.

**`RevokedTokenRepo.AddBatch([]RevocationEntry)` instead of an anonymous struct.**
Structurally identical to the prompt. A named type carries a doc comment and can
be reused by the single-entry path, whereas an anonymous struct in a signature is
both undocumented and impossible to write twice without duplicating it.

`UserRepo.UpdateBackupCodes` *is* implemented, transactionally, and delegates to
the same code path as `MFARepo.ReplaceForUser`. It opens its own transaction
because the prompt's signature does not take one. The transaction is the reason
the method is worth having: a delete followed by a bulk insert across two
statements without one leaves the user with no working recovery codes at all the
moment enrolment appears to succeed.

## Trade-offs

**Revocation: `revoked_tokens` plus `issued_access_tokens`.** These overlap.
Keeping both means two writes per issued token. `issued_access_tokens` is a
record of what was issued, needed for audit and for reuse-cascade; `revoked_tokens`
is the deny list. `revoked_tokens` is mirrored into Redis so that a resource
server check is not a database round-trip on every API call. Redis outage
behaviour is explicit and fails closed by default.

**Introspection authorises the caller.** Any authenticated client is refused
introspection of a token belonging to a different client. Without this check,
every confidential client in the system can harvest subject identifiers and
scopes for users it has no relationship with.

**Logout is not instant for self-contained tokens.** A JWT verified offline
cannot be withdrawn. The guarantee is "within `tokens.access_ttl` seconds",
optionally improved by a Redis `sid → revoked` set that resource servers check.
This is stated rather than implied, because a `logout` handler that appears
instant is a lie the README should not tell.

**Client secrets use SHA-256, passwords use Argon2id.** A client secret is 256
bits of CSPRNG output. Argon2 at 100ms per `/token` call, for a value that has
no guessing resistance to protect, is a self-inflicted CPU exhaustion problem
reachable by anyone holding a public `client_id`. The same reasoning applies to
MFA backup codes.

**Hand-rolled wiring instead of a DI framework.** With 17 repositories and 20
handlers, `wire` or `fx` would remove boilerplate at the cost of making the
graph invisible and untestable by reading. A hand-written constructor graph in
`internal/app` is greppable and has no reflection.

**PostgreSQL partitions the audit log.** It is the largest table in the system
and will bloat. Retention is `DROP PARTITION`, not `DELETE`.

## Threat model

### In scope

- Credential stuffing and password spraying
- Authorization code interception and replay
- Refresh token theft and replay
- Open redirect through `redirect_uri` or `post_logout_redirect_uri`
- CSRF against login, consent and MFA
- Session fixation and session hijacking via cookie
- Account enumeration through registration, login, or password reset
- MFA code replay inside the validity window
- Signing key compromise and rotation gaps
- Privileged escalation through client registration or admin endpoints
- PII retention after erasure

### Explicitly out of scope

- Denial of service at volumetric scale. Rate limiting exists, but there is no
  proof-of-work or CAPTCHA.
- Side-channel attacks on the host.
- Physical access to the host.
- A malicious database administrator.
- Coercion of the operator.

### Controls summary

| Threat | Control |
|---|---|
| Account enumeration | Generic response body, equal-work dummy hash verification, uniform jitter, per-account rate limit |
| Code interception | PKCE S256 mandatory, 256-bit codes, 10-minute TTL, exact `redirect_uri` match |
| Code replay | Atomic single-use consumption, reuse detection cascades to the family |
| Refresh theft | Rotation with family reuse detection and a grace window for benign races |
| Open redirect | Exact string matching only; post-logout redirect honoured only with a validated `id_token_hint` |
| CSRF | Per-flow CSRF token, `SameSite=Lax`, `__Host-` cookie prefix, positive route allowlist |
| Session fixation | New session identifier on every authentication, 32 CSPRNG bytes |
| MFA replay | Persisted counter, monotonicity enforced atomically with verification |
| Signing key theft | Private half encrypted at rest, destroyed on retirement, rotation overlap |
| Client registration abuse | Disabled by default; initial access token when enabled |
| Introspection abuse | Caller authorised against the token's own client |
| PII retention | Typed audit events, `RESTRICT` delete policy, pseudonymisation on erasure |

## Not implemented

- DPoP (RFC 9449) and mTLS-bound tokens (RFC 8705)
- FAPI 2.0 Security Profile
- Pairwise subject identifiers
- WebAuthn / passkeys
- Dynamic client management (RFC 7592)
- Introspection of opaque tokens for resource servers
- Durable back-channel logout delivery