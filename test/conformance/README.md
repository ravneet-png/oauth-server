# OpenID Foundation Conformance Suite

This directory holds the configuration and notes for running the OpenID
Foundation conformance suite against this server.

**The conformance suite is the acceptance test for an authorization server.**
Unit tests and integration tests prove that the code does what the code says it
does. They do not prove that the implementation satisfies the specification. The
suite does.

**Status: not run. Not certified.** See the Security status section of the
top-level `README.md`.

## Running

The suite is a Docker Compose stack; it drives a real browser or an HTTP client
against a live instance of the server.

```bash
# 1. Start the server under test on a host the suite can reach.
make deps-up
make migrate-up
OAUTH_SERVER_ISSUER=https://localhost:8443 make run

# 2. Start the suite.
cd third_party/oidc-conformance-suite
docker compose up
```

The suite UI is then available on the published port, and the server's
discovery document must be reachable from inside the suite's network.

## Required configuration

| Setting | Value | Reason |
|---|---|---|
| `server.issuer` | `https://` URL reachable from the suite | The suite verifies every `iss` against this value |
| `server.trusted_proxies` | suite container network | Otherwise `X-Forwarded-For` is ignored and client address assertions fail |
| `keys.retention_hours` | greater than `access_ttl` plus skew | A JWKS cached by the suite must remain valid across rotation |
| `rate_limit.enabled` | may be disabled for the run only | Suite bursts would otherwise trip the limits and produce confusing failures |
| `registration.client_registration_enabled` | enabled if testing RFC 7591 | Off by default |
| PKCE | S256 only | The suite tests `plain` rejection separately; a server accepting `plain` fails OP |

## Plans to run

| Plan | Covers |
|---|---|
| `basic` | Discovery, registration, authorization code, ID token, userinfo, logout |
| `response-type-code` | Authorization code specifics |
| `id-token` | Claim construction, `at_hash`, `c_hash`, `s_hash`, `auth_time`, `amr`, `acr` |
| `refresh-token` | Rotation, `offline_access` gating, scope narrowing |
| `client-credentials` | Machine grant |
| `pkce` | S256 enforcement, `plain` rejection |
| `token-introspection` | RFC 7662 |
| `token-revocation` | RFC 7009 |
| `par` | RFC 9126, including single-use enforcement |
| `rp-initiated-logout` | `id_token_hint`, `post_logout_redirect_uri` |
| `backchannel-logout` | `LogoutToken`, the `events` claim, `sid` correlation |

## Known expected failures

These are places where the current implementation is known not to satisfy the
suite. They are tracked rather than papered over.

| Area | Expectation |
|---|---|
| Dynamic client registration | Endpoint is disabled by default; enable explicitly for the run |
| `request` and `request_uri` parameters | JAR support is not implemented, so `request_not_supported` must be returned |
| Pairwise subjects | `subject_types_supported` is `public` only |
| `claims` parameter | Parameter-level claim selection is not implemented |
| `acr_values` | No assurance levels beyond the default are configured |
| Session management | OIDC Session Management is not implemented |
| `userinfo` at `id_token` endpoint | `claims_in_idtoken` unsupported |
| Front-channel logout | Not implemented |

## Recording results

Store the suite output alongside this file as `results/<date>-<plan>.json` and
note the overall verdict. A failing suite is not a blocker for development; a
suite that is never run is a blocker for production.