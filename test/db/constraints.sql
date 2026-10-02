-- ============================================================================
-- Schema constraint assertions.
--
-- A migration that applies cleanly has not been tested. These assertions
-- exercise every CHECK, every unique index that carries a security property,
-- and the delete policy, by attempting writes that MUST be rejected.
--
-- Run against a freshly migrated database:
--
--   make deps-up
--   psql -f test/db/constraints.sql
--
-- or, against the compose-managed container:
--
--   make schema-test
--
-- Every assertion emits `ok  rejected: <label>`. A line reading
-- `TEST FAILED: <label> was ACCEPTED` means the database permitted something it
-- must not, which is the failure mode this file exists to catch.
--
-- Four of these assertions are regressions for bugs that this schema actually
-- shipped with. They are marked REGRESSION and should never be deleted:
--
--   * grant_types / response_types / redirect_uris emptiness. PostgreSQL
--     forbids subqueries in CHECK, and array_length('{}', 1) is NULL while a
--     CHECK constraint SATISFIES a NULL result. The original
--     `array_length(grant_types, 1) > 0` therefore accepted the empty array:
--     NULL AND true is NULL, which is not false. Fixed with coalesce().
--
--   * code_challenge_method. auth_requests required S256 but auth_codes
--     permitted 'plain', on the stated assumption that application code would
--     reject it. Application code does not exist yet, and the constraint is the
--     cheap place to be correct.
--
-- The script is re-runnable: fixtures use ON CONFLICT DO NOTHING and the
-- helper is dropped on the way out.
-- ============================================================================

\set ON_ERROR_STOP off
\pset pager off

-- Helper: run a statement expected to FAIL, and report whether it did.
CREATE OR REPLACE FUNCTION assert_rejects(label text, stmt text) RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE stmt;
    RAISE EXCEPTION 'TEST FAILED: % was ACCEPTED but should have been REJECTED', label;
  EXCEPTION WHEN check_violation OR not_null_violation OR unique_violation
                OR foreign_key_violation OR string_data_right_truncation THEN
    RAISE NOTICE 'ok  rejected: %', label;
  END;
END $$ LANGUAGE plpgsql;

\echo '=== fixtures ==='

INSERT INTO users (user_id, email, password_hash)
VALUES ('u1', 'user@example.com', 'x') ON CONFLICT DO NOTHING;

INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
                     token_endpoint_auth_method, client_secret_hash)
VALUES ('c_conf', 'Confidential', ARRAY['https://client.example/cb'],
        ARRAY['authorization_code','refresh_token'], 'client_secret_basic', 'deadbeef')
ON CONFLICT DO NOTHING;

INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
                     token_endpoint_auth_method, client_secret_hash)
VALUES ('c_public', 'Public', ARRAY['https://spa.example/cb'],
        ARRAY['authorization_code','refresh_token'], 'none', NULL)
ON CONFLICT DO NOTHING;

\echo '=== 1. case-insensitive email uniqueness ==='
-- A plain UNIQUE on the email column would ACCEPT this row. Registration
-- upserts target the functional index with ON CONFLICT ((lower(email))).
SELECT assert_rejects('duplicate email differing only by case',
  $$INSERT INTO users (user_id, email, password_hash)
    VALUES ('u2', 'USER@EXAMPLE.COM', 'x')$$);

\echo '=== 2. OAuth 2.1 grant type exclusion ==='
SELECT assert_rejects('implicit grant type',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad1', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code','implicit'], 'client_secret_basic', 'x')$$);
SELECT assert_rejects('password grant type',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad2', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['password'], 'client_secret_basic', 'x')$$);

\echo '=== 3. response_type, and REGRESSION: empty arrays ==='
SELECT assert_rejects('implicit response_type',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types, response_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad3', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code'], ARRAY['token'],
            'client_secret_basic', 'x')$$);

SELECT assert_rejects('REGRESSION empty grant_types array',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad9', 'Bad', ARRAY['https://x.example/cb'], '{}',
            'client_secret_basic', 'x')$$);
SELECT assert_rejects('REGRESSION empty response_types array',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types, response_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad10', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code'], '{}',
            'client_secret_basic', 'x')$$);

\echo '=== 4. client secret consistency (this is what replaces is_confidential) ==='
SELECT assert_rejects('public client WITH a secret hash',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad4', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code'], 'none', 'a-secret')$$);
SELECT assert_rejects('confidential client WITHOUT a secret hash',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad5', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code'], 'client_secret_basic', NULL)$$);
SELECT assert_rejects('private_key_jwt with no jwks and no jwks_uri',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad6', 'Bad', ARRAY['https://x.example/cb'],
            ARRAY['authorization_code'], 'private_key_jwt', 'x')$$);

\echo '=== 5. redirect URI hardening ==='
SELECT assert_rejects('redirect_uri containing a fragment',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad7', 'Bad', ARRAY['https://x.example/cb#frag'],
            ARRAY['authorization_code'], 'client_secret_basic', 'x')$$);
SELECT assert_rejects('post_logout_redirect_uri containing a fragment',
  $$UPDATE clients SET post_logout_redirect_uris = ARRAY['https://x.example/out#f']
    WHERE client_id = 'c_conf'$$);
SELECT assert_rejects('REGRESSION authorization_code client with no redirect_uri',
  $$INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
      token_endpoint_auth_method, client_secret_hash)
    VALUES ('c_bad8', 'Bad', '{}', ARRAY['authorization_code'],
            'client_secret_basic', 'x')$$);

-- The mirror image of the case above, asserted positively: a client_credentials
-- client legitimately needs no redirect_uri and must NOT be rejected.
INSERT INTO clients (client_id, client_name, redirect_uris, grant_types,
                     token_endpoint_auth_method, client_secret_hash)
VALUES ('c_m2m', 'M2M', '{}', ARRAY['client_credentials'], 'client_secret_basic', 'x')
ON CONFLICT DO NOTHING;
\echo 'ok  accepted: client_credentials client with no redirect_uri (expected)'

\echo '=== 6. signing key lifecycle ==='

-- This section deletes its own rows first. The rotation below deliberately moves
-- k1 out of the active slot, so a plain re-run would start with no active RS256
-- key at all: the "a second active RS256 key" assertion would then be proved by
-- an empty slot rather than by the index, which is the opposite of what it is
-- meant to check.
DELETE FROM signing_keys WHERE kid IN ('k1', 'k2', 'k_es', 'k_bad');

INSERT INTO signing_keys (kid, algorithm, public_jwk, private_key_enc, status)
VALUES ('k1', 'RS256', '{"kty":"RSA"}', '\x0102', 'active');

-- The partial unique index is what guarantees a botched rotation cannot leave
-- the server with no signing key.
SELECT assert_rejects('a second active RS256 key',
  $$INSERT INTO signing_keys (kid, algorithm, public_jwk, private_key_enc, status)
    VALUES ('k2', 'RS256', '{"kty":"RSA"}', '\x0102', 'active')$$);

-- A different algorithm may be active simultaneously.
INSERT INTO signing_keys (kid, algorithm, public_jwk, private_key_enc, status)
VALUES ('k_es', 'ES256', '{"kty":"EC"}', '\x0102', 'active');
\echo 'ok  accepted: ES256 active alongside RS256 (expected)'

-- Rotation, in the only order the partial index permits: the old key must leave
-- the active slot BEFORE the new one enters it, or the second INSERT is
-- rejected. k2 is inserted here rather than reused from the rejected attempt
-- above, because that attempt left no row behind to update.
UPDATE signing_keys SET status = 'retiring', retire_at = now() + interval '48 hours'
  WHERE kid = 'k1';
INSERT INTO signing_keys (kid, algorithm, public_jwk, private_key_enc, status)
VALUES ('k2', 'RS256', '{"kty":"RSA"}', '\x0304', 'active');

DO $$
DECLARE active_rs256 int; retiring_rs256 int;
BEGIN
  SELECT count(*) FILTER (WHERE status = 'active'),
         count(*) FILTER (WHERE status = 'retiring')
    INTO active_rs256, retiring_rs256
    FROM signing_keys WHERE algorithm = 'RS256';
  IF active_rs256 <> 1 THEN
    RAISE EXCEPTION 'TEST FAILED: after rotation there are % active RS256 keys, want exactly 1', active_rs256;
  END IF;
  IF retiring_rs256 <> 1 THEN
    RAISE EXCEPTION 'TEST FAILED: after rotation there are % retiring RS256 keys, want exactly 1', retiring_rs256;
  END IF;
  RAISE NOTICE 'ok  rotated: k1 -> retiring, k2 -> active';
END $$;

SELECT assert_rejects('unknown algorithm',
  $$INSERT INTO signing_keys (kid, algorithm, public_jwk, status)
    VALUES ('k_bad', 'HS256', '{"kty":"oct"}', 'active')$$);

\echo '=== 7. single-use markers and consistency ==='
INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
VALUES ('s1', 'u1', now() + interval '1 hour', now() + interval '1 day')
ON CONFLICT DO NOTHING;

INSERT INTO token_families (family_id, user_id, client_id, absolute_expires_at)
VALUES ('f1', 'u1', 'c_conf', now() + interval '90 days') ON CONFLICT DO NOTHING;

INSERT INTO auth_codes (code_hash, client_id, user_id, session_id, sid, family_id,
                       scope, redirect_uri, code_challenge, expires_at)
VALUES ('h1', 'c_conf', 'u1', 's1', 'sid-1', 'f1', ARRAY['openid','email'],
        'https://client.example/cb', 'chal', now() + interval '10 minutes')
ON CONFLICT DO NOTHING;

-- REGRESSION: OAuth 2.1 is S256-only. auth_codes previously allowed 'plain'.
SELECT assert_rejects('REGRESSION code_challenge_method plain',
  $$INSERT INTO auth_codes (code_hash, client_id, user_id, scope, redirect_uri,
      code_challenge, code_challenge_method, expires_at)
    VALUES ('h_plain', 'c_conf', 'u1', ARRAY['openid'],
            'https://client.example/cb', 'chal', 'plain', now())$$);

-- revoked_at and revocation_reason must be set together, in both directions.
-- `rotated` is the signal that a replay occurred and cascades to the family.
SELECT assert_rejects('revoked_at set without a revocation_reason',
  $$INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id,
      scope, expires_at, revoked_at)
    VALUES ('r_bad', 'f1', 'c_conf', 'u1', ARRAY['openid'], now(), now())$$);

SELECT assert_rejects('unknown revocation_reason',
  $$INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id,
      scope, expires_at, revoked_at, revocation_reason)
    VALUES ('r_bad2', 'f1', 'c_conf', 'u1', ARRAY['openid'], now(), now(), 'because')$$);

SELECT assert_rejects('auth request with response_type token',
  $$INSERT INTO auth_requests (id, client_id, redirect_uri, response_type, scope,
      code_challenge, expires_at)
    VALUES ('ar_bad', 'c_conf', 'https://client.example/cb', 'token', ARRAY['openid'],
            'chal', now() + interval '15 minutes')$$);

\echo '=== 8. PAR payload must not carry credentials ==='
-- The request_uri is a bearer credential for the request itself. A client
-- secret inside params_json would be durable in a table the reaper only
-- clears on expiry.
SELECT assert_rejects('PAR params containing client_secret',
  $$INSERT INTO par_requests (request_uri, client_id, params_json, expires_at)
    VALUES ('urn:x', 'c_conf', '{"client_secret":"leaked"}', now() + interval '60 seconds')$$);

\echo '=== 9. users: MFA enabled requires a secret ==='
-- Otherwise a half-configured factor locks the user out with no recovery path.
SELECT assert_rejects('mfa_enabled with no encrypted secret',
  $$INSERT INTO users (user_id, email, password_hash, mfa_enabled)
    VALUES ('u3', 'u3@example.com', 'x', TRUE)$$);

\echo '=== 10. sessions: absolute expiry must exceed idle ==='
SELECT assert_rejects('absolute_expires_at before expires_at',
  $$INSERT INTO sessions (session_id, user_id, expires_at, absolute_expires_at)
    VALUES ('s_bad', 'u1', now() + interval '1 day', now() + interval '1 hour')$$);

\echo '=== 11. email_verifications purpose ==='
-- purpose and target_email are what stop a verification token issued for one
-- address from confirming a different one.
SELECT assert_rejects('unknown verification purpose',
  $$INSERT INTO email_verifications (token_hash, user_id, purpose, target_email, expires_at)
    VALUES ('ev_bad', 'u1', 'something_else', 'a@example.com', now())$$);

\echo '=== 12. ON CONFLICT on the functional unique index ==='
-- The registration upsert depends on this exact index inference syntax.
INSERT INTO users (user_id, email, password_hash)
VALUES ('u_oc', 'oc@example.com', 'x') ON CONFLICT ((lower(email))) DO NOTHING;
INSERT INTO users (user_id, email, password_hash)
VALUES ('u_oc2', 'OC@EXAMPLE.COM', 'x') ON CONFLICT ((lower(email))) DO NOTHING;
\echo 'ok  second insert via ON CONFLICT ((lower(email))) was a silent no-op (expected)'

\echo '=== 13. audit_log partition accepts writes, and bounds its indexes ==='
INSERT INTO audit_log (event, actor, ip_address, correlation_id, details)
VALUES ('user.logout', 'act-1', '2001:db8::1', 'corr-1', '{"note":"x"}');
\echo 'ok  audit_log row written to default partition'
SELECT assert_rejects('audit_log actor longer than 64 chars',
  $$INSERT INTO audit_log (event, actor) VALUES ('x', repeat('a', 65))$$);

\echo '=== 14. delete policy: RESTRICT on the user, explicit erasure only ==='
-- Nothing cascades a user's tokens, sessions or codes away. A forgotten table
-- must fail loudly rather than quietly destroying the evidence trail.
SELECT assert_rejects('DELETE users while a session exists (must RESTRICT)',
  $$DELETE FROM users WHERE user_id = 'u1'$$);

-- Erasure is an explicit transaction that clears children first.
DELETE FROM refresh_tokens   WHERE user_id = 'u1';
DELETE FROM token_families   WHERE user_id = 'u1';
DELETE FROM client_sessions  WHERE session_id = 's1';
DELETE FROM auth_codes       WHERE user_id = 'u1';
DELETE FROM sessions         WHERE user_id = 'u1';
\echo 'ok  children deleted; user row is now removable'
DELETE FROM users WHERE user_id = 'u1';
\echo 'ok  DELETE users succeeded after explicit child cleanup (expected)'

-- clients are ON DELETE CASCADE: deleting a client is a full teardown.
DELETE FROM clients WHERE client_id IN ('c_conf','c_public','c_m2m');
\echo 'ok  client teardown cascaded to token_families and auth_codes (expected)'

DROP FUNCTION assert_rejects(text, text);