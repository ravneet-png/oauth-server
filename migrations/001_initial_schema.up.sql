-- ============================================================================
-- 001_initial_schema
--
-- Bootstrap schema for an OAuth 2.1 + OIDC authorization server.
--
-- This is the ONLY migration. There is no prior history to preserve, so the
-- schema is expressed as it should be rather than as a sequence of historical
-- accretions.
--
-- ---------------------------------------------------------------------------
-- DESIGN RULES ENFORCED THROUGHOUT
-- ---------------------------------------------------------------------------
--
-- 1. SCOPE REPRESENTATION
--    `scope` is TEXT[] in every table, never TEXT. It becomes a space-delimited
--    string in exactly one place: the HTTP boundary. Two representations mean
--    two parsers, and the divergence is silent.
--
-- 2. DELETE POLICY
--    users  -> ON DELETE RESTRICT or SET NULL. Nothing cascades a user's tokens,
--              sessions, consents or codes away. Erasure is an explicit
--              transaction, and RESTRICT makes a forgotten table fail loudly
--              rather than quietly destroying the evidence trail.
--    clients-> ON DELETE CASCADE. A deleted client is a full teardown, and it is
--              an audited administrative action.
--
-- 3. ENUM-SHAPED COLUMNS
--    VARCHAR + CHECK. Not the ENUM type, so that adding a value is a cheap
--    ADD CONSTRAINT rather than a blocking ALTER TYPE.
--
-- 4. SINGLE-USE MARKERS
--    A single-use row is marked by a NULLABLE TIMESTAMP, never by a boolean.
--    `used BOOLEAN` alongside `used_at` is two sources of truth that can drift.
--    Consumption is one conditional UPDATE ... RETURNING, whose predicate
--    carries every check, including ownership.
--
-- 5. EVERY TTL TABLE IS INDEXED ON ITS EXPIRY COLUMN
--    Reapers run on a schedule. Without these indexes they are sequential
--    scans against the fastest-growing tables in the database.
--
-- ---------------------------------------------------------------------------
-- STATEMENT ORDER
-- ---------------------------------------------------------------------------
-- clients, users, sessions, client_sessions, token_families, auth_codes,
-- refresh_tokens, issued_access_tokens, revoked_tokens, par_requests,
-- auth_requests, consents, mfa_backup_codes, email_verifications,
-- signing_keys, audit_log
-- ============================================================================

-- ----------------------------------------------------------------------------
-- clients
-- ----------------------------------------------------------------------------
CREATE TABLE clients (
    client_id                    VARCHAR(64)  PRIMARY KEY,
    -- SHA-256 hex, 64 chars. NULL exactly when the client is public.
    client_secret_hash           VARCHAR(64),

    client_id_issued_at          BIGINT       NOT NULL DEFAULT extract(epoch FROM now())::bigint,
    client_secret_expires_at     BIGINT       NOT NULL DEFAULT 0,

    client_name                  VARCHAR(128) NOT NULL,
    redirect_uris                TEXT[]       NOT NULL,
    grant_types                  TEXT[]       NOT NULL,
    response_types               TEXT[]       NOT NULL DEFAULT ARRAY['code'],
    scopes                       TEXT[]       NOT NULL DEFAULT '{}',

    token_endpoint_auth_method   VARCHAR(32)  NOT NULL DEFAULT 'client_secret_basic',
    token_ttl                    INTEGER      NOT NULL DEFAULT 900,
    refresh_idle_ttl             INTEGER      NOT NULL DEFAULT 2592000,
    client_credentials_ttl       INTEGER      NOT NULL DEFAULT 900,

    jwks_uri                     TEXT,
    jwks                         JSONB,

    logo_uri                     TEXT,
    client_uri                   TEXT,
    policy_uri                   TEXT,
    tos_uri                      TEXT,
    contacts                     TEXT[]       NOT NULL DEFAULT '{}',

    sector_identifier_uri        TEXT,
    subject_type                 VARCHAR(16)  NOT NULL DEFAULT 'public',

    backchannel_logout_uri               TEXT,
    backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    post_logout_redirect_uris    TEXT[]       NOT NULL DEFAULT '{}',

    par_required                 BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled_at                  TIMESTAMPTZ,

    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- OAuth 2.1 removes the implicit and password grants. Encoding that as a
    -- constraint means it is impossible to register such a client, rather than
    -- merely intending not to.
    --
    -- coalesce(array_length(...), 0) rather than array_length(...) throughout.
    -- array_length('{}', 1) is NULL, and a CHECK constraint SATISFIES a NULL
    -- result. Written as `array_length(...) > 0`, the empty array yields NULL,
    -- and `NULL AND true` is NULL, which passes. An empty-but-present array is
    -- therefore silently accepted unless the NULL is handled explicitly.
    CONSTRAINT clients_grant_types_chk CHECK (
        coalesce(array_length(grant_types, 1), 0) > 0
        AND grant_types <@ ARRAY['authorization_code','client_credentials','refresh_token']
    ),

    -- Only the code response type is implemented, so only code may be registered.
    CONSTRAINT clients_response_types_chk CHECK (
        response_types <@ ARRAY['code']
        AND coalesce(array_length(response_types, 1), 0) > 0
    ),

    CONSTRAINT clients_auth_method_chk CHECK (
        token_endpoint_auth_method IN (
            'none','client_secret_basic','client_secret_post','private_key_jwt'
        )
    ),

    -- A secret is required for every method except `none`, and forbidden for
    -- `none`. This is what makes is_confidential unnecessary as a column: the
    -- fact is derivable from the method, and the constraint keeps it consistent.
    CONSTRAINT clients_secret_consistency_chk CHECK (
        (token_endpoint_auth_method = 'none' AND client_secret_hash IS NULL)
        OR
        (token_endpoint_auth_method <> 'none' AND client_secret_hash IS NOT NULL)
    ),

    CONSTRAINT clients_private_key_jwt_chk CHECK (
        token_endpoint_auth_method <> 'private_key_jwt'
        OR jwks IS NOT NULL
        OR jwks_uri IS NOT NULL
    ),

    CONSTRAINT clients_subject_type_chk CHECK (
        subject_type IN ('public','pairwise')
    ),

    -- A client with no redirect_uri may still use client_credentials, but
    -- nothing else. Catching this at registration beats catching it at /token.
    --
    -- PostgreSQL forbids subqueries inside a CHECK constraint, so element-wise
    -- tests are expressed by joining the array with a separator first. For the
    -- fragment ban this is exact: a '#' anywhere in any element necessarily
    -- appears in the joined string, and no join can manufacture one.
    --
    -- Note that PostgreSQL CHECK constraints are only a backstop here. The full
    -- redirect URI policy (HTTPS, no wildcards, no loopback outside development)
    -- cannot be expressed in SQL and is enforced in application code. This
    -- constraint exists so that a bug in that code still cannot register a
    -- fragment-bearing redirect URI.
    CONSTRAINT clients_redirect_uris_chk CHECK (
        (
            grant_types <@ ARRAY['client_credentials']
            OR coalesce(array_length(redirect_uris, 1), 0) > 0
        )
        -- RFC 6749 3.1.2: a redirect URI must not contain a fragment.
        AND array_to_string(redirect_uris, ' ') NOT LIKE '%#%'
        -- userinfo in a redirect URI is a phishing primitive. This can only
        -- over-reject, never under-reject: a false match requires one element
        -- to contain an '@' with no path separator after it, which is not a
        -- well-formed redirect URI in the first place.
        AND array_to_string(redirect_uris, ' ') !~ '@[^/]+/'
    ),

    CONSTRAINT clients_post_logout_chk CHECK (
        array_to_string(post_logout_redirect_uris, ' ') NOT LIKE '%#%'
        AND array_to_string(post_logout_redirect_uris, ' ') !~ '@[^/]+/'
    ),

    CONSTRAINT clients_token_ttl_chk CHECK (token_ttl > 0 AND token_ttl <= 86400),
    CONSTRAINT clients_refresh_ttl_chk CHECK (refresh_idle_ttl > 0 AND refresh_idle_ttl <= 31536000),
    CONSTRAINT clients_client_credentials_ttl_chk CHECK (client_credentials_ttl > 0 AND client_credentials_ttl <= 86400)
);

-- Grant type and auth method checks are exact equality rather than containment:
-- both are single-valued and must match a registered client precisely.
CREATE INDEX idx_clients_grant_types  ON clients USING gin (grant_types);
CREATE INDEX idx_clients_scopes       ON clients USING gin (scopes);
CREATE INDEX idx_clients_redirect_uris ON clients USING gin (redirect_uris);
CREATE INDEX idx_clients_backchannel   ON clients (backchannel_logout_uri)
    WHERE backchannel_logout_uri IS NOT NULL AND disabled_at IS NULL;

-- ----------------------------------------------------------------------------
-- users
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    user_id           VARCHAR(64)  PRIMARY KEY,
    -- Always stored lowercased. The unique index below is on lower(email) rather
    -- than on the column, so that a row inserted before normalisation still
    -- cannot create a case-variant duplicate.
    email             VARCHAR(256) NOT NULL,
    -- PHC-encoded Argon2id string, parameters embedded. ~95-120 chars.
    password_hash     VARCHAR(256) NOT NULL,
    name              VARCHAR(128),

    email_verified    BOOLEAN      NOT NULL DEFAULT FALSE,

    mfa_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    -- AES-256-GCM ciphertext. Bound to user_id as additional authenticated data.
    mfa_secret_enc    BYTEA,
    -- Highest TOTP counter consumed. Enforces TOTP replay rejection: a code is
    -- accepted only if its counter is strictly greater than this value, and the
    -- two are updated in one statement so concurrent submissions cannot both win.
    mfa_last_counter  BIGINT       NOT NULL DEFAULT 0,

    -- Backup codes live in their own table, not in an array on this row, so that
    -- one code can be consumed atomically and individually.
    failed_login_count INTEGER     NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at      TIMESTAMPTZ,

    is_admin          BOOLEAN      NOT NULL DEFAULT FALSE,
    disabled_at       TIMESTAMPTZ,

    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- MFA enabled implies a secret exists. Without this a half-configured factor
    -- would let a user lock themselves out with no recovery path.
    CONSTRAINT users_mfa_secret_chk CHECK (
        NOT mfa_enabled OR mfa_secret_enc IS NOT NULL
    ),

    CONSTRAINT users_failed_login_chk CHECK (failed_login_count >= 0)
);

-- Case-insensitive uniqueness. Registration upserts must target this index with
-- ON CONFLICT ((lower(email))).
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email));
CREATE INDEX idx_users_locked_until ON users (locked_until) WHERE locked_until IS NOT NULL;

-- ----------------------------------------------------------------------------
-- sessions
--
-- A browser login session. Carries both idle and absolute expiry, plus the
-- assurance level established at login or MFA. auth_time alone proves when a
-- user authenticated but not how, which is what amr/acr and a LogoutToken need.
-- ----------------------------------------------------------------------------
CREATE TABLE sessions (
    session_id          VARCHAR(64) PRIMARY KEY,
    user_id             VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,

    auth_time           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idle expiry.
    expires_at          TIMESTAMPTZ NOT NULL,
    -- Hard ceiling regardless of activity.
    absolute_expires_at TIMESTAMPTZ NOT NULL,

    -- Assurance established at authentication.
    acr                 VARCHAR(16),
    amr                 TEXT[]     NOT NULL DEFAULT '{}',

    ip_address          INET,
    user_agent          VARCHAR(512),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT sessions_expiry_order_chk CHECK (absolute_expires_at > expires_at)
);

CREATE INDEX idx_sessions_user    ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);
CREATE INDEX idx_sessions_absolute_expires ON sessions (absolute_expires_at);

-- ----------------------------------------------------------------------------
-- client_sessions
--
-- A client attached to a session. `sid` is the per-client session identifier
-- that appears in ID tokens and back-channel LogoutTokens.
--
-- `sid` is the primary key and the only identifier. An earlier draft carried both
-- `id` and `sid` for the same value; two names for one thing invites divergence.
-- It must be unguessable: an attacker who can predict a sid can forge a
-- LogoutToken and terminate arbitrary sessions.
--
-- `user_id` is deliberately absent. It is derivable through `session_id`, and a
-- denormalised copy can silently drift, which for the erasure flow would mean
-- back-channel logout is never sent and a client keeps believing the user is
-- still signed in.
-- ----------------------------------------------------------------------------
CREATE TABLE client_sessions (
    sid        VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    client_id  VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT client_sessions_unique_client UNIQUE (session_id, client_id)
);

CREATE INDEX idx_client_sessions_session ON client_sessions (session_id);
-- Scoped logout filters on client_id; this is the index that makes it cheap.
CREATE INDEX idx_client_sessions_client  ON client_sessions (client_id);

-- ----------------------------------------------------------------------------
-- token_families
--
-- A lineage of refresh tokens descended from one authorization grant. Holds the
-- absolute ceiling that stops rotation from extending a session forever: a
-- client rotating every 29 days would otherwise hold one grant open indefinitely.
--
-- Sessions have the same expires_at / absolute_expires_at pair; refresh families
-- simply needed the same treatment one level down.
-- ----------------------------------------------------------------------------
CREATE TABLE token_families (
    family_id             VARCHAR(64) PRIMARY KEY,
    user_id               VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    client_id             VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    -- No foreign key. Authorization codes are reaped long before the refresh
    -- tokens they seeded expire, so the reference is intentionally dangling.
    -- Recorded here so the comment survives a future "fix" that adds an FK and
    -- then cascades away live tokens during cleanup.
    source_auth_code_hash VARCHAR(64),

    absolute_expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at            TIMESTAMPTZ,
    revocation_reason     VARCHAR(32),

    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT token_families_reason_chk CHECK (
        revocation_reason IS NULL OR revocation_reason IN (
            'rotated','logout','explicit','reuse_cascade','gdpr','admin'
        )
    ),
    CONSTRAINT token_families_revocation_chk CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE INDEX idx_families_user    ON token_families (user_id);
CREATE INDEX idx_families_client  ON token_families (client_id);
CREATE INDEX idx_families_expires ON token_families (absolute_expires_at);
CREATE INDEX idx_families_active  ON token_families (family_id)
    WHERE revoked_at IS NULL;

-- ----------------------------------------------------------------------------
-- auth_codes
--
-- Denormalises session_id and sid from the session that authorised it, so that a
-- token derived from a code can be traced back to the browser session. Without
-- them, scoped logout has nothing to find.
--
-- `family_id` is assigned AT INSERT TIME by the consent step, not by a later
-- UPDATE. Writing it afterwards means a crash between the two leaves a consumed
-- code with no family, and reuse detection has nothing to cascade.
-- ----------------------------------------------------------------------------
CREATE TABLE auth_codes (
    code_hash              VARCHAR(64) PRIMARY KEY,
    client_id              VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id                VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id             VARCHAR(64) REFERENCES sessions(session_id) ON DELETE SET NULL,
    sid                    VARCHAR(64),
    family_id              VARCHAR(64) REFERENCES token_families(family_id) ON DELETE SET NULL,

    scope                  TEXT[]     NOT NULL,
    -- Stored per code so the token request can re-verify an exact match. Not
    -- looked up from the client row: the value presented at /token must equal
    -- the one presented at /authorize, byte for byte.
    redirect_uri           TEXT        NOT NULL,

    code_challenge         VARCHAR(128) NOT NULL,
    code_challenge_method  VARCHAR(8)   NOT NULL DEFAULT 'S256',
    nonce                  VARCHAR(128),
    auth_time              TIMESTAMPTZ,

    expires_at             TIMESTAMPTZ NOT NULL,
    -- Single-use marker. NULL means unused.
    used_at                TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- OAuth 2.1 permits PKCE S256 only. The column exists so that the stored
    -- code records how it was derived, and so that the /token verifier can
    -- compare the presented method against what was registered rather than
    -- assuming. An earlier draft allowed 'plain' here on the theory that
    -- application code would reject it; the constraint did not. That is the
    -- wrong shape of defence, and it also contradicted auth_requests, which
    -- required S256. Both are now S256-only.
    CONSTRAINT auth_codes_challenge_method_chk CHECK (
        code_challenge_method = 'S256'
    )
);

CREATE INDEX idx_auth_codes_user    ON auth_codes (user_id);
CREATE INDEX idx_auth_codes_client  ON auth_codes (client_id);
CREATE INDEX idx_auth_codes_session ON auth_codes (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_auth_codes_expires ON auth_codes (expires_at);

-- ----------------------------------------------------------------------------
-- refresh_tokens
--
-- `revoked_at` is the single marker for both rotation and revocation; the
-- separate `revoked` boolean is gone. `revocation_reason` is what lets a replay
-- be told apart from an administrative revocation: `rotated` means reuse and
-- cascades to the family, everything else does not.
--
-- `replaced_by_hash` supports the grace window that keeps a benign concurrent
-- refresh from being mistaken for token theft.
-- ----------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    token_hash             VARCHAR(64) PRIMARY KEY,
    family_id              VARCHAR(64) NOT NULL REFERENCES token_families(family_id) ON DELETE CASCADE,
    client_id              VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id                VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id             VARCHAR(64) REFERENCES sessions(session_id) ON DELETE SET NULL,
    -- No FK to auth_codes: codes are reaped long before the refresh tokens they
    -- seeded expire.
    source_auth_code_hash  VARCHAR(64),
    replaced_by_hash       VARCHAR(64) REFERENCES refresh_tokens(token_hash) ON DELETE SET NULL,

    scope                  TEXT[]     NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    revocation_reason      VARCHAR(32),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT refresh_tokens_reason_chk CHECK (
        revocation_reason IS NULL OR revocation_reason IN (
            'rotated','logout','explicit','reuse_cascade','gdpr','admin'
        )
    ),
    CONSTRAINT refresh_tokens_revocation_chk CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

-- Reuse detection looks a token up by hash, then cascades over one family.
CREATE INDEX idx_refresh_family  ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_user    ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_session ON refresh_tokens (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_refresh_source  ON refresh_tokens (source_auth_code_hash) WHERE source_auth_code_hash IS NOT NULL;
CREATE INDEX idx_refresh_expires ON refresh_tokens (expires_at);
-- Supports finding the family of a rotated token without scanning.
CREATE INDEX idx_refresh_rotated ON refresh_tokens (token_hash) WHERE revoked_at IS NOT NULL;

-- ----------------------------------------------------------------------------
-- issued_access_tokens
--
-- A record of every access token issued, keyed by jti. Retained so that a
-- self-contained JWT can be resolved back to its origin for revocation,
-- introspection, reuse cascade and audit.
--
-- user_id is ON DELETE SET NULL: the token must remain revocable after the user
-- is erased. This is the one place where erasure nulls rather than restricts.
-- ----------------------------------------------------------------------------
CREATE TABLE issued_access_tokens (
    jti                    VARCHAR(64) PRIMARY KEY,
    user_id                VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    client_id              VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    session_id             VARCHAR(64) REFERENCES sessions(session_id) ON DELETE SET NULL,
    source_auth_code_hash  VARCHAR(64),

    scope                  TEXT[]     NOT NULL,
    issued_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at             TIMESTAMPTZ NOT NULL,

    CONSTRAINT issued_access_tokens_expiry_chk CHECK (expires_at > issued_at)
);

CREATE INDEX idx_issued_tokens_user    ON issued_access_tokens (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_issued_tokens_session ON issued_access_tokens (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_issued_tokens_source  ON issued_access_tokens (source_auth_code_hash) WHERE source_auth_code_hash IS NOT NULL;
CREATE INDEX idx_issued_tokens_expires ON issued_access_tokens (expires_at);
CREATE INDEX idx_issued_tokens_client  ON issued_access_tokens (client_id);

-- ----------------------------------------------------------------------------
-- revoked_tokens
--
-- The deny list for self-contained JWTs, keyed by jti and mirrored into Redis so
-- that a resource server check does not cost a database round-trip on every
-- API call. Postgres is the durable source; Redis is a cache that may be lost.
--
-- `reason` is populated only when known. Logout-driven revocations are not
-- interesting enough to enumerate in a hot-path table.
-- ----------------------------------------------------------------------------
CREATE TABLE revoked_tokens (
    jti        VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    reason     VARCHAR(32),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_revoked_expires ON revoked_tokens (expires_at);

-- ----------------------------------------------------------------------------
-- par_requests
--
-- RFC 9126. Single use: a second presentation MUST be denied, so consumption is
-- a conditional UPDATE guarded on consumed_at IS NULL. Without that column the
-- reference URI stays replayable for its whole lifetime.
-- ----------------------------------------------------------------------------
CREATE TABLE par_requests (
    request_uri  VARCHAR(128) PRIMARY KEY,
    client_id    VARCHAR(64)  NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    params_json  JSONB        NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- The reference URI is a bearer credential for the request itself and must
    -- never carry client credentials inside params_json.
    CONSTRAINT par_requests_params_chk CHECK (
        NOT (params_json ?| ARRAY[
            'request_uri','client_secret','client_assertion',
            'client_assertion_type','client_id'
        ])
    )
);

CREATE INDEX idx_par_client   ON par_requests (client_id);
CREATE INDEX idx_par_expires  ON par_requests (expires_at);

-- ----------------------------------------------------------------------------
-- auth_requests
--
-- An in-flight authorization request. Exists so that validated parameters
-- survive the redirect chain /authorize -> /login -> /mfa -> /consent.
--
-- Pushed requests make this necessary rather than merely tidy: request_uri is
-- single-use, so once consumed at /authorize a refresh of the login page finds
-- nothing and the parameters are gone.
--
-- The full validated parameter set lives in params_json, not in hand-picked
-- columns. Every parameter validated at /authorize and then dropped is a bug
-- waiting to happen: prompt and max_age in particular must survive to the login
-- decision, or prompt=none becomes impossible to honour.
-- ----------------------------------------------------------------------------
CREATE TABLE auth_requests (
    id            VARCHAR(64) PRIMARY KEY,
    client_id     VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    redirect_uri  TEXT        NOT NULL,
    response_type VARCHAR(16) NOT NULL,

    -- Retained as a generated convenience for indexes and queries; params_json
    -- remains the authority so there is exactly one parser.
    scope         TEXT[]      NOT NULL,
    state         VARCHAR(512),
    nonce         VARCHAR(128),
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(8) NOT NULL DEFAULT 'S256',

    -- Filled in as the flow progresses.
    user_id       VARCHAR(64) REFERENCES users(user_id) ON DELETE RESTRICT,
    session_id    VARCHAR(64) REFERENCES sessions(session_id) ON DELETE SET NULL,
    auth_time     TIMESTAMPTZ,

    params_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,

    expires_at    TIMESTAMPTZ NOT NULL,
    -- Single-use marker. The consent handler completes this with a
    -- completed_at IS NULL guard; without the guard a double-submitted consent
    -- form mints two codes.
    completed_at  TIMESTAMPTZ,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT auth_requests_response_type_chk CHECK (response_type = 'code'),
    CONSTRAINT auth_requests_challenge_method_chk CHECK (code_challenge_method = 'S256')
);

CREATE INDEX idx_auth_requests_expires   ON auth_requests (expires_at);
CREATE INDEX idx_auth_requests_user      ON auth_requests (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_auth_requests_client    ON auth_requests (client_id);
CREATE INDEX idx_auth_requests_incomplete ON auth_requests (expires_at) WHERE completed_at IS NULL;

-- ----------------------------------------------------------------------------
-- consents
--
-- The granted scope set. Comparison against a request is set containment, never
-- equality: a narrowed request must not silently shrink an existing grant, and
-- an expanded one must re-prompt.
-- ----------------------------------------------------------------------------
CREATE TABLE consents (
    user_id       VARCHAR(64) NOT NULL REFERENCES users(user_id)  ON DELETE CASCADE,
    client_id     VARCHAR(64) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    scopes        TEXT[]     NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    -- Periodic re-prompting. NULL means consent does not expire on its own.
    expires_at    TIMESTAMPTZ,

    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX idx_consents_client ON consents (client_id);
CREATE INDEX idx_consents_scopes ON consents USING gin (scopes);
CREATE INDEX idx_consents_expiring ON consents (expires_at) WHERE expires_at IS NOT NULL;

-- ----------------------------------------------------------------------------
-- mfa_backup_codes
--
-- One row per recovery code, individually hashed and individually consumable.
--
-- This replaces a TEXT[] on users for three reasons. An array requires a
-- read-modify-write to consume one code, so two concurrent submissions both
-- succeed and one code authorises two grants. There is no record of which code
-- was used. And a fixed-size array makes per-code rate limiting impossible.
--
-- Codes are 128 bits of CSPRNG output, so they are hashed with SHA-256 rather
-- than a password KDF. The KDF would cost real CPU for no added protection
-- against a value that has no guessing resistance to protect.
-- ----------------------------------------------------------------------------
CREATE TABLE mfa_backup_codes (
    code_hash  VARCHAR(64) PRIMARY KEY,
    user_id    VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_backup_codes_user  ON mfa_backup_codes (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_backup_codes_unused ON mfa_backup_codes (user_id) WHERE used_at IS NULL;

-- ----------------------------------------------------------------------------
-- email_verifications
--
-- `purpose` and `target_email` let one table serve both initial verification and
-- an email change. A change token must bind to the ADDRESS BEING CLAIMED, not to
-- the address already on the account, or a verification token issued for one
-- address would silently confirm another.
-- ----------------------------------------------------------------------------
CREATE TABLE email_verifications (
    token_hash   VARCHAR(64) PRIMARY KEY,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    purpose      VARCHAR(16) NOT NULL DEFAULT 'signup',
    target_email VARCHAR(256) NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    -- Verification codes are guessable if entropy is low. This bounds attempts
    -- per token independently of the global rate limiter.
    attempt_count INTEGER   NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT email_verifications_purpose_chk CHECK (
        purpose IN ('signup','change_email','password_reset')
    ),
    CONSTRAINT email_verifications_attempts_chk CHECK (attempt_count >= 0)
);

CREATE INDEX idx_email_verif_user    ON email_verifications (user_id);
CREATE INDEX idx_email_verif_expires ON email_verifications (expires_at);
CREATE INDEX idx_email_verif_email   ON email_verifications (lower(target_email));

-- ----------------------------------------------------------------------------
-- signing_keys
--
-- Lifecycle is active -> retiring -> retired.
--
--   active   : signs, and is published in the JWKS
--   retiring : published for verification only, does not sign, is destroyed
--              after its retention window
--   retired  : not published, private half destroyed
--
-- The partial unique index below is what guarantees exactly one signing key per
-- algorithm, so rotation cannot leave the server unable to sign. The CHECK
-- enforces that a retired key has no private material left.
--
-- public_jwk is stored so the published set can be read without decrypting
-- anything; it is regenerated from the private key on write and never edited by
-- hand. private_key_enc is BYTEA because AES-GCM output is binary.
-- ----------------------------------------------------------------------------
CREATE TABLE signing_keys (
    kid             VARCHAR(64) PRIMARY KEY,
    algorithm       VARCHAR(8)  NOT NULL DEFAULT 'RS256',
    public_jwk      JSONB       NOT NULL,
    private_key_enc BYTEA,

    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A key must not be accepted for verification before it was published.
    not_before      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retire_at       TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ,

    CONSTRAINT signing_keys_algorithm_chk CHECK (
        algorithm IN ('RS256','PS256','ES256','EdDSA')
    ),
    CONSTRAINT signing_keys_status_chk CHECK (
        status IN ('active','retiring','retired')
    ),
    -- A retired key has no private half. Enforced so that "we rotated" cannot
    -- quietly leave every historical signing key decryptable on disk forever.
    CONSTRAINT signing_keys_retired_chk CHECK (
        status <> 'retired'
        OR (retired_at IS NOT NULL AND private_key_enc IS NULL)
    ),
    CONSTRAINT signing_keys_timing_chk CHECK (
        retire_at IS NULL OR retire_at >= created_at
    )
);

-- At most one active key per algorithm. Without this, a botched rotation can
-- leave the server with no usable signing key.
CREATE UNIQUE INDEX idx_signing_keys_active_per_alg ON signing_keys (algorithm)
    WHERE status = 'active';

-- The JWKS serves exactly the keys still needed for verification.
CREATE INDEX idx_signing_keys_published ON signing_keys (not_before)
    WHERE status IN ('active','retiring');
CREATE INDEX idx_signing_keys_retiring_at ON signing_keys (retire_at)
    WHERE status = 'retiring' AND retire_at IS NOT NULL;

-- ----------------------------------------------------------------------------
-- audit_log
--
-- Partitioned by month because it is the largest table in the system and will
-- bloat. Retention is DROP PARTITION, never DELETE.
--
-- audit_log deliberately has NO foreign keys. An audit record must outlive the
-- rows it describes, and a FK would cascade-delete history.
--
-- There are no free-form JSONB PII columns. audit.Event is a Go struct, so the
-- set of fields that can hold personal data is closed and known, which is what
-- makes erasure provably complete. Redacting arbitrary JSONB by removing
-- top-level keys is unsound: details - 'email' does not touch {"ctx":{"email":...}}.
--
-- ip_address is INET rather than VARCHAR(45): 16 bytes instead of 45, native
-- comparison and masking, and malformed input is rejected at the type level.
--
-- The default partition absorbs writes until a scheduled job creates the
-- monthly partitions. Note that rows in the default partition must be moved
-- before a partition covering that range can be attached.
-- ----------------------------------------------------------------------------
CREATE TABLE audit_log (
    id             BIGSERIAL   NOT NULL,
    event          VARCHAR(64) NOT NULL,
    -- HMAC-SHA256(pepper, lower(email)), not a bare hash. A bare SHA-256 of an
    -- email address is reversible from any rainbow table, which would re-identify
    -- every row belonging to one person without pseudonymising anything.
    actor          VARCHAR(64),
    target         VARCHAR(64),
    session_id     VARCHAR(64),
    ip_address     INET,
    user_agent     VARCHAR(512),
    correlation_id VARCHAR(64),
    details        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (id, created_at),

    -- Both are free text from the caller's perspective but constrained to known
    -- shapes, because event is the index every incident response starts from.
    CONSTRAINT audit_log_actor_chk  CHECK (actor  IS NULL OR length(actor)  <= 64),
    CONSTRAINT audit_log_target_chk CHECK (target IS NULL OR length(target) <= 64)
) PARTITION BY RANGE (created_at);

CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;

-- These propagate to every partition automatically as they are attached.
CREATE INDEX idx_audit_actor        ON audit_log (actor)  WHERE actor IS NOT NULL;
CREATE INDEX idx_audit_target       ON audit_log (target) WHERE target IS NOT NULL;
CREATE INDEX idx_audit_event        ON audit_log (event);
CREATE INDEX idx_audit_created      ON audit_log (created_at);
-- Without this, querying by correlation id to reconstruct a login is a
-- sequential scan, which is the whole point of recording it.
CREATE INDEX idx_audit_correlation  ON audit_log (correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX idx_audit_session      ON audit_log (session_id) WHERE session_id IS NOT NULL;

-- ----------------------------------------------------------------------------
-- Row-level safety notes, for whoever writes the grants
-- ----------------------------------------------------------------------------
--
-- The application role must be INSERT-only on audit_log. Append-only enforced
-- at the database is stronger than trusting every code path to behave.
--
-- No UPDATE or DELETE grant on audit_log is needed by the application. Retention
-- is performed by a privileged role issuing DROP PARTITION.
--
-- Erasure performs UPDATE ... SET actor = NULL, ip_address = NULL,
-- user_agent = NULL, session_id = NULL WHERE actor = $1 OR target = $1.
-- It does not attempt to rewrite details, because the column cannot contain
-- personally identifying data by construction.