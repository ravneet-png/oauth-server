-- 006_device_codes
-- Device Authorization Grant (RFC 8628). One row per in-progress device
-- authorization, from the client's POST /device_authorization until the device
-- redeems tokens at POST /token.
--
-- Two credentials live on the row and they are deliberately different shapes.
-- device_code_hash is the SHA-256 of a high-entropy secret the device holds and
-- never shows to a person; it is the only value that redeems tokens. user_code is
-- a short, human-typed string that is NOT secret: it is protected by the user
-- authenticating and consenting on the verification page, plus the short lifetime
-- and the enforced poll interval, not by entropy.

CREATE TABLE device_codes (
    device_code_hash  VARCHAR(64)  PRIMARY KEY,
    user_code         VARCHAR(32)  NOT NULL,
    client_id         VARCHAR(64)  NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    scope             TEXT[]       NOT NULL DEFAULT '{}',
    status            TEXT         NOT NULL DEFAULT 'pending',
    user_id           VARCHAR(64)  REFERENCES users(user_id) ON DELETE RESTRICT,
    interval_seconds  INTEGER      NOT NULL,
    last_polled_at    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ  NOT NULL,
    approved_at       TIMESTAMPTZ,
    consumed_at       TIMESTAMPTZ,

    CONSTRAINT device_codes_status_chk CHECK (
        status IN ('pending','approved','denied','consumed')
    ),

    -- The subject and the status move together: an approved or consumed request
    -- always names the user who approved it, and a pending or denied one never
    -- does. Without this a malformed update could leave an approved row with no
    -- subject, and the token minted from it would identify nobody.
    CONSTRAINT device_codes_subject_chk CHECK (
        (status IN ('approved','consumed') AND user_id IS NOT NULL)
        OR (status IN ('pending','denied') AND user_id IS NULL)
    ),

    -- The poll floor is a positive number of seconds. Zero would let a client
    -- poll in a tight loop and turn /token into a drain on the database.
    CONSTRAINT device_codes_interval_chk CHECK (interval_seconds > 0)
);

-- The user_code must address exactly one live decision, so it is unique among
-- live requests. A partial index rather than a plain unique constraint, because a
-- code is recycled once its request is over: an expired, denied or consumed row
-- must not hold the code hostage.
CREATE UNIQUE INDEX idx_device_codes_user_code_live
    ON device_codes (user_code)
    WHERE status IN ('pending','approved');

-- The reaper scans by expiry.
CREATE INDEX idx_device_codes_expires_at ON device_codes (expires_at);
