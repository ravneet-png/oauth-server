-- ============================================================================
-- 001_initial_schema (down)
--
-- Drops in reverse dependency order. Partition children go with their parent.
--
-- This is destructive and irreversible. `make migrate-down-1` exists for
-- development only; there is deliberately no target that drops everything, so
-- that running this against a database holding data requires typing it out.
-- ============================================================================

-- audit_log is partitioned; the child goes automatically with the parent, but
-- dropping it explicitly keeps the intent readable and survives a future change
-- to the partitioning strategy.
DROP TABLE IF EXISTS audit_log;

DROP TABLE IF EXISTS signing_keys;

DROP TABLE IF EXISTS email_verifications;

DROP TABLE IF EXISTS mfa_backup_codes;

DROP TABLE IF EXISTS consents;

DROP TABLE IF EXISTS auth_requests;

DROP TABLE IF EXISTS par_requests;

DROP TABLE IF EXISTS revoked_tokens;

DROP TABLE IF EXISTS issued_access_tokens;

-- refresh_tokens before token_families: the family_id FK cascades either way,
-- but the explicit order makes the graph readable.
DROP TABLE IF EXISTS refresh_tokens;

DROP TABLE IF EXISTS auth_codes;

DROP TABLE IF EXISTS token_families;

DROP TABLE IF EXISTS client_sessions;

DROP TABLE IF EXISTS sessions;

DROP TABLE IF EXISTS users;

DROP TABLE IF EXISTS clients;

-- idx_users_email_lower, idx_par_params_chk and every other index and
-- constraint is owned by its table and drops with it.