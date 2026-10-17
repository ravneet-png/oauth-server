-- 007_device_grant_client_constraints (down)
-- Restore the pre-device-grant client constraints. This will fail if any client
-- is registered for the device grant, which is the correct outcome: rolling back
-- the constraint while such a client exists would leave a row the schema no
-- longer describes.

ALTER TABLE clients
    DROP CONSTRAINT clients_grant_types_chk,
    DROP CONSTRAINT clients_redirect_uris_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_grant_types_chk CHECK (
        coalesce(array_length(grant_types, 1), 0) > 0
        AND grant_types <@ ARRAY['authorization_code','client_credentials','refresh_token']
    ),

    ADD CONSTRAINT clients_redirect_uris_chk CHECK (
        (
            grant_types <@ ARRAY['client_credentials']
            OR coalesce(array_length(redirect_uris, 1), 0) > 0
        )
        AND array_to_string(redirect_uris, ' ') NOT LIKE '%#%'
        AND array_to_string(redirect_uris, ' ') !~ '@[^/]+/'
    );
