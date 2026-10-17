-- 007_device_grant_client_constraints
-- Teach the clients table about the RFC 8628 device authorization grant.
--
-- Two constraints were written before the grant existed and both reject a
-- perfectly valid device client:
--
--   * clients_grant_types_chk allowed only authorization_code, client_credentials
--     and refresh_token, so registering a client for the device grant failed at
--     the allow-list.
--
--   * clients_redirect_uris_chk required a redirect_uri unless every grant was
--     client_credentials. A device client has no browser redirect at all, so a
--     redirect-less device client was rejected even once the grant was allowed.
--
-- The application layer already treats only authorization_code as needing a
-- redirect (client_register.go), so these constraints are being brought back in
-- line with the code rather than the other way round.

ALTER TABLE clients
    DROP CONSTRAINT clients_grant_types_chk,
    DROP CONSTRAINT clients_redirect_uris_chk;

ALTER TABLE clients
    ADD CONSTRAINT clients_grant_types_chk CHECK (
        coalesce(array_length(grant_types, 1), 0) > 0
        AND grant_types <@ ARRAY[
            'authorization_code',
            'client_credentials',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code'
        ]
    ),

    -- A client may omit redirect_uris only when none of its grants ever redirects
    -- a browser. client_credentials, refresh_token and the device grant all
    -- qualify — a device client routinely also carries refresh_token, and neither
    -- grant sends the user back to the client. authorization_code is the one grant
    -- that does, so a client carrying it still needs a redirect_uri. This mirrors
    -- the check in client_register.go, which treats only authorization_code as
    -- needing a redirect.
    ADD CONSTRAINT clients_redirect_uris_chk CHECK (
        (
            grant_types <@ ARRAY[
                'client_credentials',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code'
            ]
            OR coalesce(array_length(redirect_uris, 1), 0) > 0
        )
        -- RFC 6749 3.1.2: a redirect URI must not contain a fragment.
        AND array_to_string(redirect_uris, ' ') NOT LIKE '%#%'
        -- userinfo in a redirect URI is a phishing primitive.
        AND array_to_string(redirect_uris, ' ') !~ '@[^/]+/'
    );
