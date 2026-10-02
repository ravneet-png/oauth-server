package storage

// Client persistence.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// ClientRepo reads and writes the clients table.
type ClientRepo struct {
	pool *pgxpool.Pool
}

// NewClientRepo builds a ClientRepo over pool.
func NewClientRepo(pool *pgxpool.Pool) *ClientRepo {
	assertPoolNonNil(pool, "ClientRepo")
	return &ClientRepo{pool: pool}
}

// clientColumns is the single column list, so the SELECT and every scan agree by
// construction.
//
// Duplicating a column list in two places is how a column gets added to the
// SELECT and forgotten in the Scan, which compiles fine and silently shifts
// every subsequent field: clients has both client_id_issued_at and
// client_secret_expires_at adjacent to each other and both are BIGINT, so a
// mismatch there is a wrong value rather than a type error.
const clientColumns = `
	client_id, client_secret_hash,
	client_id_issued_at, client_secret_expires_at,
	client_name, redirect_uris, grant_types, response_types, scopes,
	token_endpoint_auth_method, token_ttl, refresh_idle_ttl, client_credentials_ttl,
	jwks_uri, jwks,
	logo_uri, client_uri, policy_uri, tos_uri, contacts,
	sector_identifier_uri, subject_type,
	backchannel_logout_uri, backchannel_logout_session_required, post_logout_redirect_uris,
	par_required, disabled_at, created_at, updated_at`

// scanClient reads one row. pgx maps NULL to a nil pointer for *string and
// []byte, and BIGINT to int64, so the epoch conversion happens here.
func scanClient(row interface{ Scan(...any) error }) (*domain.Client, error) {
	var (
		c               domain.Client
		secretHash      *string
		issuedAt        int64
		secretExpiresAt int64
		tokenTTL        int32
		refreshIdleTTL  int32
		clientCredsTTL  int32
		jwks            []byte
		redirectURIs    []string
		grantTypes      []string
		responseTypes   []string
		scopes          []string
		contacts        []string
		postLogoutURIs  []string
		disabledAt      *time.Time
	)

	err := row.Scan(
		&c.ClientID, &secretHash,
		&issuedAt, &secretExpiresAt,
		&c.ClientName, &redirectURIs, &grantTypes, &responseTypes, &scopes,
		&c.TokenEndpointAuthMethod, &tokenTTL, &refreshIdleTTL, &clientCredsTTL,
		&c.JWKSURI, &jwks,
		&c.LogoURI, &c.ClientURI, &c.PolicyURI, &c.TosURI, &contacts,
		&c.SectorIdentifierURI, &c.SubjectType,
		&c.BackchannelLogoutURI, &c.BackchannelLogoutSessionRequired, &postLogoutURIs,
		&c.PARRequired, &disabledAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	c.ClientSecretHash = secretHash
	c.ClientIDIssuedAt = epochToTime(issuedAt)
	c.ClientSecretExpiresAt = epochToTime(secretExpiresAt)
	c.RedirectURIs = scanStrings(redirectURIs)
	c.GrantTypes = scanStrings(grantTypes)
	c.ResponseTypes = scanStrings(responseTypes)
	c.Scopes = scanStrings(scopes)
	c.Contacts = scanStrings(contacts)
	c.PostLogoutRedirectURIs = scanStrings(postLogoutURIs)
	c.DisabledAt = disabledAt
	if len(jwks) > 0 {
		c.JWKSet = jwks
	}
	// The schema stores these as INTEGER seconds and the domain as time.Duration.
	// Converting here means no caller ever has to remember which is which.
	c.TokenTTL = time.Duration(tokenTTL) * time.Second
	c.RefreshIdleTTL = time.Duration(refreshIdleTTL) * time.Second
	c.ClientCredentialsTTL = time.Duration(clientCredsTTL) * time.Second

	return &c, nil
}

// GetByID returns the client with the given id.
//
// A disabled client is returned, not filtered out. /token must be able to answer
// invalid_client for a client that exists but is disabled, and returning
// ErrNotFound for those two cases would let an attacker distinguish registered
// from unregistered client IDs by whether the error mentions the account state.
// Client.IsEnabled is the caller's check.
func (r *ClientRepo) GetByID(ctx context.Context, clientID string) (*domain.Client, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE client_id = $1`, clientID)

	c, err := scanClient(row)
	if err != nil {
		return nil, rowNotFound(err, formatOp("clients", "get"))
	}
	return c, nil
}

// Create inserts a client.
//
// The schema's CHECK constraints are the real validation here: a client that
// registers a fragment-bearing redirect URI, or a `none` client holding a
// secret, is rejected by the database rather than by a code path someone has to
// remember to call. That is why Create does not pre-validate: a pre-check that
// disagrees with the constraint produces a server that accepts what its own
// database forbids, and the CHECK is the one both must agree with.
func (r *ClientRepo) Create(ctx context.Context, c *domain.Client) error {
	const q = `
		INSERT INTO clients (
			client_id, client_secret_hash,
			client_id_issued_at, client_secret_expires_at,
			client_name, redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, token_ttl, refresh_idle_ttl, client_credentials_ttl,
			jwks_uri, jwks,
			logo_uri, client_uri, policy_uri, tos_uri, contacts,
			sector_identifier_uri, subject_type,
			backchannel_logout_uri, backchannel_logout_session_required, post_logout_redirect_uris,
			par_required, disabled_at
		) VALUES (
			$1, $2,
			$3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, $12, $13,
			$14, $15::jsonb,
			$16, $17, $18, $19, $20,
			$21, $22,
			$23, $24, $25,
			$26, $27
		)`
	args := []any{
		c.ClientID, c.ClientSecretHash,
		timeToEpoch(c.ClientIDIssuedAt), timeToEpoch(c.ClientSecretExpiresAt),
		c.ClientName, c.RedirectURIs, c.GrantTypes, c.ResponseTypes, c.Scopes,
		c.TokenEndpointAuthMethod,
		int32(c.TokenTTL / time.Second),
		int32(c.RefreshIdleTTL / time.Second),
		int32(c.ClientCredentialsTTL / time.Second),
		c.JWKSURI, jsonOrNil(c.JWKSet),
		c.LogoURI, c.ClientURI, c.PolicyURI, c.TosURI, c.Contacts,
		c.SectorIdentifierURI, c.SubjectType,
		c.BackchannelLogoutURI, c.BackchannelLogoutSessionRequired, c.PostLogoutRedirectURIs,
		c.PARRequired, c.DisabledAt,
	}

	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return classifyError(err, formatOp("clients", "create"))
	}
	return nil
}

// GetWithBackchannelLogout returns every enabled client that has registered a
// back-channel logout URI.
//
// Only for clients that are not disabled, and only those with a URI set. The
// prompt for this method lists no arguments, and that is the correct shape: the
// caller is a periodic sweep, not a request handler, so filtering by session or
// user would mean this method cannot be used to discover the full set at all.
//
// The alternative reading is "clients to notify for this user", which is a
// different query and belongs to a different caller: it needs the user_id that
// client_sessions deliberately does not store, so it must join through sessions.
// Putting that here would give this method two incompatible contracts.
//
// The partial index idx_clients_backchannel covers exactly this predicate, so
// this stays an index scan rather than a full pass as the client table grows.
func (r *ClientRepo) GetWithBackchannelLogout(ctx context.Context) ([]*domain.Client, error) {
	const q = `SELECT ` + clientColumns + `
		FROM clients
		WHERE backchannel_logout_uri IS NOT NULL
		  AND disabled_at IS NULL
		ORDER BY client_id`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, classifyError(err, formatOp("clients", "backchannel"))
	}
	defer rows.Close()

	var out []*domain.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, wrapRowsErr(err, formatOp("clients", "backchannel", "scan"))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		// A truncated result set is worse than an error: a caller that fans out
		// back-channel logout to a partial list leaves some RPs believing the
		// user is still signed in.
		return nil, wrapRowsErr(err, formatOp("clients", "backchannel", "iterate"))
	}
	return out, nil
}
