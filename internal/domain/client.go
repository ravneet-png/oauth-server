package domain

// Registered OAuth client.
//
// Note there is deliberately NO IsConfidential field: it is derived from
// TokenEndpointAuthMethod, and two sources of truth can drift apart. The schema
// enforces the derivation with clients_secret_consistency_chk, so a row cannot
// claim to be public while holding a secret hash.

import (
	"encoding/json"
	"time"
)

// Token endpoint authentication methods. This is the closed set the schema
// permits, and the set of Authenticator implementations that exist.
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
	AuthMethodNone              = "none"
)

// Grant types. OAuth 2.1 removes implicit and password; the schema's
// clients_grant_types_chk rejects them at registration, so a client row cannot
// name a grant the server has no code path for.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantRefreshToken      = "refresh_token"
)

// Subject types for pairwise subject identifiers.
const (
	SubjectTypePublic   = "public"
	SubjectTypePairwise = "pairwise"
)

// Client is a registered OAuth client.
type Client struct {
	ClientID string

	// SHA-256 hex of the client secret. nil exactly when AuthMethod is `none`.
	ClientSecretHash *string

	ClientIDIssuedAt      time.Time
	ClientSecretExpiresAt time.Time

	ClientName    string
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string

	TokenEndpointAuthMethod string
	TokenTTL                time.Duration
	RefreshIdleTTL          time.Duration
	ClientCredentialsTTL    time.Duration

	// JWKSURI and JWKSet are the two ways a private_key_jwt client publishes
	// its verification key. At least one must be present. JWKSet is stored as
	// JSONB, so it is held here as raw JSON rather than a decoded struct: the
	// domain layer does not need to understand JWK structure, and decoding it
	// here would put a crypto-library type in every layer that touches Client.
	JWKSURI *string
	JWKSet  json.RawMessage

	LogoURI   *string
	ClientURI *string
	PolicyURI *string
	TosURI    *string
	Contacts  []string

	SectorIdentifierURI *string
	SubjectType         string

	BackchannelLogoutURI             *string
	BackchannelLogoutSessionRequired bool
	PostLogoutRedirectURIs           []string

	// PARRequired makes /authorize refuse any request that did not arrive via a
	// pushed authorization request.
	PARRequired bool

	DisabledAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IsConfidential reports whether the client can keep a secret.
//
// Derived, never stored. A `none` client is public and relies entirely on PKCE
// to stop an attacker who intercepts an authorization code from redeeming it;
// an attacker who also intercepted the token request has nothing left to guess.
func (c *Client) IsConfidential() bool {
	return c.TokenEndpointAuthMethod != AuthMethodNone
}

// IsEnabled reports whether the client may currently be used. A disabled client
// still resolves, so that /token can answer invalid_client rather than an
// error that reveals the client ID is unregistered.
func (c *Client) IsEnabled() bool {
	return c.DisabledAt == nil
}

// SupportsGrant reports whether grant is registered for this client.
func (c *Client) SupportsGrant(grant string) bool {
	return ScopeContains(c.GrantTypes, grant)
}

// RedirectURIAllowed reports whether uri was registered for this client.
//
// Comparison is exact string equality against the registered set. No prefix
// matching, no trailing-slash tolerance, no case folding, no normalisation of
// the query string. Any of those widens the set of URIs an attacker can
// redirect to, and a redirect URI is the one thing in OAuth that must be
// matched byte for byte (RFC 6749 section 3.1.2.3).
func (c *Client) RedirectURIAllowed(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// PostLogoutRedirectURIAllowed reports whether uri is registered for
// post-logout redirect. Exact match, same reasoning as RedirectURIAllowed.
//
// Note that an unregistered post-logout URI must fall back to rendering a local
// confirmation page, never to a redirect. This is the classic open-redirect
// primitive: an attacker sends a victim a logout link that lands them on a
// phishing page still framed as the authorization server.
func (c *Client) PostLogoutRedirectURIAllowed(uri string) bool {
	for _, allowed := range c.PostLogoutRedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// RequiresPAR reports whether this client must use pushed authorization
// requests.
func (c *Client) RequiresPAR() bool {
	return c.PARRequired
}

// CanUseRedirect reports whether grant needs a registered redirect URI at all.
// Only client_credentials can proceed without one, because it never involves a
// browser redirect.
func (c *Client) CanUseRedirect(grant string) bool {
	return grant != GrantClientCredentials && len(c.RedirectURIs) > 0
}
