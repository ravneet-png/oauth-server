// Deterministic test data builders: clients of each auth method, users with and without MFA, expired rows, and consumed codes. Versioned alongside migrations so that drift is visible.

package fixtures

import (
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
)

// ConfidentialClient builds a client_secret_basic client.
//
// The secret is stored the way the production paths store it: SHA-256 hex. The plaintext
// is returned so a test can authenticate with it. If the fixture hashed differently from
// the server, every token request would fail authentication with a 401 that looks like a
// test bug rather than a fixture bug.
func ConfidentialClient(clientID, secret, name string, redirectURIs, grantTypes, scopes []string) (*domain.Client, string) {
	hash := crypto.SHA256Hex(secret)
	return &domain.Client{
		ClientID:                clientID,
		ClientSecretHash:        &hash,
		ClientIDIssuedAt:        time.Now().UTC(),
		ClientSecretExpiresAt:   time.Now().UTC().Add(365 * 24 * time.Hour),
		ClientName:              name,
		RedirectURIs:            orEmpty(redirectURIs),
		GrantTypes:              orEmpty(grantTypes),
		ResponseTypes:           []string{"code"},
		Scopes:                  orEmpty(scopes),
		Contacts:                []string{},
		PostLogoutRedirectURIs:  []string{},
		TokenEndpointAuthMethod: "client_secret_basic",
		TokenTTL:                15 * time.Minute,
		RefreshIdleTTL:          30 * 24 * time.Hour,
		ClientCredentialsTTL:    15 * time.Minute,
		SubjectType:             "public",
	}, secret
}

// PublicClient builds a client with no secret (token_endpoint_auth_method "none").
//
// ClientSecretHash is nil, which is the exact condition the schema encodes for a public
// client and the condition the token endpoint checks before allowing PKCE-only exchange.
func PublicClient(clientID, name string, redirectURIs, grantTypes, scopes []string) *domain.Client {
	return &domain.Client{
		ClientID:                clientID,
		ClientIDIssuedAt:        time.Now().UTC(),
		ClientSecretExpiresAt:   time.Now().UTC(),
		ClientName:              name,
		RedirectURIs:            orEmpty(redirectURIs),
		GrantTypes:              orEmpty(grantTypes),
		ResponseTypes:           []string{"code"},
		Scopes:                  orEmpty(scopes),
		Contacts:                []string{},
		PostLogoutRedirectURIs:  []string{},
		TokenEndpointAuthMethod: "none",
		TokenTTL:                15 * time.Minute,
		RefreshIdleTTL:          30 * 24 * time.Hour,
		ClientCredentialsTTL:    15 * time.Minute,
		SubjectType:             "public",
	}
}

// orEmpty converts a nil slice to an empty one.
//
// The repository passes slices straight to PostgreSQL, where a nil slice is NULL. Every
// one of these columns is NOT NULL, so a fixture that left one nil would fail the insert
// with a NOT NULL violation that names no column and reads as a schema bug rather than a
// fixture bug.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UserWithPassword builds a verified user whose password hash matches password.
//
// Uses the same Argon2 defaults as config.yaml so a hash produced here verifies against
// a server constructed from the shipped defaults.
func UserWithPassword(userID, email, password string) (*domain.User, string) {
	hash, err := crypto.HashPassword(password, crypto.DefaultArgon2Params())
	if err != nil {
		// A fixture that cannot hash cannot build a usable user, and returning a
		// half-built one would surface as an authentication failure far from here.
		panic("fixtures: hash password: " + err.Error())
	}
	name := "Test User"
	return &domain.User{
		UserID:            userID,
		Email:             email,
		PasswordHash:      hash,
		Name:              &name,
		EmailVerified:     true,
		PasswordChangedAt: time.Now().UTC(),
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}, password
}

// Admin builds an administrator, which is the only role allowed to reach the erasure and
// key-rotation endpoints.
func Admin(userID, email, password string) (*domain.User, string) {
	u, pw := UserWithPassword(userID, email, password)
	u.IsAdmin = true
	return u, pw
}
