package client_auth

// secret_basic.go — client_secret_basic authentication.
//
// Client sends Authorization: Basic base64(client_id:client_secret).
// The secret is verified against the stored SHA-256 hex digest.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// SecretBasicAuthenticator authenticates clients using HTTP Basic auth.
type SecretBasicAuthenticator struct {
	repo *storage.ClientRepo
}

// NewSecretBasicAuthenticator builds a SecretBasicAuthenticator.
func NewSecretBasicAuthenticator(repo *storage.ClientRepo) *SecretBasicAuthenticator {
	return &SecretBasicAuthenticator{repo: repo}
}

// Authenticate parses the Basic header, loads the client, verifies the auth
// method is client_secret_basic, and checks the secret against the stored hash.
func (a *SecretBasicAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("%w: missing Authorization header", ErrInvalidClient)
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return nil, fmt.Errorf("%w: Authorization header must be Basic", ErrInvalidClient)
	}

	encoded := strings.TrimPrefix(auth, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid Basic encoding", ErrInvalidClient)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: invalid Basic credentials", ErrInvalidClient)
	}

	clientID, secret := parts[0], parts[1]
	if clientID == "" || secret == "" {
		return nil, fmt.Errorf("%w: empty client_id or secret", ErrInvalidClient)
	}

	client, err := a.repo.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
	}

	if client.TokenEndpointAuthMethod != domain.AuthMethodClientSecretBasic {
		return nil, fmt.Errorf("%w: auth method not allowed for this client", ErrInvalidClient)
	}

	if client.ClientSecretHash == nil {
		return nil, fmt.Errorf("%w: client has no secret", ErrInvalidClient)
	}

	// SHA-256, not Argon2id. A client secret is 256 bits of CSPRNG output, so a
	// password KDF buys nothing against guessing and costs ~100ms of CPU on every
	// token request. The stored column is VARCHAR(64), which is the length of a
	// SHA-256 hex digest and shorter than any Argon2id encoding, so the schema
	// already made this choice.
	if !crypto.VerifySHA256Hex(secret, *client.ClientSecretHash) {
		return nil, fmt.Errorf("%w: invalid client secret", ErrInvalidClient)
	}

	return client, nil
}
