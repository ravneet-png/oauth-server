package client_auth

// secret_post.go — client_secret_post authentication.
//
// Client sends client_id and client_secret as form parameters in the request body.

import (
	"context"
	"fmt"
	"net/http"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// SecretPostAuthenticator authenticates clients using form body credentials.
type SecretPostAuthenticator struct {
	repo *storage.ClientRepo
}

// NewSecretPostAuthenticator builds a SecretPostAuthenticator.
func NewSecretPostAuthenticator(repo *storage.ClientRepo) *SecretPostAuthenticator {
	return &SecretPostAuthenticator{repo: repo}
}

// Authenticate parses client_id and client_secret from the form body,
// verifies the auth method is client_secret_post, and checks the secret.
func (a *SecretPostAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("%w: method must be POST", ErrInvalidClient)
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: parse form: %v", ErrInvalidClient, err)
	}

	clientID := r.Form.Get("client_id")
	secret := r.Form.Get("client_secret")

	if clientID == "" || secret == "" {
		return nil, fmt.Errorf("%w: client_id and client_secret are required", ErrInvalidClient)
	}

	client, err := a.repo.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
	}

	if client.TokenEndpointAuthMethod != domain.AuthMethodClientSecretPost {
		return nil, fmt.Errorf("%w: auth method not allowed for this client", ErrInvalidClient)
	}

	if client.ClientSecretHash == nil {
		return nil, fmt.Errorf("%w: client has no secret", ErrInvalidClient)
	}

	// SHA-256, matching secret_basic and the VARCHAR(64) column. See the note there.
	if !crypto.VerifySHA256Hex(secret, *client.ClientSecretHash) {
		return nil, fmt.Errorf("%w: invalid client secret", ErrInvalidClient)
	}

	return client, nil
}
