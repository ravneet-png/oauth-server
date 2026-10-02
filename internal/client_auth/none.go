package client_auth

// none.go — Public client authentication (SPAs, mobile).
//
// The client sends only client_id in the request body. No secret, no assertion.
// Security relies entirely on PKCE: the authorization code cannot be redeemed
// without the code_verifier that only the legitimate client knows.

import (
	"context"
	"fmt"
	"net/http"

	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// NoneAuthenticator authenticates public clients using client_id only.
type NoneAuthenticator struct {
	repo *storage.ClientRepo
}

// NewNoneAuthenticator builds a NoneAuthenticator.
func NewNoneAuthenticator(repo *storage.ClientRepo) *NoneAuthenticator {
	return &NoneAuthenticator{repo: repo}
}

// Authenticate extracts client_id from the form body, loads the client, and
// verifies it is a public client (TokenEndpointAuthMethod == "none").
func (a *NoneAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("%w: method must be POST", ErrInvalidClient)
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: parse form: %w", ErrInvalidClient, err)
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrInvalidClient)
	}

	client, err := a.repo.GetByID(ctx, clientID)
	if err != nil {
		// Whether unknown or DB error: same error to prevent enumeration
		return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
	}

	if client.IsConfidential() {
		return nil, fmt.Errorf("%w: confidential client must authenticate", ErrInvalidClient)
	}
	if client.TokenEndpointAuthMethod != domain.AuthMethodNone {
		return nil, fmt.Errorf("%w: auth method not allowed for this client", ErrInvalidClient)
	}

	return client, nil
}
