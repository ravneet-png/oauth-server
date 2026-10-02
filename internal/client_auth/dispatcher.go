package client_auth

// dispatcher.go — Detects and dispatches to the appropriate authenticator.

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// Dispatcher holds all authenticators and routes requests to the right one.
type Dispatcher struct {
	clientRepo *storage.ClientRepo
	basicAuth  *SecretBasicAuthenticator
	postAuth   *SecretPostAuthenticator
	jwtAuth    *PrivateKeyJWTAuthenticator
	noneAuth   *NoneAuthenticator
}

// NewDispatcher builds a Dispatcher with all authenticators.
func NewDispatcher(
	clientRepo *storage.ClientRepo,
	basicAuth *SecretBasicAuthenticator,
	postAuth *SecretPostAuthenticator,
	jwtAuth *PrivateKeyJWTAuthenticator,
	noneAuth *NoneAuthenticator,
) *Dispatcher {
	return &Dispatcher{
		clientRepo: clientRepo,
		basicAuth:  basicAuth,
		postAuth:   postAuth,
		jwtAuth:    jwtAuth,
		noneAuth:   noneAuth,
	}
}

// Authenticate detects the auth method from the request and delegates.
//
// Detection order:
//  1. Authorization: Basic → secret_basic
//  2. client_assertion in body → private_key_jwt
//  3. client_secret in body → secret_post
//  4. client_id in body (no secret, no assertion) → none
//  5. nothing → ErrInvalidClient("no credentials")
//
// After successful authentication, verifies that the used method matches
// client.TokenEndpointAuthMethod. Mismatch → ErrInvalidClient("auth method not allowed").
func (d *Dispatcher) Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error) {
	// Copy the request body for parsing (ParseForm can be called multiple times)
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("%w: method must be POST", ErrInvalidClient)
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: parse form: %w", ErrInvalidClient, err)
	}

	// 1. Authorization: Basic
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		return d.authenticateWithCheck(ctx, r, d.basicAuth, domain.AuthMethodClientSecretBasic)
	}

	// 2. client_assertion in body
	if r.Form.Get("client_assertion") != "" {
		return d.authenticateWithCheck(ctx, r, d.jwtAuth, domain.AuthMethodPrivateKeyJWT)
	}

	// 3. client_secret in body (no assertion)
	if r.Form.Get("client_secret") != "" {
		return d.authenticateWithCheck(ctx, r, d.postAuth, domain.AuthMethodClientSecretPost)
	}

	// 4. client_id only (no secret, no assertion)
	if r.Form.Get("client_id") != "" {
		return d.authenticateWithCheck(ctx, r, d.noneAuth, domain.AuthMethodNone)
	}

	// 5. Nothing
	return nil, fmt.Errorf("%w: no credentials provided", ErrInvalidClient)
}

// authenticateWithCheck runs the authenticator and then verifies the method matches.
func (d *Dispatcher) authenticateWithCheck(ctx context.Context, r *http.Request, auth Authenticator, expectedMethod string) (*domain.Client, error) {
	if auth == nil {
		return nil, fmt.Errorf("%w: authenticator not configured for %s", ErrInvalidClient, expectedMethod)
	}

	client, err := auth.Authenticate(ctx, r)
	if err != nil {
		return nil, err
	}

	// Double-check the client's allowed method matches what we used
	if client.TokenEndpointAuthMethod != expectedMethod {
		return nil, fmt.Errorf("%w: auth method %q not allowed for this client (expected %s)", ErrInvalidClient, expectedMethod, client.TokenEndpointAuthMethod)
	}

	return client, nil
}
