package client_auth

// Authenticator interface and shared error types.

import (
	"context"
	"errors"
	"net/http"

	"oauth-server/internal/domain"
)

// ErrInvalidClient is returned when client authentication fails for any reason.
//
// It is a domain OAuth error rather than a plain sentinel so that oautherr.From maps it
// to invalid_client with a 401 on the way out. A plain error here would reach the token
// endpoint's generic error branch and be rendered as an opaque server_error, turning
// every misconfigured or wrong client secret into an apparent server fault and a 500.
var ErrInvalidClient = domain.NewInvalidClient("client authentication failed")

// ErrUnsupportedAuthMethod means the client tried an auth method the server
// doesn't implement for that client.
var ErrUnsupportedAuthMethod = errors.New("client authentication method not supported for this client")

// Authenticator authenticates a client from an HTTP request.
//
// Implementations must return a *domain.Client on success, or ErrInvalidClient
// (or wrapped variant) on any failure. The specific failure reason is not
// exposed to the client to prevent enumeration.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error)
}
