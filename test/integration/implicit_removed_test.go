// Implicit grant is removed (OAuth 2.1).

package integration

import (
	"context"
	"testing"

	"oauth-server/internal/domain"
)

func TestImplicitGrantRemoved(t *testing.T) {
	e := newEnv(t)

	// Try to create a client with implicit grant type - should be rejected
	client := &domain.Client{
		ClientID:                "implicit-test-app",
		ClientSecretHash:        nil,
		ClientName:              "Implicit Test",
		RedirectURIs:            []string{testRedirectURI},
		GrantTypes:              []string{"implicit"},
		ResponseTypes:           []string{"token"},
		Scopes:                  []string{"openid profile"},
		Contacts:                []string{},
		PostLogoutRedirectURIs:  []string{},
		TokenEndpointAuthMethod: "none",
		SubjectType:             "public",
	}

	if err := e.App.Deps.Clients.Create(context.Background(), client); err == nil {
		t.Error("implicit grant should have been rejected at client creation")
		return
	}
}
