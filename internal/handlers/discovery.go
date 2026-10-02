package handlers

// GET /.well-known/openid-configuration — OIDC discovery.
//
// A public document. Every URL it advertises must be the URL the corresponding handler
// actually serves, which is why the endpoints are assembled from one Config rather than
// written as literals here: a discovery document that disagrees with the server it
// describes sends clients to a 404 and is discovered only by an integrator.

import (
	"net/http"

	"oauth-server/internal/httpapi"
)

// Discovery handles the OpenID Provider metadata document.
func (d *Deps) Discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}

	c := d.Config
	doc := map[string]any{
		"issuer":                 c.Issuer,
		"authorization_endpoint": c.AuthorizationEndpoint,
		"token_endpoint":         c.TokenEndpoint,
		"userinfo_endpoint":      c.UserInfoEndpoint,
		"jwks_uri":               c.JWKSURI,
		"revocation_endpoint":    c.RevocationEndpoint,
		"introspection_endpoint": c.IntrospectionEndpoint,

		"response_types_supported": []string{"code"},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		},
		"code_challenge_methods_supported": []string{"S256"},
		"scopes_supported":                 []string{"openid", "email", "profile", "offline_access"},
		"claims_supported":                 []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name"},
		"response_modes_supported":         []string{"query"},

		"pushed_authorization_request_endpoint": c.PAREndpoint,
		"end_session_endpoint":                  c.EndSessionEndpoint,

		"backchannel_logout_supported":         true,
		"backchannel_logout_session_supported": true,
	}

	if c.ClientRegistrationEnabled {
		doc["registration_endpoint"] = c.RegistrationEndpoint
	}

	httpapi.JSON(w, http.StatusOK, doc)
}
