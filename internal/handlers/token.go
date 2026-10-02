package handlers

// POST /token — the token endpoint, all three grants.
//
// One endpoint, one client-authentication step, then a dispatch on grant_type. The
// grant implementations live in internal/flows; this file is deliberately thin because
// the token endpoint is where a handler that "just does a bit of validation" becomes the
// place authorization bypasses are found.

import (
	"net/http"

	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// Token handles token requests.
func (d *Deps) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	// The body must be parsed before client authentication: client_secret_post and
	// private_key_jwt carry their credentials in *this* form.
	if !parseForm(r) {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "malformed request body"))
		return
	}

	client, err := d.ClientAuth.Authenticate(r.Context(), r)
	if err != nil {
		httpapi.OAuthError(w, oautherr.From(err).SuppressDescription())
		return
	}

	grantType := stringParam(r, "grant_type")
	if grantType == "" {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "grant_type is required"))
		return
	}

	var resp *flows.TokenResponse
	switch grantType {
	case "authorization_code":
		resp, err = flows.ExchangeAuthorizationCode(
			r.Context(),
			client,
			stringParam(r, "code"),
			stringParam(r, "code_verifier"),
			stringParam(r, "redirect_uri"),
			d.Codes,
			d.AccessToks,
			d.RefreshToks,
			d.Families,
			d.Revoked,
			d.Users,
			d.Audit,
			d.AccessBldr,
			d.IDBldr,
			d.Config.AccessTTL,
			d.Config.RefreshTTL,
			d.Config.IDTTL,
			d.Config.RefreshAbsoluteTTL,
			d.Config.TokenEndpoint,
		)
	case "refresh_token":
		resp, err = flows.ExchangeRefreshToken(
			r.Context(),
			client,
			stringParam(r, "refresh_token"),
			d.RefreshToks,
			d.AccessToks,
			d.Revoked,
			d.Audit,
			d.AccessBldr,
			d.Config.AccessTTL,
			d.Config.RefreshTTL,
			d.Config.TokenEndpoint,
		)
	case "client_credentials":
		resp, err = flows.ExchangeClientCredentials(
			r.Context(),
			client,
			scopes(stringParam(r, "scope")),
			d.AccessToks,
			d.Audit,
			d.AccessBldr,
			d.Config.ClientCredTTL,
			d.Config.TokenEndpoint,
		)
	default:
		// implicit and password land here too, which is the whole point: there is no
		// branch for them, so there is no code path to reach them.
		httpapi.OAuthError(w, oautherr.Newf("unsupported_grant_type", "grant_type %q is not supported", grantType))
		return
	}

	if err != nil {
		// A server_error reached the client as an opaque code; the reason it is opaque
		// is exactly why it must be logged here. Without this, a database fault in the
		// grant is indistinguishable from a genuinely invalid request, and the only
		// place the distinction existed was a stack that has already returned.
		oauthErr := oautherr.From(err)
		if oauthErr.Code() == "server_error" {
			d.Logger.Error("token: grant failed",
				"grant_type", grantType,
				"client_id", client.ClientID,
				"error", err.Error(),
				"correlation_id", d.state(r).correlationID,
			)
		}
		httpapi.OAuthError(w, oauthErr)
		return
	}

	// Build the response, omitting absent members.
	//
	// A refresh_token key with an empty value is not the same as no refresh_token key:
	// a client checking `if "refresh_token" in response` would try to use an empty
	// string. Only present values are written.
	fields := map[string]any{
		"access_token": resp.AccessToken,
		"expires_in":   resp.ExpiresIn,
	}
	if resp.RefreshToken != "" {
		fields["refresh_token"] = resp.RefreshToken
	}
	if resp.IDToken != "" {
		fields["id_token"] = resp.IDToken
	}
	if resp.Scope != "" {
		fields["scope"] = resp.Scope
	}
	httpapi.TokenResponse(w, http.StatusOK, fields)
}
