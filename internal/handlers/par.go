package handlers

// POST /par — the pushed authorization request endpoint (RFC 9126).
//
// The client authenticates, pushes the whole authorization request, and gets back a
// request_uri. The browser then presents only that reference. The point is that the
// authorization parameters are validated on a back channel, before a user is involved,
// so a malformed request is rejected without a redirect or a rendered page.

import (
	"net/http"

	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// PAR handles pushed authorization requests.
func (d *Deps) PAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	if !parseForm(r) {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "malformed request body"))
		return
	}

	// Client authentication is mandatory here. RFC 9126 section 2.1 requires it for
	// confidential clients and permits `none` only where PKCE still protects the flow;
	// the dispatcher enforces the client's registered method either way.
	client, err := d.ClientAuth.Authenticate(r.Context(), r)
	if err != nil {
		// Suppressed: a PAR endpoint that explains which half of a credential pair
		// was wrong is a client-secret oracle.
		httpapi.OAuthError(w, oautherr.From(err).SuppressDescription())
		return
	}

	// A client_id in the form that disagrees with the authenticated client is
	// refused rather than ignored: silently substituting the authenticated identity
	// would push a request attributed to a client the caller did not name.
	if supplied := stringParam(r, "client_id"); supplied != "" && supplied != client.ClientID {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "client_id does not match authenticated client"))
		return
	}

	// redirect_uri: the form value wins, but a query copy that disagreers is refused.
	redirectURI, _ := httpapi.ExtractRedirectURI(r)

	params := flows.PARParams{
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		ResponseType:        stringParam(r, "response_type"),
		Scope:               scopes(stringParam(r, "scope")),
		State:               optionalParam(r, "state"),
		Nonce:               optionalParam(r, "nonce"),
		CodeChallenge:       stringParam(r, "code_challenge"),
		CodeChallengeMethod: stringParam(r, "code_challenge_method"),
		Prompt:              scopes(stringParam(r, "prompt")),
		MaxAge:              optionalInt(r, "max_age"),
		LoginHint:           stringParam(r, "login_hint"),
	}

	requestURI, expiresIn, err := flows.HandlePAR(r.Context(), d.PARs, d.Clients, params, d.Config.PARTTL)
	if err != nil {
		httpapi.OAuthError(w, oautherr.From(err).WithIssuer(d.Config.Issuer))
		return
	}

	httpapi.JSON(w, http.StatusCreated, map[string]any{
		"request_uri": requestURI,
		"expires_in":  expiresIn,
	})
}
