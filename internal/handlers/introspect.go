package handlers

// POST /introspect — token introspection (RFC 7662).
//
// The caller is authenticated as a client and may introspect only tokens belonging to
// that client. The authorisation check lives in flows.IntrospectToken because it needs
// the token's own client_id claim; this file supplies the credential and renders the
// result.

import (
	"net/http"

	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// Introspect handles token introspection.
func (d *Deps) Introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	if !parseForm(r) {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "malformed request body"))
		return
	}

	client, err := d.ClientAuth.Authenticate(r.Context(), r)
	if err != nil {
		httpapi.OAuthError(w, oautherr.From(err).SuppressDescription())
		return
	}

	token := stringParam(r, "token")
	if token == "" {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "token is required"))
		return
	}

	resp, err := flows.IntrospectToken(
		r.Context(),
		client,
		token,
		d.Verifier,
		d.AccessToks,
		d.RefreshToks,
		d.Revoked,
		d.Users,
	)
	if err != nil {
		// A dependency failure is reported as such rather than as `active: false`.
		// The two are different: an inactive token is a definite answer, a failed
		// lookup is no answer at all, and collapsing them would let a resource server
		// reject a valid token because the database blipped.
		httpapi.OAuthError(w, oautherr.From(err))
		return
	}

	httpapi.JSON(w, http.StatusOK, resp)
}
