package handlers

// POST /revoke — token revocation (RFC 7009).
//
// The entire security property of this endpoint is that its response is identical in
// every failure mode. It returns 200 whether the token existed, whether it belonged to
// the caller, or whether it was a valid token at all. Any distinguishable outcome turns
// revocation into an oracle for scanning tokens.

import (
	"net/http"

	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// Revoke handles token revocation.
func (d *Deps) Revoke(w http.ResponseWriter, r *http.Request) {
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
		// A missing required parameter is a malformed request, distinct from a token
		// that does not exist. Only the latter must be indistinguishable.
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "token is required"))
		return
	}

	// The hint only orders the lookup; it is never trusted to select the target. A
	// caller that labels a refresh token `access_token` must not be able to make the
	// server skip the refresh path and leave the token live.
	if err := flows.RevokeToken(
		r.Context(),
		client,
		token,
		d.Verifier,
		d.AccessToks,
		d.RefreshToks,
		d.Revoked,
	); err != nil {
		httpapi.OAuthError(w, oautherr.From(err))
		return
	}

	httpapi.JSON(w, http.StatusOK, map[string]any{})
}
