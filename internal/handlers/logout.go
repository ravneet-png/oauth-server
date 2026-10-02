package handlers

// GET and POST /logout — RP-initiated and session-scoped logout.
//
// Two entry points with deliberately different trust models. GET is browser navigation
// from a client and carries an id_token_hint that may authorise a redirect back to that
// client; POST is a direct API call authenticated by the session cookie alone. Neither
// revokes anything belonging to another session.

import (
	"net/http"

	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/middleware"
	"oauth-server/internal/ui"
)

// Logout handles logout.
func (d *Deps) Logout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.logoutRP(w, r)
	case http.MethodPost:
		d.logoutSession(w, r)
	default:
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// logoutRP handles RP-initiated logout (GET /logout).
func (d *Deps) logoutRP(w http.ResponseWriter, r *http.Request) {
	if !parseForm(r) {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}

	sessionID := ""
	if s := sessionOf(r); s != nil {
		sessionID = s.SessionID
	}

	redirectURL, err := flows.LogoutRP(
		r.Context(),
		stringParam(r, "id_token_hint"),
		stringParam(r, "post_logout_redirect_uri"),
		stringParam(r, "state"),
		sessionID,
		d.Verifier,
		d.Sessions,
		d.Clients,
		d.LogoutBldr,
		d.AccessToks,
		d.RefreshToks,
		d.Revoked,
		d.Audit,
		d.ClientSess,
		d.Backchannel,
	)
	if err != nil {
		// A hint that does not verify, or a redirect target we may not honour, must not
		// become a redirect — but it must also not become a failed logout. The session
		// is ended locally and a confirmation page is rendered, which is exactly the
		// "client could not be identified" behaviour the API describes.
		d.Logger.Warn("logout: rp-initiated logout fell back to local confirmation",
			"error", err.Error(), "correlation_id", d.state(r).correlationID)
		if sessionID != "" {
			if lerr := d.performLogout(r, sessionID); lerr != nil {
				d.Logger.Error("logout: session logout", "error", lerr.Error(), "correlation_id", d.state(r).correlationID)
			}
		}
		middleware.ClearSessionCookie(w, d.Config.SessionCookieSecure)
		d.renderLoggedOut(w, r)
		return
	}

	if redirectURL != "" {
		// The redirect target was validated against the client identified by the hint.
		httpapi.FormRedirect(w, r, redirectURL)
		return
	}

	if sessionID != "" {
		middleware.ClearSessionCookie(w, d.Config.SessionCookieSecure)
	}
	d.renderLoggedOut(w, r)
}

// logoutSession handles session-scoped logout (POST /logout).
func (d *Deps) logoutSession(w http.ResponseWriter, r *http.Request) {
	st := d.state(r)
	if st.sessionID != "" {
		if err := d.performLogout(r, st.sessionID); err != nil {
			d.Logger.Error("logout: session logout", "error", err.Error(), "correlation_id", st.correlationID)
			d.renderError(w, r, http.StatusInternalServerError, "server_error")
			return
		}
	}
	// Clear the cookie whether or not a session was found: a client that calls /logout
	// to discard a stale cookie should get one that is actually gone.
	middleware.ClearSessionCookie(w, d.Config.SessionCookieSecure)
	w.WriteHeader(http.StatusNoContent)
}

// performLogout revokes the session's tokens and deletes the session.
func (d *Deps) performLogout(r *http.Request, sessionID string) error {
	return flows.Logout(
		r.Context(),
		sessionID,
		d.Sessions,
		d.ClientSess,
		d.AccessToks,
		d.RefreshToks,
		d.Revoked,
		d.Audit,
		d.Clients,
		d.LogoutBldr,
		d.Backchannel,
	)
}

// renderLoggedOut renders the post-logout confirmation page.
func (d *Deps) renderLoggedOut(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, ui.PageLoggedOut, http.StatusOK, ui.LoggedOutData{
		Base:     d.base(r, "Signed out"),
		LoginURL: "/login",
	})
}
