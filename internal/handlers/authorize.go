package handlers

// GET /authorize — the OAuth 2.1 authorization endpoint.
//
// This handler's job is small and its failure modes are large. It parses the request,
// asks flows.HandleAuthorize whether the request is coherent, and then routes to the
// next screen. The interesting part is that it is the one endpoint where an error may
// be delivered to a *third party* — the client's redirect_uri — and only after that URI
// has been validated against the client's registration. Delivering an error anywhere
// else is an open redirect (API.md, endpoint class "redirect-bearing").

import (
	"net/http"
	"net/url"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/flows"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
)

// Authorize handles authorization requests.
//
// Handles both the query-string form and the PAR form. In the PAR form the query
// carries only request_uri (and optionally client_id); everything else was validated at
// /par and is read from the stored copy by flows.HandleAuthorize.
func (d *Deps) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}
	if !parseForm(r) {
		d.renderError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}

	// extraParams is every query parameter other than request_uri itself. Predictable
	// ordering is not needed; the flow only checks membership.
	requestURI := r.URL.Query().Get("request_uri")
	var extraParams []string
	if requestURI != "" {
		for name := range r.URL.Query() {
			if name != "request_uri" {
				extraParams = append(extraParams, name)
			}
		}
	}

	clientID := stringParam(r, "client_id")
	// The client is looked up before the flow so the redirect policy can be built from
	// the *registered* URIs. An unknown client has no policy, so its error is local.
	client, clientErr := d.Clients.GetByID(r.Context(), clientID)

	// redirect_uri extraction refuses a form/query disagreement rather than choosing.
	suppliedRedirect, _ := httpapi.ExtractRedirectURI(r)
	state, statePresent := stringParamPresent(r, "state")
	var statePtr *string
	if statePresent {
		statePtr = &state
	}

	params := flows.Params{
		ClientID:            clientID,
		RedirectURI:         suppliedRedirect,
		ResponseType:        stringParam(r, "response_type"),
		Scope:               scopes(stringParam(r, "scope")),
		State:               statePtr,
		Nonce:               optionalParam(r, "nonce"),
		CodeChallenge:       stringParam(r, "code_challenge"),
		CodeChallengeMethod: stringParam(r, "code_challenge_method"),
		Prompt:              scopes(stringParam(r, "prompt")),
		MaxAge:              optionalInt(r, "max_age"),
		LoginHint:           stringParam(r, "login_hint"),
	}

	// A session, if any, comes from the session middleware. A nil session stays nil:
	// the flow distinguishes "no session" from "empty session id" and sends the former
	// to login. auth_time is passed separately because max_age compares against it.
	var sessionID *string
	var sessionUserID *string
	var sessionAuthTime *time.Time
	if s := sessionOf(r); s != nil {
		id := s.SessionID
		sessionID = &id
		uid := s.UserID
		sessionUserID = &uid
		at := s.AuthTime
		sessionAuthTime = &at
	}

	authReqID, nextStep, err := flows.HandleAuthorize(
		r.Context(),
		d.AuthReqs,
		d.PARs,
		d.Clients,
		sessionID,
		sessionUserID,
		sessionAuthTime,
		requestURI,
		extraParams,
		params,
		d.Config.AuthReqTTL,
	)
	if err != nil {
		d.authorizeError(w, r, client, clientErr, suppliedRedirect, state, err)
		return
	}

	// The request is live and owned by this server. Route to the next screen with a
	// 303: the browser's method on the original request is not the method for the next
	// one, and a 302 would let a user agent replay GET /authorize as GET /login which
	// looks harmless and discards the method contract.
	switch nextStep {
	case string(domain.NextStepLogin):
		httpapi.SeeOther(w, r, "/login?auth_request_id="+url.QueryEscape(authReqID))
	case string(domain.NextStepConsent):
		httpapi.SeeOther(w, r, "/consent?auth_request_id="+url.QueryEscape(authReqID))
	case string(domain.NextStepMFA):
		httpapi.SeeOther(w, r, "/mfa?auth_request_id="+url.QueryEscape(authReqID))
	default:
		// An unrecognised next step is a server inconsistency, not a client error.
		d.renderError(w, r, http.StatusInternalServerError, "server_error")
	}
}

// authorizeError delivers an authorization error to the right place.
//
// The rule, once, in one function: if the redirect_uri is valid for the client, the
// error goes to the client as query parameters and the response is a redirect; otherwise
// the error is rendered locally and the redirect target is never contacted. A handler
// that got this wrong in either direction would either break the client or hand an
// attacker a redirect to an arbitrary URI.
func (d *Deps) authorizeError(
	w http.ResponseWriter,
	r *http.Request,
	client *domain.Client,
	clientErr error,
	suppliedRedirect, state string,
	err error,
) {
	oe := oautherr.From(err).WithIssuer(d.Config.Issuer)

	// Redirect only when all three hold: the client is known, its registration lists
	// this exact URI, and the URI is structurally usable. The structural check happens
	// in RedirectURIValid; a URI that parses but is not registered still fails the
	// second condition.
	if target, ok := validRedirectFor(client, clientErr, suppliedRedirect); ok {
		httpapi.RedirectError(w, r, target, state, oe)
		return
	}

	// No valid target. Render locally. The status is the error's own status (401 for
	// invalid_client, 400 for the rest), so a developer sees a meaningful code without
	// the operator having to correlate a log line.
	d.renderError(w, r, oe.Status(), oe.Code())
}

// validRedirectFor reports whether an error may be redirected to supplied.
//
// The three conditions are all required and each rules out a different mistake: the
// client must be known (otherwise there is no registration to check against), the URI
// must be structurally usable (a malformed target must not reach the Location header),
// and it must match the registration exactly. The middle check is done first so a
// malformed URI is never even compared as a string, which would let a value that
// happens to equal a registration byte-for-byte but does not parse through.
func validRedirectFor(client *domain.Client, clientErr error, supplied string) (string, bool) {
	if client == nil || clientErr != nil || supplied == "" {
		return "", false
	}
	if err := httpapi.RedirectURIValid(supplied); err != nil {
		return "", false
	}
	if !client.RedirectURIAllowed(supplied) {
		return "", false
	}
	return supplied, true
}
