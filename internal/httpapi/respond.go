package httpapi

// Response helpers.
//
// Every response an OAuth server writes carries no-store, because the endpoints here
// return tokens, and a cached token response is a token in a shared proxy. The headers
// are set in one place so no handler can forget them, which is the failure mode that
// produces a caching bug nobody finds until a token leaks.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"oauth-server/internal/domain"
	"oauth-server/internal/oautherr"
	"oauth-server/internal/ui"
)

// NoCacheHeaders sets the headers every response from this server must carry.
//
// RFC 6749 section 5.1 requires no-store on token responses specifically; it is applied
// universally here because these endpoints have no responses that benefit from caching,
// and a per-endpoint judgement is a chance to forget.
func NoCacheHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	// Stops an intermediary from storing a body even if it ignored no-store.
	h.Set("Expires", "0")
}

// JSON writes a JSON response with no-store headers.
func JSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Marshalling a map of strings should not fail. If it does, the value contains
		// something unencodable, and the client must not receive a half-written body
		// with a 200.
		ServerError(w)
		return
	}

	NoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// TokenResponse writes an OAuth token response.
//
// Deliberately not a struct: the field set differs by grant, and RFC 6749 says a
// response must omit optional fields it does not use rather than send them empty. A
// struct with omitempty on every field gets that right, and a map gets it right without
// a compile error when a field is misnamed.
func TokenResponse(w http.ResponseWriter, status int, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	// access_token_type is required by RFC 6749 section 5.1 even when everything else
	// is optional. Set here so no handler can produce a token response without it.
	if _, ok := fields["token_type"]; !ok {
		fields["token_type"] = "Bearer"
	}
	JSON(w, status, fields)
}

// OAuthError writes a protocol error as JSON.
//
// Used on every endpoint that does not redirect: /token, /revoke, /introspect,
// /userinfo, /par, discovery and JWKS.
func OAuthError(w http.ResponseWriter, err *oautherr.Error) {
	e := oautherr.From(err)
	if e == nil {
		ServerError(w)
		return
	}

	body := map[string]string{"error": e.Code()}
	// Description is omitted when suppressed, not sent empty. An empty
	// error_description is still a field the client will display.
	if d := e.Description(); d != "" {
		body["error_description"] = d
	}

	NoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// invalid_client gets 401 with a challenge; RFC 6749 section 5.2 is specific, and
	// a 400 makes clients retry a credential failure as an authorization problem.
	status := e.Status()
	if oautherr.IsAuthenticationFailure(e) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		status = http.StatusUnauthorized
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ErrorFrom writes err as an OAuth error response.
//
// The form handlers call after any internal failure. Anything that is not already an
// OAuth error becomes an opaque server_error: a flow function that returns a bare
// database error must not have its text forwarded to a client.
func ErrorFrom(w http.ResponseWriter, err error) {
	OAuthError(w, oautherr.From(err))
}

// ServerError writes a 500 in the OAuth error shape.
//
// Used for failures that are this server's fault. The description is always the same
// string: a specific message about what broke internally is a map of the system.
func ServerError(w http.ResponseWriter) {
	OAuthError(w, oautherr.New(domain.NewServerError("internal server error")))
}

// RedirectError sends a browser to a client with OAuth error parameters.
//
// Only ever called after the redirect_uri has been validated against the client's
// registration. Redirecting to an unvalidated URI is the open-redirect primitive, and
// it is why the validation lives in the flow rather than here.
//
// state is echoed so the client can correlate the response with its request.
func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err *oautherr.Error) {
	target, buildErr := ErrorRedirectURL(redirectURI, state, err)
	if buildErr != nil {
		// The redirect_uri we were about to use does not parse. That is a server-side
		// inconsistency, and following the redirect anyway would send an OAuth error
		// to an unvalidated target — the exact failure this function exists to avoid.
		ServerError(w)
		return
	}

	NoCacheHeaders(w)
	http.Redirect(w, r, target, http.StatusFound)
}

// ErrorRedirectURL builds the error redirect URL without performing it.
//
// Exposed separately because the /authorize handler needs the URL for its tests, and
// because building it in one place means the query encoding is right everywhere.
func ErrorRedirectURL(redirectURI, state string, err *oautherr.Error) (string, error) {
	if redirectURI == "" {
		return "", errors.New("httpapi: ErrorRedirectURL: redirect URI is empty")
	}

	base, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		return "", parseErr
	}
	// A fragment must be preserved as a fragment, never merged into the query. RFC 6749
	// section 3.1.2 permits a registered redirect_uri to carry one, and moving it into
	// the query changes where the client looks for the code.
	fragment := base.Fragment

	q := base.Query()
	for _, p := range oautherr.From(err).Query(state, redirectURI) {
		q.Set(p.Key, p.Value)
	}
	base.RawQuery = q.Encode()
	base.Fragment = fragment

	return base.String(), nil
}

// FormRedirect sends a browser to a local path.
//
// For redirects within this server — post-login, post-consent — where the target is a
// server-side identifier rather than anything the client supplied.
func FormRedirect(w http.ResponseWriter, r *http.Request, target string) {
	NoCacheHeaders(w)
	http.Redirect(w, r, target, http.StatusFound)
}

// SeeOther is a POST-completion redirect.
//
// 303 rather than 302: after a POST the browser must not repeat the request on a
// refresh, and a 302 on a POST is resubmitted by several browsers. That turns a
// one-time login or consent form into a form that fires twice.
func SeeOther(w http.ResponseWriter, r *http.Request, target string) {
	NoCacheHeaders(w)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// NotFoundRedirect sends a browser to a 404 page.
func NotFoundRedirect(w http.ResponseWriter, r *http.Request, notFoundPath string) {
	SeeOther(w, r, notFoundPath)
}

// RenderPage writes an HTML page through the UI renderer.
//
// A thin pass-through so handlers depend on httpapi rather than reaching into ui, and so
// a handler that forgets no-store on an HTML page is still safe.
func RenderPage(w http.ResponseWriter, renderer *ui.Renderer, page string, status int, data any) {
	if err := ui.RenderPage(w, renderer, page, status, data); err != nil {
		// The renderer buffers, so nothing has been written yet and a 500 is still
		// possible. If this fails the connection is broken; there is nothing better to
		// do than return.
		ServerError(w)
	}
}

// WithRetryAfter sets Retry-After and writes a 429.
func WithRetryAfter(w http.ResponseWriter, seconds int) {
	if seconds < 1 {
		// A Retry-After of 0 tells the client to retry immediately, which for a limit
		// means it comes straight back and is refused again.
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}

// MethodNotAllowed writes a 405 with a correct Allow header.
//
// 405 rather than an OAuth 400, because the request is well formed and the wrong verb
// is not a condition RFC 6749 section 5.2 has an error code for. A client
// branching on 400 to retry with a different method is following the status code, and
// `invalid_request` invites exactly that. RFC 9110 section 15.5.6 requires the status
// and the Allow header together, which is why the body still carries the OAuth shape:
// the endpoint is still an OAuth endpoint and generic clients parse that body.
//
// RFC 9207 `iss` is deliberately absent here. That parameter identifies the issuer on a
// response delivered to a redirect_uri; a 405 carries no redirect, so there is no
// relying party for it to disambiguate.
func MethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	e := oautherr.New(domain.NewInvalidRequest("method not allowed"))

	body := map[string]string{"error": e.Code()}
	if d := e.Description(); d != "" {
		body["error_description"] = d
	}

	NoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_ = json.NewEncoder(w).Encode(body)
}
