// OAuth 2.1 and OIDC error responses. A leaf package with no internal imports, so handlers build these directly and middleware renders them without importing handler code.

package oautherr

import (
	"errors"
	"fmt"
	"net/http"

	"oauth-server/internal/domain"
)

// OAuth error and response parameter names, per RFC 6749 section 4.1.2.1 and
// section 5.2. Defined here rather than imported so the leaf package stays free of
// internal imports, and so a rename cannot silently alter wire output: these strings
// are the contract with clients.
const (
	ParamError            = "error"
	ParamErrorDescription = "error_description"
	ParamErrorURI         = "error_uri"
	ParamState            = "state"

	// ParamIssuer is the RFC 9207 authorization server issuer identifier.
	ParamIssuer = "iss"
)

// Error is an OAuth protocol error.
//
// It is a thin wrapper over domain.OAuthError rather than a replacement, so the
// error code vocabulary has exactly one definition. What this type adds is the
// rendering concern: an OAuth error's correct presentation depends on where it
// happens, and getting that wrong is how `error` and `error_description` end up
// in a redirect or a JSON body where RFC 6749 forbids them.
type Error struct {
	err *domain.OAuthError

	// suppressDescription keeps the human-readable text out of the response.
	//
	// Needed for client authentication failures on the token endpoint. RFC 6749
	// section 5.2 requires the description to identify what the client must fix,
	// and equally requires that a *failed* authentication not reveal which half of
	// the credentials was wrong, because that turns the endpoint into an oracle for
	// enumerating client secrets. "invalid client" is the whole answer the RFC
	// permits there.
	suppressDescription bool

	// issuer is the value of the RFC 9207 `iss` response parameter.
	//
	// Held here rather than passed alongside the error so that every rendering
	// surface picks it up from one place. RFC 9207 section 2 requires `iss` on the
	// error response as well as the success response, and an error that omits it is
	// the exact case a mix-up attack relies on: the client sees a well-formed error
	// and has no way to tell it came from the wrong issuer.
	issuer string
}

// WithIssuer attaches the RFC 9207 `iss` parameter to an error redirect.
//
// Returns a copy, so the shared sentinel errors in domain can be reused across
// requests without one request's issuer leaking into another's.
func (e *Error) WithIssuer(issuer string) *Error {
	if e == nil {
		return nil
	}
	c := *e
	c.issuer = issuer
	return &c
}

// Issuer returns the RFC 9207 issuer, or "" when unset.
func (e *Error) Issuer() string {
	if e == nil {
		return ""
	}
	return e.issuer
}

// New wraps a domain OAuth error.
func New(err *domain.OAuthError) *Error {
	if err == nil {
		return nil
	}
	return &Error{err: err}
}

// Newf wraps a domain OAuth error with a formatted description.
func Newf(code string, format string, args ...any) *Error {
	return New(domain.NewOAuthError(code, fmt.Sprintf(format, args...)))
}

// SuppressDescription returns a copy that will not expose its description to the
// client. Use for anything reachable before authentication succeeds.
func (e *Error) SuppressDescription() *Error {
	if e == nil {
		return nil
	}
	c := *e
	c.suppressDescription = true
	return &c
}

// Code returns the RFC error code, e.g. "invalid_grant".
func (e *Error) Code() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Code
}

// Description returns the human-readable description, or "" when suppressed.
func (e *Error) Description() string {
	if e == nil || e.err == nil || e.suppressDescription {
		return ""
	}
	return e.err.Description
}

// Status returns the HTTP status this error should produce on a direct (non-redirect)
// response.
func (e *Error) Status() int {
	if e == nil || e.err == nil {
		return http.StatusInternalServerError
	}
	return e.err.HTTPStatus
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil || e.err == nil {
		return "<nil oautherr.Error>"
	}
	return e.err.Code
}

// Unwrap exposes the underlying domain error for errors.Is/As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// From extracts an *Error from err, or synthesises a server_error.
//
// The synthesised default is deliberate: this is called on the error path of every
// handler, and a nil return there would mean writing a 200 with an empty body for an
// operation that failed. Anything reaching here that is not already an OAuth error is
// a bug, and the client gets an opaque server_error while the log gets the real
// error.
func From(err error) *Error {
	if err == nil {
		return nil
	}

	var oe *Error
	if errors.As(err, &oe) {
		return oe
	}

	var de *domain.OAuthError
	if errors.As(err, &de) {
		return New(de)
	}

	return New(domain.NewServerError("internal error"))
}

// IsAuthenticationFailure reports whether err is an invalid_client.
//
// Used by the token endpoint to decide between 401 with a WWW-Authenticate header
// and a plain 400. RFC 6749 section 5.2 is specific: invalid_client gets a 401,
// everything else gets a 400, and conflating them makes clients retry a
// non-retryable credential failure as if it were an authorization problem.
func IsAuthenticationFailure(err error) bool {
	var oe *domain.OAuthError
	if errors.As(err, &oe) && oe.Code == domain.ErrCodeInvalidClient {
		return true
	}
	return false
}

// Param is a single key/value pair for an error redirect query string.
type Param struct {
	Key   string
	Value string
}

// Query renders an OAuth error as redirect query parameters for a
// `response_type` of anything but `code`.
//
// The error parameters go in the query string, not a fragment. RFC 6749 section
// 4.1.2.1 says the fragment is for the authorization *response*; an error carrying
// `state` still has to be delivered where the client will read it, and the client
// only parses the query by convention.
func (e *Error) Query(state string, redirectURI string) []Param {
	if e == nil || e.err == nil {
		return nil
	}
	params := []Param{{Key: ParamError, Value: e.Code()}}
	if d := e.Description(); d != "" {
		params = append(params, Param{Key: ParamErrorDescription, Value: d})
	}
	// state is echoed only when non-empty.
	//
	// Echoing an empty state writes `state=` into the redirect, and a client
	// comparing its round-tripped state byte-for-byte will fail. Absence and empty
	// are different values to that comparison, and the spec requires echoing the
	// value "if one was present in the request".
	if state != "" {
		params = append(params, Param{Key: ParamState, Value: state})
	}
	// iss last, so the parameter order in the rendered URL is error, description,
	// state, iss. Order is not normative, but a stable order makes the URLs
	// comparable in a test without parsing them.
	if e.issuer != "" {
		params = append(params, Param{Key: ParamIssuer, Value: e.issuer})
	}
	return params
}
