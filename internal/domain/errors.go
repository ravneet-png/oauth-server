// Error sentinels and the internal error taxonomy. Does not import oautherr;
// oautherr depends on this package so that crypto, tokens and storage can
// construct typed errors without pulling in HTTP concerns.

package domain

import (
	"errors"
	"fmt"
	"net/http"
)

// OAuth error codes.
//
// RFC 6749 section 5.2 defines the first block. OpenID Connect Core 1.0
// section 3.1.2.6 adds the interaction codes. RFC 9068 adds
// unsupported_token_type, which is what a resource server must return when a
// token is not a JWT it can validate locally.
//
// The type name is what the HTTP layer marshals, so the set of codes is closed
// by this constant block rather than by string literals scattered across the
// codebase.
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeInvalidToken            = "invalid_token"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeServerError             = "server_error"
	ErrCodeTemporarilyUnavailable  = "temporarily_unavailable"

	// OpenID Connect Core 1.0, section 3.1.2.6.
	ErrCodeLoginRequired       = "login_required"
	ErrCodeConsentRequired     = "consent_required"
	ErrCodeInteractionRequired = "interaction_required"

	// RFC 9068, section 2.1.
	ErrCodeUnsupportedTokenType = "unsupported_token_type"
)

// OAuthError is the wire representation of a protocol error.
//
// HTTPStatus is deliberately not serialised. The status is a property of how the
// error is delivered, and one code can be delivered two ways: `access_denied`
// from /authorize is normally a 302 carrying the code as a query parameter,
// because returning 403 would render the error on the authorization server's
// origin instead of the client's. The same code returned from /token is a 403
// JSON body. Binding the status into the error would force one of the two to
// be wrong.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`

	// HTTPStatus is the status to use when this error is the response body of a
	// token or revocation endpoint. Not part of the JSON body.
	HTTPStatus int `json:"-"`
}

// Error implements the error interface.
//
// The description is included deliberately. An OAuthError reaching a log is
// almost always a bug being diagnosed, and the code alone ("invalid_grant")
// identifies no cause at all. Descriptions must never contain secrets; they
// are returned to the client verbatim, so this is also the place a careless
// implementation leaks a token or an email address.
func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// WithDescription returns a copy carrying desc. Returning a copy rather than
// mutating means an error shared across goroutines cannot be rewritten by
// another caller.
func (e *OAuthError) WithDescription(desc string) *OAuthError {
	clone := *e
	clone.Description = desc
	return &clone
}

// WithURI returns a copy pointing at a human-readable description of the code.
// The URI is documentation, not a callback.
func (e *OAuthError) WithURI(uri string) *OAuthError {
	clone := *e
	clone.URI = uri
	return &clone
}

// NewOAuthError builds an error for a code, using that code's canonical status.
// Useful for codes that are not worth a dedicated constructor.
func NewOAuthError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description, HTTPStatus: statusForCode(code)}
}

// statusForCode is the single source of truth for the default status of each
// code. The constructors below are preferred where they exist; this exists so
// that NewOAuthError cannot invent a status.
func statusForCode(code string) int {
	switch code {
	case ErrCodeInvalidClient:
		// RFC 6749 5.2: the client failed to authenticate. 401, and the
		// response must carry a WWW-Authenticate header.
		return http.StatusUnauthorized
	case ErrCodeInvalidToken:
		// RFC 6750: an invalid bearer credential is an authentication failure.
		return http.StatusUnauthorized
	case ErrCodeAccessDenied:
		return http.StatusForbidden
	case ErrCodeServerError:
		return http.StatusInternalServerError
	case ErrCodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// NewInvalidRequest reports a malformed or otherwise unusable request.
func NewInvalidRequest(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeInvalidRequest, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewInvalidClient reports a client that failed to authenticate, or an
// `client_id` that is unknown. These are deliberately indistinguishable to the
// caller: distinguishing them tells an attacker which client IDs are real.
func NewInvalidClient(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeInvalidClient, Description: desc, HTTPStatus: http.StatusUnauthorized}
}

// NewInvalidGrant reports an invalid, expired, revoked or already-used grant.
// Covers authorization codes and refresh tokens.
func NewInvalidGrant(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeInvalidGrant, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewUnauthorizedClient reports an authenticated client that is not permitted to
// use the requested grant type. Distinct from invalid_client: the credentials
// were fine, the authorisation was not.
func NewUnauthorizedClient(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeUnauthorizedClient, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewUnsupportedGrantType reports a grant type the server does not implement,
// including the implicit and password grants that OAuth 2.1 removed.
func NewUnsupportedGrantType(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeUnsupportedGrantType, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewInvalidScope reports scopes that are malformed, unknown, or not permitted
// for this client.
func NewInvalidScope(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeInvalidScope, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewServerError reports an unexpected condition. The description is for the
// log; the client should receive an opaque message.
func NewServerError(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeServerError, Description: desc, HTTPStatus: http.StatusInternalServerError}
}

// NewTemporarilyUnavailable reports overload or maintenance. Safe to retry.
func NewTemporarilyUnavailable(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeTemporarilyUnavailable, Description: desc, HTTPStatus: http.StatusServiceUnavailable}
}

// NewAccessDenied reports that the resource owner or the server refused the
// request. From /authorize this is normally delivered as a redirect parameter,
// not as this status.
func NewAccessDenied(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeAccessDenied, Description: desc, HTTPStatus: http.StatusForbidden}
}

// NewUnsupportedResponseType reports a response_type other than code.
func NewUnsupportedResponseType(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeUnsupportedResponseType, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewLoginRequired reports that the request needs end-user interaction that
// silent authentication cannot supply, per prompt or max_age.
func NewLoginRequired(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeLoginRequired, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewConsentRequired reports that the request needs a consent prompt the server
// cannot show during a back-channel request.
func NewConsentRequired(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeConsentRequired, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewInteractionRequired reports that the request needs interaction, and that
// none of login_required, consent_required or account_selection_required
// applies specifically.
func NewInteractionRequired(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeInteractionRequired, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// NewUnsupportedTokenType reports a token the resource server cannot validate,
// per RFC 9068.
func NewUnsupportedTokenType(desc string) *OAuthError {
	return &OAuthError{Code: ErrCodeUnsupportedTokenType, Description: desc, HTTPStatus: http.StatusBadRequest}
}

// Internal sentinel errors. These are NOT serialised and never reach a client;
// the HTTP layer translates them into one of the OAuthError codes above or into
// a 500. Storage returns them so that callers can distinguish "no such row" from
// "the database is unreachable", which a bare error string cannot.

// ErrNotFound means the row does not exist. For single-use consumption it also
// covers the case where the row existed and has already been consumed, because
// the two are indistinguishable from outside and must not be.
var ErrNotFound = errors.New("domain: not found")

// ErrConflict means a uniqueness constraint rejected the write.
var ErrConflict = errors.New("domain: conflict")

// ErrAlreadyConsumed means a single-use row was presented a second time. This
// is the signal that triggers token family revocation, so it is deliberately
// distinct from ErrNotFound: a caller must not be able to confuse "never
// existed" with "already used".
var ErrAlreadyConsumed = errors.New("domain: already consumed")

// ErrExpired means the row is past its expiry.
var ErrExpired = errors.New("domain: expired")

// ErrNoActiveKey means the signing_keys table holds no active key for the
// configured algorithm, so the server cannot sign. Fatal at boot.
var ErrNoActiveKey = errors.New("domain: no active signing key")

// ErrDisabled means the client or user has been administratively disabled.
var ErrDisabled = errors.New("domain: disabled")

// AsOAuthError extracts an *OAuthError from an error chain, reporting whether
// one was present. Used by the HTTP error middleware so that internal errors
// become an opaque server_error instead of leaking their text.
func AsOAuthError(err error) (*OAuthError, bool) {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr, true
	}
	return nil, false
}

// Wrapf annotates err with context while preserving the sentinel, so that
// errors.Is and errors.As still work through the wrap.
func Wrapf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
}
