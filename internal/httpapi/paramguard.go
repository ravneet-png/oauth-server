package httpapi

// Request parameter validation.
//
// Three rules, all from the same source: RFC 6749 requires parameters to be exact, not
// approximately matched, and a server that is lenient about one of them is a server
// where a parametrised attack has somewhere to land.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrDuplicateParameter reports a parameter that appeared more than once.
//
// A duplicate is refused rather than resolved by taking the first or the last. Both
// choices are parametrised: a WAF or proxy in front of this server that inspects the
// first occurrence, while this server acts on the last, is a classic bypass.
var ErrDuplicateParameter = errors.New("httpapi: duplicate request parameter")

// ErrParameterTooLong reports a value over the configured cap.
var ErrParameterTooLong = errors.New("httpapi: request parameter is too long")

// DefaultMaxParameterLength caps a single parameter value.
//
// Generous for anything legitimate. A redirect_uri is the longest realistic value and
// tops out well under 2KB; a PKCE challenge is 43 characters. 8KB leaves room without
// letting a request body become a memory exhaustion vector.
const DefaultMaxParameterLength = 8192

// DefaultMaxFormMemory caps total parsed form size.
//
// 1MB. A token endpoint carrying client credentials has no legitimate need for more.
const DefaultMaxFormMemory = 1 << 20

// Guard validates request parameters.
type Guard struct {
	// MaxLength caps one parameter's value.
	MaxLength int

	// MaxFormMemory caps the parsed body.
	MaxFormMemory int64

	// allowedParams, when non-empty, is the set of accepted parameter names.
	allowedParams map[string]bool
}

// NewGuard builds a Guard.
func NewGuard() *Guard {
	return &Guard{
		MaxLength:     DefaultMaxParameterLength,
		MaxFormMemory: DefaultMaxFormMemory,
	}
}

// Only allows exactly these parameter names.
//
// Used on the token and authorize endpoints, where an unexpected parameter is either a
// typo or an attempt to smuggle a value past a proxy that filters known names.
func (g *Guard) Only(names ...string) *Guard {
	g.allowedParams = make(map[string]bool, len(names))
	for _, n := range names {
		g.allowedParams[n] = true
	}
	return g
}

// CheckQuery validates a request's query parameters.
func (g *Guard) CheckQuery(r *http.Request) error {
	values := r.URL.Query()
	for name, vals := range values {
		if len(vals) > 1 {
			return fmt.Errorf("%w: %s", ErrDuplicateParameter, name)
		}
		if err := g.checkValue(name, vals[0]); err != nil {
			return err
		}
		if g.allowedParams != nil && !g.allowedParams[name] {
			return fmt.Errorf("httpapi: unexpected parameter %q", name)
		}
	}
	return nil
}

// CheckForm parses and validates a form body.
//
// ParseForm is bounded by MaxFormMemory so a large Content-Length or a chunked body
// cannot be read unbounded into memory.
func (g *Guard) CheckForm(r *http.Request) error {
	if r.ContentLength > g.maxForm() {
		return fmt.Errorf("%w: body is %d bytes", ErrParameterTooLong, r.ContentLength)
	}

	if err := r.ParseMultipartForm(g.maxForm()); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return fmt.Errorf("httpapi: parse form: %w", err)
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("httpapi: parse form: %w", err)
	}

	for name, vals := range r.Form {
		if len(vals) > 1 {
			return fmt.Errorf("%w: %s", ErrDuplicateParameter, name)
		}
		if err := g.checkValue(name, vals[0]); err != nil {
			return err
		}
		if g.allowedParams != nil && !g.allowedParams[name] {
			return fmt.Errorf("httpapi: unexpected parameter %q", name)
		}
	}
	return nil
}

// maxForm returns the body cap, defaulting if unset.
func (g *Guard) maxForm() int64 {
	if g.MaxFormMemory <= 0 {
		return DefaultMaxFormMemory
	}
	return g.MaxFormMemory
}

// checkValue validates one parameter value's length.
func (g *Guard) checkValue(name, value string) error {
	limit := g.MaxLength
	if limit <= 0 {
		limit = DefaultMaxParameterLength
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrParameterTooLong, name, len(value), limit)
	}
	return nil
}

// RedirectURIMatchesExact compares a supplied redirect_uri against a registered one.
//
// Byte-for-byte, per RFC 6749 section 3.1.2.2. None of the customary relaxations are
// safe here:
//
//   - ignoring a trailing slash: /cb and /cb/ are different endpoints
//   - comparing case-insensitively: paths are case-sensitive
//   - ignoring default ports: :443 is not the same string as nothing
//   - normalising percent-encoding: %2f and / are the same character to some servers and
//     not others, which is exactly the ambiguity an attacker wants
//
// The only normalisation performed is stripping surrounding whitespace, because a
// copied URL routinely arrives with a trailing newline and the client's own
// registration cannot contain one.
func RedirectURIMatchesExact(registered, supplied string) bool {
	registered = strings.TrimSpace(registered)
	supplied = strings.TrimSpace(supplied)
	if registered == "" || supplied == "" {
		return false
	}
	return registered == supplied
}

// RedirectURIValid reports whether a redirect_uri is syntactically usable at all.
//
// Checked before comparison so a value like "not a url" is rejected as invalid_request
// rather than compared as a string that happens not to match. Without this, a
// syntactically invalid URI and a well-formed but unregistered one produce the same
// response, which is fine — but a malformed one that some downstream component tries to
// parse is not.
func RedirectURIValid(raw string) error {
	// Control characters are refused on the raw value, before parsing and before
	// trimming.
	//
	// url.Parse silently deletes ASCII tab, CR and LF from what it is given, so a
	// value carrying one arrives here looking clean and would be written into a
	// Location header with the newline intact. That is response splitting: the caller
	// controls the header terminator. Checking after parsing is too late because the
	// parse is what removed the evidence.
	if i := strings.IndexFunc(raw, isControlRune); i >= 0 {
		return fmt.Errorf("httpapi: redirect_uri contains a control character at byte %d", i)
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("httpapi: redirect_uri is empty")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("httpapi: redirect_uri does not parse: %w", err)
	}
	// RFC 6749 section 3.1.2 requires an absolute URI. A relative one would resolve
	// against this server, and a client following it lands on a page it does not own.
	if !u.IsAbs() {
		return errors.New("httpapi: redirect_uri must be absolute")
	}
	// A fragment is permitted (section 3.1.2 permits one for the response) but the URI
	// must have an authority.
	if u.Host == "" {
		return errors.New("httpapi: redirect_uri has no host")
	}
	if strings.ContainsAny(trimmed, "\r\n\t") {
		return errors.New("httpapi: redirect_uri contains a control character")
	}
	// javascript: and data: are absolute URIs with no host, so the check above already
	// excludes them; assert it here too, because the whole point is that this function
	// is where that judgement lives and it should not depend on url.Parse's behaviour.
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file":
		return fmt.Errorf("httpapi: redirect_uri scheme %q is not allowed", u.Scheme)
	}
	return nil
}

// isControlRune reports whether r is an ASCII control character or DEL.
//
// Deliberately narrower than unicode.IsControl: the value is destined for an HTTP header,
// and what must not appear there is the C0 range plus DEL. Treating, say, U+0085 as a
// control would reject addresses a user could legitimately have configured.
func isControlRune(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// ExtractRedirectURI pulls redirect_uri out of a request, preferring the form body.
//
// RFC 6749 section 3.1.2.1 says parameters MUST NOT be included in both the query and
// the fragment; some clients and most proxies send them in the query regardless of what
// the spec says, so the body is read first and the query is the fallback.
//
// A value present in both is rejected rather than one silently winning: the two
// disagreeing is either a bug or an attempt to have a proxy validate one while this
// server acts on the other.
func ExtractRedirectURI(r *http.Request) (string, error) {
	fromForm := r.PostFormValue("redirect_uri")
	fromQuery := r.URL.Query().Get("redirect_uri")

	switch {
	case fromForm != "" && fromQuery != "" && fromForm != fromQuery:
		return "", fmt.Errorf("%w: redirect_uri", ErrDuplicateParameter)
	case fromForm != "":
		return fromForm, nil
	default:
		return fromQuery, nil
	}
}
