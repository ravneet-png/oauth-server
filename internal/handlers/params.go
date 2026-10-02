package handlers

// Request parameter reading, shared by every handler in the package.
//
// Redirect building deliberately lives in internal/httpapi rather than here: the
// fragment-preserving query merge is already implemented and tested there, and a second
// copy is a second set of bugs. What this file adds is the *parsing* discipline.

import (
	"net/http"
	"strconv"
	"strings"

	"oauth-server/internal/crypto"
)

// maxFormBytes caps a form body a handler will parse.
//
// Matches httpapi.Guard's default so a handler behaves identically whether it arrives
// through a guarded chain or is called directly in a test.
const maxFormBytes = 1 << 20

// parseForm parses a form body under a size cap.
//
// Returns false on any refusal and the caller renders the error; the reason is
// deliberately not returned, because a caller that could distinguish "too large" from
// "malformed" would eventually tell a client its body was too large, which is a free
// oracle for probing limits.
//
// The duplicate check is the load-bearing part. Taking the first or last value of a
// repeated parameter is parametrised: an intermediary may inspect the first while this
// server acts on the last, and a parameter whose meaning depends on which copy wins is
// a request smuggling primitive.
//
// On the protocol endpoints `scope` is a single space-delimited string, so a repeated
// scope there is an unambiguous smuggling attempt and is refused like any other
// duplicate. The consent screen is the one place repetition is the encoding: it posts
// one `scope` per box the user ticked, and RFC 6749 section 3.3 defines scope as a
// list. It calls parseFormAllowing instead.
func parseForm(r *http.Request) bool {
	return parseFormAllowing(r)
}

// parseFormAllowing is parseForm with the duplicate check relaxed for the named
// parameters.
func parseFormAllowing(r *http.Request, repeatable ...string) bool {
	if r.ContentLength > maxFormBytes {
		return false
	}
	// MaxBytesReader so a chunked request with no Content-Length is bounded too.
	// Its error is reported as a parse failure, indistinguishable from malformed input.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(nil, r.Body, maxFormBytes)
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	allowed := make(map[string]bool, len(repeatable))
	for _, name := range repeatable {
		allowed[name] = true
	}
	for name, values := range r.PostForm {
		if allowed[name] {
			continue
		}
		if len(values) > 1 {
			return false
		}
	}
	return true
}

// stringParam reads a single form-or-query value.
//
// Form first, because a browser endpoint accepts the same parameter in both places and
// a value that differs between them is ambiguous. Callers that care use
// httpapi.ExtractRedirectURI, which refuses the disagreement instead of choosing.
func stringParam(r *http.Request, name string) string {
	if v := r.PostFormValue(name); v != "" {
		return v
	}
	return r.URL.Query().Get(name)
}

// stringParamPresent reads a value and reports whether the parameter appeared at all.
//
// Needed because "absent" and "empty" are different to a client comparing state
// byte-for-byte, and RFC 6749 section 4.1.1 requires echoing the value if one was
// present — including when it was present and empty.
func stringParamPresent(r *http.Request, name string) (value string, present bool) {
	if values, ok := r.PostForm[name]; ok && len(values) > 0 {
		return values[0], true
	}
	if values, ok := r.URL.Query()[name]; ok && len(values) > 0 {
		return values[0], true
	}
	return "", false
}

// scopes splits a space-delimited scope parameter.
//
// Parsed rather than passed as a string because every downstream check is set-valued:
// subset of the client's registration, the consent record, the granted set in an ID
// token. Comparing "openid email" and "email openid" as strings would make two
// identical requests different grants, which is a distinction no client means and one a
// client comparing its two responses byte-for-byte would trip over.
func scopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Fields(raw)
}

// optionalParam returns a pointer to the parameter's value when it was present, and nil
// otherwise.
//
// Used for parameters whose absence and whose empty value mean different things — for
// example nonce, where absent means "no nonce was requested" and an empty nonce would
// otherwise be echoed into an ID token as present-but-empty.
func optionalParam(r *http.Request, name string) *string {
	v, present := stringParamPresent(r, name)
	if !present {
		return nil
	}
	return &v
}

// optionalInt returns a pointer to a parsed non-negative integer when the parameter was
// present and well formed, and nil otherwise.
//
// A malformed max_age is treated as absent rather than as zero: zero would mean "force
// re-authentication on every request", turning a typo into a login loop. Absent means
// "no constraint", which is what the client most likely meant.
func optionalInt(r *http.Request, name string) *int {
	v, present := stringParamPresent(r, name)
	if !present || v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// secureEqual compares two secrets without leaking their contents through timing.
//
// Both sides are hashed first rather than calling subtle.ConstantTimeCompare on the raw
// values: that function returns immediately when the lengths differ, and a length
// mismatch is exactly what an attacker produces by submitting short candidates.
// Hashing makes the inputs the same length by construction, so the early return becomes
// unreachable, and crypto.VerifySHA256Hex compares with hmac.Equal.
func secureEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return crypto.VerifySHA256Hex(a, crypto.SHA256Hex(b))
}
