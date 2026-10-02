package middleware

// Return path validation.
//
// Deliberately separate from CSRF protection: a defect in one must not disable the
// other. This is defence in depth behind the fact that post-login redirects resolve from
// a server-side request identifier, not from a value the client supplies.
//
// The whole point of the file is that "does it start with /" is not a sufficient test.
// "/\\evil.com" and "https://evil.com" and "//evil.com" all pass a naive prefix check
// and all send the user to an attacker's site from a page that looks like ours.

import (
	"net/url"
	"strings"
)

// ReturnPathAllowed reports whether a return_to value is a safe local redirect target.
//
// Rejected:
//
//   - anything with a scheme ("https://evil.com")
//   - protocol-relative URLs ("//evil.com"), which navigate to a host
//   - backslash forms ("/\evil.com"), which several browsers normalise to "//"
//   - control characters, which defeat a prefix comparison by hiding the real target
//   - paths that do not begin with exactly one "/"
//
// Accepted: any path matching one of allowedPrefixes.
func ReturnPathAllowed(returnTo string, allowedPrefixes []string) bool {
	if returnTo == "" {
		return false
	}

	// Rejected before any parsing. A NUL or newline inside a path is how a value gets
	// past one check and interpreted differently by the next.
	if hasControlChars(returnTo) {
		return false
	}

	// Backslash is normalised to "/" before the check because Chrome and Firefox treat
	// "/\evil.com" as protocol-relative. Normalising here means the rest of this
	// function sees what the browser will see.
	normalised := strings.ReplaceAll(returnTo, "\\", "/")

	if !strings.HasPrefix(normalised, "/") {
		return false
	}
	// A leading "//" or "/\..." (already normalised) is a host, not a path.
	if strings.HasPrefix(normalised, "//") {
		return false
	}

	// Belt and braces: after the structural checks, confirm it really parses as a
	// path with no authority or scheme.
	u, err := url.Parse(normalised)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return false
	}
	if !strings.HasPrefix(u.Path, "/") {
		return false
	}

	for _, prefix := range allowedPrefixes {
		prefix = strings.ReplaceAll(strings.TrimSpace(prefix), "\\", "/")
		if prefix == "" {
			continue
		}
		if !strings.HasPrefix(prefix, "/") {
			// A prefix that is not a path cannot safely match one.
			continue
		}
		// Compare against the parsed path rather than the raw string, so an encoded
		// form ("%2f%2fevil.com") cannot match a prefix it does not really begin with.
		if u.Path == prefix || strings.HasPrefix(u.Path, strings.TrimSuffix(prefix, "/")+"/") || strings.HasPrefix(u.Path, prefix) {
			return true
		}
	}
	return false
}

// hasControlChars reports whether s contains a C0 control character or DEL.
func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// ValidateReturnPath checks if a return_to path is an allowed internal path.
//
// Only paths starting with one of the configured allowed prefixes are permitted.
// External URLs (containing ://) are always rejected. Empty path is rejected.
func ValidateReturnPath(path string, allowedPrefixes []string) bool {
	return ReturnPathAllowed(path, allowedPrefixes)
}

// SafeReturnURL returns the redirect target to use, or "" when none is allowed.
//
// Returns a string rather than a bool so a caller cannot accidentally redirect to the
// unvalidated value it was given. The empty result must be handled by rendering a page
// instead of redirecting, which is the only safe response.
func SafeReturnURL(returnTo string, allowedPrefixes []string) string {
	if !ReturnPathAllowed(returnTo, allowedPrefixes) {
		return ""
	}
	return strings.ReplaceAll(returnTo, "\\", "/")
}
