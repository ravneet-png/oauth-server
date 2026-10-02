package domain

// Scope parsing, normalisation and containment. The single scope representation
// for the whole codebase. Scopes are TEXT[] in every table and are only
// converted to a space-delimited string at the HTTP boundary.

import (
	"fmt"
	"sort"
	"strings"
)

// ScopeDelimiter is the separator defined by RFC 6749 section 3.3. The space is
// not arbitrary: `%x20` is the only delimiter the grammar allows.
const ScopeDelimiter = " "

// NormalizeScope splits a space-delimited scope string as it arrives on the wire
// and returns it as a deduplicated, sorted slice.
//
// Sorting is not cosmetic. Two clients presenting the same scope set in a
// different order must produce byte-identical stored values, or a consent record
// written as ["openid","email"] fails to match a later request for
// ["email","openid"] and the user is prompted again for no reason.
//
// An empty or whitespace-only input yields an empty, non-nil slice, so that a
// caller can distinguish "no scope requested" from "scope not parsed yet".
func NormalizeScope(raw string) []string {
	fields := strings.Split(raw, ScopeDelimiter)
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		// RFC 6749 3.3: scope-token = 1*NQCHAR / %x21 / %x23-5B / %x5D-7E.
		// The double quote (0x22) is excluded because these values are
		// interpolated into HTML and into a Content-Type-adjacent context.
		// Rather than silently accepting a malformed token, drop anything
		// outside the grammar: the request is rejected upstream by
		// ValidateScopeTokens.
		if f == "" || !isValidScopeToken(f) {
			continue
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ValidateScopeTokens is the gate that must run before NormalizeScope.
//
// It exists because NormalizeScope silently DROPS anything outside the grammar,
// which is the right behaviour for a value already known to be well-formed and
// the wrong behaviour for untrusted input. Parsing `openid email"` with
// NormalizeScope alone yields ["openid"], a request for two scopes answered with
// a grant for one, and the caller never learns anything was discarded. This
// function refuses instead, so a malformed value becomes invalid_request rather
// than a quieter grant.
//
// The error names the offending token so a client can be told which part of its
// request was wrong; scope values are not secrets and are already visible to the
// client that sent them.
func ValidateScopeTokens(raw string) error {
	// An absent or empty scope parameter is zero scopes, not a malformed one.
	// Splitting "" yields one empty string, so this case has to be handled
	// before the loop or every client that legitimately omits scope is
	// rejected. Whitespace-only is still an error: a caller that sends " "
	// meant to send something.
	if raw == "" {
		return nil
	}
	for _, f := range strings.Split(raw, ScopeDelimiter) {
		if f == "" {
			// An empty field means a doubled, leading or trailing space. The
			// grammar has no such token, so it is a malformed request rather
			// than an empty scope to ignore.
			return fmt.Errorf("%w: scope contains an empty token", NewInvalidRequest("malformed scope parameter"))
		}
		if !isValidScopeToken(f) {
			return fmt.Errorf("%w: scope token %q is outside the RFC 6749 grammar", NewInvalidRequest("malformed scope parameter"), f)
		}
	}
	return nil
}

// isValidScopeToken reports whether s is a single %x21 / %x23-5B / %x5D-7E
// character. Everything outside RFC 6749's grammar is rejected, which also
// blocks the space-splitting tricks ("openid\u00a0email") that would otherwise
// smuggle a second scope past a naive comparison.
func isValidScopeToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}

// JoinScope is the only place a scope set becomes a string. Restricting the
// conversion to one function means there is one encoder to audit and one place
// to change if the format ever moves.
func JoinScope(scopes []string) string {
	return strings.Join(scopes, ScopeDelimiter)
}

// ScopeContains reports whether set contains want.
func ScopeContains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// ScopeContainsAll reports whether set contains every element of want. This is
// the test that consent must satisfy: partial coverage is not consent.
func ScopeContainsAll(set, want []string) bool {
	for _, w := range want {
		if !ScopeContains(set, w) {
			return false
		}
	}
	return true
}

// ScopeIsSubset reports whether every element of set appears in allowed. Used to
// reject a request for scopes the client is not registered for, and to filter
// grantable scopes before the consent screen renders.
func ScopeIsSubset(set, allowed []string) bool {
	for _, s := range set {
		if !ScopeContains(allowed, s) {
			return false
		}
	}
	return true
}

// ScopeMissing returns the elements of want that set does not contain, sorted.
// The consent screen needs the list to explain to the user what was withheld and
// why, so this returns the difference rather than a bare bool.
func ScopeMissing(set, want []string) []string {
	var missing []string
	for _, w := range want {
		if !ScopeContains(set, w) {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	return missing
}

// NormalizeScopeSet is NormalizeScope for a slice that came out of the database.
// It deduplicates and sorts without re-validating individual characters, because
// a value that reached the database already passed validation and a silent drop
// here would be much harder to trace than a duplicate.
func NormalizeScopeSet(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ScopeEqual reports set equality, order-insensitively. Consent comparison
// still uses ScopeContainsAll rather than this: a stored grant of
// [openid,email,profile] satisfies a request for [openid,email] and must not
// re-prompt.
func ScopeEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	na := NormalizeScopeSet(a)
	nb := NormalizeScopeSet(b)
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}
