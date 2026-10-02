package middleware

// Client address resolution.
//
// Forwarded headers are read only when the immediate peer is a configured trusted proxy.
// Without that check, ClientIP trusts X-Forwarded-For from whoever connects, and every
// IP-keyed rate limit becomes a suggestion: an attacker rotating a header value the
// server believes gets an unlimited number of attempts.

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientAddrKeyType struct{}

var clientAddrKey = clientAddrKeyType{}

// contextWithClientAddr stores the resolved address in the context.
func contextWithClientAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, clientAddrKey, addr)
}

// TrustedProxy resolves the client address from forwarded headers, but only for peers
// it has been configured to trust.
type TrustedProxy struct {
	// enabled is false when no proxies are configured at all.
	//
	// A separate field rather than an empty list because "trust nobody" and "trust
	// the empty set" both iterate over zero entries and would otherwise be
	// indistinguishable from each other in a refactor.
	enabled bool

	// networks are the parsed trusted ranges. Parsed once at construction: matching a
	// CIDR per request means re-parsing on every request, and a parse error at request
	// time is a rate limit that silently stops applying.
	networks []netip.Prefix
}

// NewTrustedProxy builds a TrustedProxy from CIDR strings and bare addresses.
//
// Bare addresses are widened to a single host (/32 or /128), because a configuration
// listing "10.0.0.5" almost certainly means that one proxy and not the entire 10/8.
func NewTrustedProxy(trusted []string) (*TrustedProxy, error) {
	if len(trusted) == 0 {
		return &TrustedProxy{enabled: false}, nil
	}

	tp := &TrustedProxy{enabled: true, networks: make([]netip.Prefix, 0, len(trusted))}

	for _, entry := range trusted {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, &ProxyConfigError{Entry: entry, Err: err}
			}
			tp.networks = append(tp.networks, prefix.Masked())
			continue
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, &ProxyConfigError{Entry: entry, Err: err}
		}
		tp.networks = append(tp.networks, netip.PrefixFrom(addr, addr.BitLen()))
	}

	// Every entry blank leaves nothing trusted, which is the safe direction.
	if len(tp.networks) == 0 {
		return &TrustedProxy{enabled: false}, nil
	}
	return tp, nil
}

// ProxyConfigError reports an unparseable trusted proxy entry.
type ProxyConfigError struct {
	Entry string
	Err   error
}

func (e *ProxyConfigError) Error() string {
	return "middleware: trusted proxy entry " + e.Entry + " is not a valid address or CIDR: " + e.Err.Error()
}

func (e *ProxyConfigError) Unwrap() error { return e.Err }

// Trusts reports whether the immediate peer is a configured proxy.
func (t *TrustedProxy) Trusts(peer string) bool {
	if t == nil || !t.enabled {
		return false
	}
	addr, ok := parseAddr(peer)
	if !ok {
		return false
	}
	for _, p := range t.networks {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseAddr extracts an address from a "host:port" pair or a bare address.
func parseAddr(peer string) (netip.Addr, bool) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return netip.Addr{}, false
	}

	// Bare address first, so an IPv6 literal without a port is not mistaken for
	// host:port by the last-colon split below.
	if addr, err := netip.ParseAddr(peer); err == nil {
		return addr.Unmap(), true
	}

	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// Middleware resolves the client address and stores it in the request context.
func (t *TrustedProxy) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := t.Resolve(r)
		ctx := contextWithClientAddr(r.Context(), addr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Resolve returns the client address for a request.
//
// Walks X-Forwarded-For right to left and takes the first address that is not itself a
// trusted proxy. That is the last hop this server actually controlled, so it is the
// closest thing to the real client that the header chain can honestly attest.
//
// Taking the leftmost entry instead — the obvious reading — is wrong whenever the
// chain contains an untrusted hop: that entry is whatever the untrusted hop chose to
// write, and it is chosen by the party being rate limited.
func (t *TrustedProxy) Resolve(r *http.Request) string {
	peer := r.RemoteAddr

	if !t.Trusts(peer) {
		// Direct connection, or a peer we do not trust. Forwarded headers are
		// attacker-controlled in the second case and meaningless in the first.
		if addr, ok := parseAddr(peer); ok {
			return addr.String()
		}
		return peer
	}

	if addr := t.resolveForwarded(r); addr != "" {
		return addr
	}

	if addr, ok := parseAddr(peer); ok {
		return addr.String()
	}
	return peer
}

// maxForwardedHops bounds the header walk.
//
// The chain is attacker-supplied even when the first hop is trusted, so an attacker can
// prepend entries indefinitely. Bounding the walk means the cost is constant; anything
// found after the bound is discarded rather than trusted.
const maxForwardedHops = 32

// resolveForwarded walks the forwarded chain and returns the last untrusted address.
func (t *TrustedProxy) resolveForwarded(r *http.Request) string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return ""
	}

	// Multiple header lines are joined rather than only reading the first: RFC 7230
	// permits a repeated header and each line is a continuation of the same list.
	var parts []string
	for _, v := range values {
		parts = append(parts, strings.Split(v, ",")...)
	}

	hops := 0
	for i := len(parts) - 1; i >= 0; i-- {
		hops++
		if hops > maxForwardedHops {
			return ""
		}

		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		// A quoted or bracketed entry, or an "unknown" token, is not an address this
		// server can reason about, so the chain is treated as untrustworthy from
		// there up.
		addr, ok := parseAddr(candidate)
		if !ok {
			return ""
		}
		if t.Trusts(addr.String()) {
			continue
		}
		return addr.String()
	}
	return ""
}

// ClientAddrFromContext returns the address the proxy middleware resolved.
func ClientAddrFromContext(r *http.Request) string {
	if v := r.Context().Value(clientAddrKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
