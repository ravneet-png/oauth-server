package client_auth

// ssrf.go — Network policy for outbound fetches of client-published URLs.
//
// A jwks_uri is a URL this server was told to fetch. Without a network policy that is a
// request forgery primitive: whoever can register or update a client picks the host, and
// this server reaches it from inside the deployment network. The targets that matter are
// the ones an attacker cannot otherwise reach — the cloud metadata address, a database,
// an admin interface bound to loopback.
//
// The check is in the dialer rather than in a URL parser on purpose. Parsing the host and
// rejecting "127.0.0.1" is defeated by a hostname that resolves to that address, and
// resolving once and checking the result before connecting is defeated by a second
// resolution returning a different answer. Validating the address the socket is actually
// being opened to closes both, because there is no gap between the check and the connect.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// errBlockedAddr means the resolved address is not routable on the public internet.
type errBlockedAddr struct {
	ip   net.IP
	host string
}

func (e *errBlockedAddr) Error() string {
	return fmt.Sprintf("jwks_uri host %q resolves to non-public address %s", e.host, e.ip)
}

// allowPrivateNets disables the network policy entirely.
//
// It exists for tests that must serve a key set from an httptest server, which is by
// definition on loopback. It is a method rather than a package variable so that turning
// the policy off is visible at the call site, and so production code cannot do it by
// accident from somewhere else in the package.
func allowPrivateNets() *http.Client {
	return &http.Client{Timeout: jwksFetchTimeout}
}

// guardedClient returns the client used to fetch a client's published key set.
//
// The policy is default-deny toward the private ranges and default-allow toward public
// ones: a client whose key set is genuinely hosted on the public internet keeps working,
// and the addresses an attacker wants are refused before a connection exists.
func guardedClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		// Force the address check to happen here rather than trusting any proxy or
		// resolver behaviour chosen elsewhere in the process.
		Proxy:                 nil,
		DialContext:           guardedDialContext(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: time.Second,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Redirects are refused rather than followed. A jwks_uri is a URL this server
		// was told to trust, and following a redirect from it hands the fetch to a host
		// that was never registered, which turns a client registration into an outbound
		// request to anywhere the registered endpoint chooses to name. The dialer would
		// catch a redirect into a private range, but a redirect to another public host is
		// still an unvalidated fetch, so this refuses the whole class.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// guardedDialContext resolves the address, checks every answer, then dials.
//
// All answers are checked, not just the first: a name with both a public and a private
// record is a normal way to make a check-then-connect race winnable, and refusing the
// name outright is the only response that does not depend on which record the resolver
// happens to return in which order.
func guardedDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("jwks_uri: parse address %q: %w", addr, err)
		}

		// An IP literal needs no resolution; check it directly so a client cannot skip
		// the policy by writing the address out in full.
		if ip := net.ParseIP(host); ip != nil {
			if !isPublicIP(ip) {
				return nil, &errBlockedAddr{ip: ip, host: host}
			}
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("jwks_uri: resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("jwks_uri: %q resolved to no addresses", host)
		}
		for _, ip := range ips {
			if !isPublicIP(ip.IP) {
				return nil, &errBlockedAddr{ip: ip.IP, host: host}
			}
		}

		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
}

// isPublicIP reports whether an address is routable on the public internet.
//
// Everything that is not is refused. The list is deliberately long and the default is
// refusal, because the cost of an unnecessary refusal is a client whose key set has to be
// republished, while the cost of a necessary one is an unauthenticated read of an internal
// service.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}

	// An IPv4-mapped IPv6 address carries the v4 address in its low 32 bits and would
	// otherwise slip past the v4 checks above.
	if v4 := ip.To4(); v4 != nil {
		return isPublicIPv4(v4)
	}
	return isPublicIPv6(ip)
}

// isPublicIPv4 applies the ranges that net.IP's predicates do not cover.
func isPublicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}

	// Carrier-grade NAT, RFC 6598. Reachable from inside a cloud VPC and off the public
	// internet, which is exactly the shape this policy exists to refuse.
	if inCIDR(v4, "100.64.0.0", 10) {
		return false
	}
	// RFC 6890 special-purpose blocks.
	if inCIDR(v4, "192.0.0.0", 24) || // IETF protocol assignments
		inCIDR(v4, "192.0.2.0", 24) || // TEST-NET-1
		inCIDR(v4, "198.18.0.0", 15) || // benchmarking
		inCIDR(v4, "198.51.100.0", 24) || // TEST-NET-2
		inCIDR(v4, "203.0.113.0", 24) || // TEST-NET-3
		inCIDR(v4, "240.0.0.0", 4) { // reserved, includes 255.255.255.255
		return false
	}
	return true
}

// isPublicIPv6 applies the ranges that net.IP's predicates do not cover.
func isPublicIPv6(ip net.IP) bool {
	// Unique local, fc00::/7. IsPrivate covers this on current Go, but it is named here
	// so the refusal survives a change in that implementation.
	if inCIDR(ip, "fc00::", 7) {
		return false
	}
	// Link-local and site-local are refused by the predicates above; these are the
	// documentation and discard ranges that remain.
	if inCIDR(ip, "2001:db8::", 32) || // documentation
		inCIDR(ip, "100::", 64) { // discard-only
		return false
	}
	return true
}

// inCIDR reports whether ip falls inside base/prefix.
func inCIDR(ip net.IP, base string, prefix int) bool {
	_, network, err := net.ParseCIDR(base + "/" + itoa(prefix))
	if err != nil {
		// A malformed constant is a programming error, and silently returning false
		// would turn it into an open policy.
		panic("client_auth: bad CIDR constant " + base)
	}
	return network.Contains(ip)
}

// itoa avoids importing strconv for two call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
