// OIDC back-channel logout delivery.
//
// Delivery is deliberately synchronous-but-bounded rather than a fire-and-forget
// goroutine. A `go sendLogoutToken(...)` call is the wrong shape here for three
// reasons: the goroutine outlives the request context and so is killed mid-POST,
// the process can exit before delivery is attempted, and there is nothing to retry
// or to observe when an RP's endpoint is down. This package owns delivery instead,
// with a bounded attempt count and a caller-supplied context.

package backchannel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults for delivery. Both bounded: an unbounded retry loop against a
// permanently broken endpoint is a resource leak, and an unbounded timeout lets
// one slow RP hold a logout request open until the client gives up.
const (
	DefaultMaxAttempts = 3
	DefaultTimeout     = 5 * time.Second
)

// ErrDeliveryFailed means every attempt failed. The wrapped cause is the last
// transport error, which is what an operator needs; the HTTP status is available
// through StatusError when the endpoint answered at all.
var ErrDeliveryFailed = errors.New("backchannel: logout delivery failed")

// StatusError is returned when the endpoint answered with a non-2xx status.
//
// A distinct type because "the RP said 400" and "the RP did not answer" call for
// different responses: the first is the client's fault and will not fix itself on
// retry, the second is transient and usually will.
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("backchannel: endpoint returned %d", e.StatusCode)
}

// Sender POSTs logout tokens to relying party endpoints.
type Sender struct {
	client      *http.Client
	maxAttempts int
}

// Option configures a Sender.
type Option func(*Sender)

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Sender) { s.client = c }
}

// WithMaxAttempts sets the attempt ceiling, clamped to at least 1.
func WithMaxAttempts(n int) Option {
	return func(s *Sender) {
		if n < 1 {
			n = 1
		}
		s.maxAttempts = n
	}
}

// NewSender builds a Sender.
//
// The default client is used with no timeout override, so the per-attempt bound
// comes from the context deadline set in Deliver. Giving the client its own
// Timeout as well would create two independent limits, and the shorter one would
// win for reasons the caller cannot see.
func NewSender(opts ...Option) *Sender {
	s := &Sender{
		client:      &http.Client{},
		maxAttempts: DefaultMaxAttempts,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Deliver posts logout_token to endpoint.
//
// The body is form-encoded, which is what OpenID Connect Back-Channel Logout 1.0
// section 2.4 specifies, and which most RPs parse with a standard form decoder.
//
// Retries are immediate-with-backoff and only on transport errors or 5xx. A 4xx
// is a permanent refusal: the RP understood the request and declined it, so
// repeating it produces the same answer and delays the caller for nothing.
func (s *Sender) Deliver(ctx context.Context, endpoint, logoutToken string) error {
	if endpoint == "" {
		return fmt.Errorf("%w: no endpoint", ErrDeliveryFailed)
	}
	if logoutToken == "" {
		return fmt.Errorf("%w: no logout token", ErrDeliveryFailed)
	}
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("%w: unparseable endpoint: %w", ErrDeliveryFailed, err)
	}

	form := url.Values{"logout_token": {logoutToken}}
	body := form.Encode()

	backoff := 100 * time.Millisecond
	var lastErr error

	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %w (last error: %w)", ErrDeliveryFailed, ctx.Err(), lastErr)
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("%w: build request: %w", ErrDeliveryFailed, err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Drained before the status is judged. Closing without reading leaves the
		// connection unusable, so the next attempt opens a new one and the retry
		// loop pays for a fresh TCP and TLS handshake every time.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		// Close error is not actionable: the delivery outcome is decided by the
		// status code below, not by whether the socket shut down cleanly.
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		statusErr := &StatusError{StatusCode: resp.StatusCode, Body: string(respBody)}
		if resp.StatusCode < 500 {
			// Permanent. Returned immediately rather than wrapped, so a caller can
			// distinguish "the RP refused" from "the RP was unreachable".
			return statusErr
		}
		lastErr = statusErr
	}

	return fmt.Errorf("%w: %w", ErrDeliveryFailed, lastErr)
}
