// SMTP delivery for rendered messages.

package email

import (
	"context"
	"fmt"
	netmail "net/mail"
	"strings"

	"github.com/wneessen/go-mail"
)

// smtpTransport is the default Transport: a multipart/alternative message over SMTP.
//
// multipart/alternative rather than text/html, because a message sent as HTML alone
// has no plain-text alternative and is either rejected or shown as raw markup by some
// clients. The plain-text part carries the link in full, which is the part that must
// survive: a verification link buried in quoted markup becomes a support ticket.
type smtpTransport struct {
	client *mail.Client
	from   *netmail.Address
}

// Send delivers one message.
func (t *smtpTransport) Send(ctx context.Context, msg *Message) error {
	if msg == nil {
		return fmt.Errorf("%w: no message", ErrDelivery)
	}
	if t.from == nil || t.client == nil {
		return fmt.Errorf("%w: transport is not initialised", ErrDelivery)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}

	m := mail.NewMsg()
	if err := m.From(t.from.String()); err != nil {
		return fmt.Errorf("%w: build from header: %w", ErrDelivery, err)
	}
	if err := m.To(msg.To); err != nil {
		return fmt.Errorf("%w: build to header: %w", ErrDelivery, err)
	}
	// sanitizeHeader on the way in. A newline in a subject appends headers the
	// receiving MTA will honour, which is how a mailer becomes an open relay for
	// spam. Subjects here are built from constants, but the guard belongs at the
	// boundary that builds the header rather than at the one place that fills it.
	m.Subject(sanitizeHeader(msg.Subject))
	m.SetDate()
	// Marked machine-generated so a mail client threading a reply to a verification
	// notice does not send it back to us, and so spam heuristics that discount
	// automated mail do not treat these as unsolicited.
	// SetGenHeader, not the deprecated SetHeader: these are general headers, not
	// address headers.
	m.SetGenHeader("Auto-Submitted", "auto-generated")
	m.SetGenHeader("X-Auto-Response-Suppress", "All")

	// Order matters: SetBodyString establishes the first part, AddAlternativeString
	// adds a further one with increasing precedence, so HTML last is what a capable
	// client renders.
	m.SetBodyString(mail.TypeTextPlain, msg.Text)
	m.AddAlternativeString(mail.TypeTextHTML, msg.Body)

	// Dial-and-send per message rather than a pooled connection. A shared connection
	// that fails mid-send leaves the next send writing to a half-closed socket, and
	// the resulting error reads as a bug in the mailer rather than the server having
	// dropped us.
	if err := t.client.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	return nil
}

// sanitizeHeader strips CR and LF from a header value.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}
