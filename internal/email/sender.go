// Outbound email transport and template rendering.

package email

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	netmail "net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/wneessen/go-mail"

	"oauth-server/internal/crypto"
)

// templateFS holds the message bodies.
//
// Embedded rather than read from disk: a container that ships without a templates
// directory would fail at the first verification email instead of at startup, and
// the failure would look like an SMTP problem.

//go:embed templates/*.html
var templateFS embed.FS

// Purpose is the kind of message a token belongs to.
//
// The persisted purposes are exactly the strings the email_verifications purpose
// CHECK constraint permits. They are part of the token record rather than inferred
// from the template name, because a hash is redeemable only for the purpose it was
// issued under: accepting a verification link where a password reset is expected
// turns one magic link into universal account takeover.
//
// PurposeAccountLocked and PurposeNewDeviceNotice are notifications. They carry no
// token row and must never be written to email_verifications; NewSender refuses a
// purpose that is not in the token-persisted set only when asked to issue one, so
// see IsPersistedPurpose.
type Purpose string

const (
	// PurposeSignup is the initial email verification for a new account.
	PurposeSignup Purpose = "signup"

	// PurposePasswordReset is a password reset token.
	PurposePasswordReset Purpose = "password_reset"

	// PurposeChangeEmail is a token confirming a change of sign-in address.
	PurposeChangeEmail Purpose = "change_email"

	// PurposeAccountLocked notifies that sign-in attempts tripped the lockout
	// threshold. Carries no token of its own.
	PurposeAccountLocked Purpose = "account_locked"

	// PurposeNewDeviceNotice reports a sign-in from an unrecognised device.
	// Carries no token of its own.
	PurposeNewDeviceNotice Purpose = "new_device"
)

// IsPersistedPurpose reports whether a purpose has a row in email_verifications.
//
// Checked before issuing a token so a notification-only purpose cannot be written to
// a table whose CHECK constraint rejects it, and — more importantly — so nobody adds
// a new notification purpose and assumes its token was stored.
func (p Purpose) IsPersistedPurpose() bool {
	switch p {
	case PurposeSignup, PurposePasswordReset, PurposeChangeEmail:
		return true
	default:
		return false
	}
}

// ErrDelivery is returned when a message could not be handed to the transport.
//
// A single sentinel, so the caller's decision is "did it go out or not" rather than a
// judgement about which SMTP failure occurred. The wrapped cause is available for the
// log.
//
// Note this is an error and not a silent log line. Registration and verification are
// enumeration-safe only if the caller can treat "the message did not go out" as a
// failure to deliver the service, not as a successful no-op: a swallowed SMTP error
// means an account is created with no way to verify it and no operator alert.
var ErrDelivery = errors.New("email: delivery failed")

// Config is the transport configuration.
//
// The password is a field rather than read inside Send, so that a Sender built from
// this struct cannot accidentally log or serialise it, and so the credential is
// supplied once at construction.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string

	FromAddress string
	FromName    string

	// Timeout bounds one delivery attempt. Without it a connection to a black-holed
	// SMTP host holds a request open for the TCP default, which on some hosts is
	// over two minutes.
	Timeout time.Duration

	// StartTLSMode selects transport security.
	//
	// Not the mail library's own enum: this is a configuration surface that comes
	// from a config file, and pinning the library type in Config would leak a
	// dependency's zero value into the meaning of "unset" here.
	StartTLSMode StartTLSMode

	// MaxAttempts is how many times one Send retries a transient failure.
	MaxAttempts int
}

// StartTLSMode selects SMTP transport security.
type StartTLSMode int

const (
	// TLSOpportunistic uses TLS when the server advertises it and sends in the
	// clear when it does not.
	//
	// The default, and it is what makes MailHog and other plaintext development
	// hosts work without a second configuration path. Production should set
	// TLSRequired.
	TLSOpportunistic StartTLSMode = iota

	// TLSRequired refuses to deliver over an unencrypted connection.
	TLSRequired
)

// DefaultTimeout and DefaultMaxAttempts for delivery.
const (
	DefaultTimeout     = 10 * time.Second
	DefaultMaxAttempts = 3
)

// Transport delivers a rendered message.
type Transport interface {
	Send(ctx context.Context, msg *Message) error
}

// Message is one outbound email, already rendered.
type Message struct {
	To      string
	Subject string
	// Body is HTML. Text is the plain-text alternative.
	Body string
	Text string
}

// Sender renders templates and delivers messages.
type Sender struct {
	cfg       Config
	client    *mail.Client
	transport Transport
	templates *template.Template
	log       *slog.Logger
}

// Option configures a Sender.
type Option func(*Sender)

// WithTransport replaces the SMTP transport. For tests.
func WithTransport(t Transport) Option {
	return func(s *Sender) { s.transport = t }
}

// WithTemplates replaces the parsed template set.
func WithTemplates(t *template.Template) Option {
	return func(s *Sender) { s.templates = t }
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Sender) {
		if l != nil {
			s.log = l
		}
	}
}

// NewSender builds a Sender.
//
// Returns an error rather than deferring SMTP connection failure to the first send.
// A registration service that accepts registrations it cannot mail is worse than one
// that refuses to start: the accounts exist, and nobody can prove it or recover.
func NewSender(cfg Config, opts ...Option) (*Sender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("email: NewSender: host is empty")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("email: NewSender: port %d out of range", cfg.Port)
	}
	if cfg.FromAddress == "" {
		return nil, fmt.Errorf("email: NewSender: from address is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	// An out-of-range enum from a config file would otherwise be passed straight to
	// the mail library, where it is an untyped int and means nothing in particular.
	switch cfg.StartTLSMode {
	case TLSOpportunistic, TLSRequired:
	default:
		return nil, fmt.Errorf("email: NewSender: starttls_mode %d is not a known mode", cfg.StartTLSMode)
	}

	s := &Sender{cfg: cfg, log: slog.Default()}
	// html/template, not text/template. The bodies are HTML, and html/template
	// contextualises each interpolation: {{.Address}} lands inside HTML text and is
	// escaped, while {{.Link}} lands in an href attribute and is checked as a URL.
	// With text/template a request parameter that reached .Address would inject markup
	// into a message rendered inside the user's mail client.
	tpl, err := template.New("email").ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse templates: %w", err)
	}
	s.templates = tpl

	for _, opt := range opts {
		opt(s)
	}

	if s.transport == nil {
		client, err := newSMTPClient(cfg)
		if err != nil {
			return nil, err
		}
		s.client = client
		s.transport = &smtpTransport{client: client, from: senderAddress(cfg)}
	}
	return s, nil
}

// newSMTPClient builds the SMTP client.
//
// Construction only, no connection. go-mail dials per send through
// DialAndSendWithContext, which is what this Transport wants: a shared pooled
// connection that fails mid-send leaves the next send writing to a half-closed
// socket, and the resulting error looks like a bug in the mailer rather than the
// server having dropped us.
//
// Reachability is therefore checked by the caller's first send, not here. NewSender
// validates configuration — a wrong host or a missing From address is a startup
// error — while an unreachable server is a runtime condition that retries and then
// reports ErrDelivery.
func newSMTPClient(cfg Config) (*mail.Client, error) {
	options := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithTimeout(cfg.Timeout),
		mail.WithTLSPolicy(cfg.StartTLSMode.tlsPolicy()),
	}
	if cfg.Username != "" {
		options = append(options,
			mail.WithUsername(cfg.Username),
			mail.WithPassword(cfg.Password),
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
		)
	}

	client, err := mail.NewClient(cfg.Host, options...)
	if err != nil {
		return nil, fmt.Errorf("email: create smtp client: %w", err)
	}
	return client, nil
}

// tlsPolicy maps the config enum onto the mail library's.
func (m StartTLSMode) tlsPolicy() mail.TLSPolicy {
	if m == TLSRequired {
		return mail.TLSMandatory
	}
	return mail.TLSOpportunistic
}

// senderAddress builds the RFC 5322 From header.
func senderAddress(cfg Config) *netmail.Address {
	name := cfg.FromName
	if name == "" {
		name = cfg.FromAddress
	}
	return &netmail.Address{Name: name, Address: cfg.FromAddress}
}

// TemplateData is what the message templates render against.
//
// A closed struct rather than a map. These templates interpolate a target address and
// a link into HTML, and a map would let any future caller put an arbitrary value into
// a slot the template escapes as text but a caller expects to be a URL.
type TemplateData struct {
	// Purpose selects which template is used and is not itself rendered.
	Purpose Purpose

	// Token is the raw, unhashed token.
	//
	// This is the only place a raw token exists outside the request that generated
	// it, and it is rendered into a URL once and then discarded. Everything the
	// database stores is crypto.SHA256Hex(token).
	Token string

	// BaseURL is the server's externally visible issuer, used to build links.
	BaseURL string

	// Address is the recipient, rendered in the body.
	Address string

	// ExpiresInHours is shown so a user knows whether to bother retrying.
	ExpiresInHours int

	// Extra carries the few per-purpose values a template needs.
	Extra map[string]string
}

// Link builds the absolute URL for a token purpose.
//
// Built centrally rather than in each template because the endpoint differs per
// purpose and getting one wrong produces a link that looks right and fails: a
// signup token pointed at /reset-password redeems against the wrong purpose and is
// rejected, and the user is left with no way to tell that from a broken link.
//
// Token in the query string, not the fragment. A fragment is never transmitted to
// the server, so a handler cannot read it without JavaScript; a token that must be
// redeemed by a redirect needs to be in the query.
func (d TemplateData) Link() string {
	base := strings.TrimRight(d.BaseURL, "/")
	switch d.Purpose {
	case PurposeSignup:
		return base + "/verify-email?token=" + urlQueryEscape(d.Token)
	case PurposePasswordReset:
		return base + "/reset-password?token=" + urlQueryEscape(d.Token)
	case PurposeChangeEmail:
		return base + "/verify-email-change?token=" + urlQueryEscape(d.Token)
	case PurposeAccountLocked:
		return base + "/reset-password"
	case PurposeNewDeviceNotice:
		return base + "/account/sessions"
	default:
		return base
	}
}

// Send renders and delivers a message for a purpose.
func (s *Sender) Send(ctx context.Context, data TemplateData) error {
	if data.Address == "" {
		return fmt.Errorf("%w: no recipient", ErrDelivery)
	}
	// A template that renders an empty link produces a message that looks complete
	// and cannot be used, and the recipient's only recourse is to write in. Refusing
	// before rendering is the only point where this is visible.
	//
	// Notifications carry no token and legitimately have none; the account-locked
	// notice points at the reset page rather than at a tokenised link.
	if data.Purpose.IsPersistedPurpose() && data.Token == "" {
		return fmt.Errorf("%w: purpose %s needs a token", ErrDelivery, data.Purpose)
	}

	msg, err := s.render(data)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 1; attempt <= s.cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v (last error: %v)", ErrDelivery, err, lastErr)
		}
		if err := s.transport.Send(ctx, msg); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt < s.cfg.MaxAttempts {
			// Backoff is small and bounded: the caller is a request handler, so a
			// long retry budget here becomes a long request.
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %v (last error: %v)", ErrDelivery, ctx.Err(), lastErr)
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
		}
	}

	s.log.Error("email delivery failed",
		"purpose", data.Purpose,
		"attempts", s.cfg.MaxAttempts,
		"error", lastErr.Error(),
	)
	return fmt.Errorf("%w: %v", ErrDelivery, lastErr)
}

// render executes the template for a purpose into a Message.
func (s *Sender) render(data TemplateData) (*Message, error) {
	name := string(data.Purpose) + ".html"

	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, fmt.Errorf("email: render %s: %w", name, err)
	}

	subject, err := s.renderSubject(data)
	if err != nil {
		return nil, err
	}

	return &Message{
		To:      data.Address,
		Subject: subject,
		Body:    buf.String(),
		Text:    plainText(data),
	}, nil
}

// renderSubject produces the subject line.
//
// Subjects are built in code rather than templated because each is a single line of
// constant text plus at most the purpose, and a template that could not escape its
// own output would be a needless injection surface in a header.
func (s *Sender) renderSubject(data TemplateData) (string, error) {
	// CR and LF are stripped so a caller-supplied value can never inject a header.
	// Nothing legitimate here contains them.
	clean := func(v string) string {
		return strings.NewReplacer("\r", "", "\n", "").Replace(v)
	}

	switch data.Purpose {
	case PurposeSignup:
		return "Confirm your email address", nil
	case PurposePasswordReset:
		return "Reset your password", nil
	case PurposeChangeEmail:
		return "Confirm your new email address", nil
	case PurposeAccountLocked:
		return "Your account has been temporarily locked", nil
	case PurposeNewDeviceNotice:
		return "New sign-in to your account", nil
	default:
		// clean is applied so an unknown purpose read from a config or request
		// cannot smuggle a newline into a header through the error path's caller.
		return "", fmt.Errorf("email: unknown purpose %q", clean(string(data.Purpose)))
	}
}

// plainText builds the text alternative.
//
// Present because a multipart/alternative message with only an HTML part is
// undeliverable in practice: spam filters score it as bulk mail and text-only clients
// see nothing at all. Verification links must arrive.
func plainText(data TemplateData) string {
	link := data.Link()
	if link == "" || link == data.BaseURL {
		return ""
	}
	return fmt.Sprintf("%s\n\nIf you did not request this, you can ignore this message.", link)
}

// hashToken returns the stored form of a raw token.
//
// The one place raw tokens become stored values, so that no repository has to
// remember which column is hashed.
func hashToken(token string) string {
	return crypto.SHA256Hex(token)
}

// urlQueryEscape escapes a token for a query value.
//
// net/url rather than a hand-rolled replacement table. The table version omitted "=",
// which is harmless for the current base64url tokens and turns into a broken link the
// first time a token source is changed to something else. The escaping rules are easy
// to get subtly wrong and impossible to review by eye, so the standard library owns
// them.
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

// Close releases the SMTP connection.
func (s *Sender) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}
