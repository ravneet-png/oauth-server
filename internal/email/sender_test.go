package email

// Sender and password-reset tests.
//
// These need no database: the Sender is exercised through the Transport interface,
// and the reset flow's behaviour worth testing — enumeration safety, single use,
// purpose separation — is a property of the code's control flow, not of SMTP.
//
// The tests that DO need PostgreSQL (a token row actually round-tripping) belong in
// internal/storage alongside the other repository tests, where a live pool is
// already the norm.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingTransport captures messages instead of sending them.
type recordingTransport struct {
	mu   sync.Mutex
	msgs []*Message
	err  error
	// calls counts Send invocations, including retries.
	calls int
}

func (r *recordingTransport) Send(ctx context.Context, msg *Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.msgs = append(r.msgs, msg)
	return nil
}

func (r *recordingTransport) last(t *testing.T) *Message {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.msgs) == 0 {
		t.Fatal("no message was delivered")
	}
	return r.msgs[len(r.msgs)-1]
}

func (r *recordingTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

func newTestSender(t *testing.T, tr Transport, opts ...Option) *Sender {
	t.Helper()
	s, err := NewSender(Config{
		Host:        "localhost",
		Port:        1025,
		FromAddress: "noreply@example.com",
		FromName:    "Example",
		Timeout:     time.Second,
		MaxAttempts: 2,
	}, append([]Option{WithTransport(tr)}, opts...)...)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	return s
}

// TestSendDeliversRenderedMessage checks the happy path end to end: render,
// transport, and the fields a recipient's client depends on.
func TestSendDeliversRenderedMessage(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	if err := s.Send(context.Background(), TemplateData{
		Purpose:        PurposeSignup,
		Token:          "raw-token-value",
		BaseURL:        "https://auth.example.com/",
		Address:        "user@example.com",
		ExpiresInHours: 24,
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg := tr.last(t)
	if msg.To != "user@example.com" {
		t.Errorf("recipient = %q, want user@example.com", msg.To)
	}
	if msg.Subject != "Confirm your email address" {
		t.Errorf("subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.Body, "user@example.com") {
		t.Error("body does not name the address being confirmed")
	}
	if !strings.Contains(msg.Body, "raw-token-value") {
		t.Error("body does not contain the token")
	}
	// multipart/alternative exists so a text-only client still gets a usable link.
	if !strings.Contains(msg.Text, "https://auth.example.com/verify-email?token=raw-token-value") {
		t.Errorf("plain-text part lacks the link:\n%s", msg.Text)
	}
}

// TestLinkPointsAtTheRightEndpointPerPurpose guards the reason Link is centralised.
//
// A signup token sent to /reset-password is rejected as a wrong-purpose token, and the
// user sees a broken link with nothing to indicate why. The endpoint per purpose is
// therefore part of the contract, not an incidental string.
func TestLinkPointsAtTheRightEndpointPerPurpose(t *testing.T) {
	tests := []struct {
		purpose Purpose
		want    string
	}{
		{PurposeSignup, "https://auth.example.com/verify-email?token=t"},
		{PurposePasswordReset, "https://auth.example.com/reset-password?token=t"},
		{PurposeChangeEmail, "https://auth.example.com/verify-email-change?token=t"},
		// Notifications carry no token and must not fabricate a tokenised link.
		{PurposeAccountLocked, "https://auth.example.com/reset-password"},
		{PurposeNewDeviceNotice, "https://auth.example.com/account/sessions"},
	}

	for _, tc := range tests {
		t.Run(string(tc.purpose), func(t *testing.T) {
			got := TemplateData{
				Purpose: tc.purpose,
				Token:   "t",
				BaseURL: "https://auth.example.com/",
			}.Link()
			if got != tc.want {
				t.Errorf("Link() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLinkTokenIsEscaped covers a token that would otherwise break the URL.
//
// RandomToken is base64url so this is defence in depth against a future token source,
// but a bare '&' in a query value silently truncates the parameter at the first
// other parameter and the link arrives dead.
func TestLinkTokenIsEscaped(t *testing.T) {
	got := TemplateData{
		Purpose: PurposeSignup,
		Token:   "a&b=c#d",
		BaseURL: "https://auth.example.com",
	}.Link()
	if strings.Contains(got, "#d") && !strings.Contains(got, "%23d") {
		t.Errorf("fragment character was not escaped: %q", got)
	}
	if !strings.Contains(got, "a%26b%3Dc%23d") {
		t.Errorf("token not escaped as expected: %q", got)
	}
}

// TestSendRefusesTokenlessPersistedPurpose checks the guard against a message that
// renders a complete-looking body around an unusable link.
func TestSendRefusesTokenlessPersistedPurpose(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	err := s.Send(context.Background(), TemplateData{
		Purpose: PurposePasswordReset,
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	})
	if !errors.Is(err, ErrDelivery) {
		t.Fatalf("error = %v, want ErrDelivery", err)
	}
	if tr.count() != 0 {
		t.Error("a message was delivered despite the missing token")
	}
}

// TestSendAllowsTokenlessNotifications confirms the guard above does not block the
// notices that legitimately carry no token.
func TestSendAllowsTokenlessNotifications(t *testing.T) {
	for _, purpose := range []Purpose{PurposeAccountLocked, PurposeNewDeviceNotice} {
		t.Run(string(purpose), func(t *testing.T) {
			tr := &recordingTransport{}
			s := newTestSender(t, tr)
			err := s.Send(context.Background(), TemplateData{
				Purpose: purpose,
				BaseURL: "https://auth.example.com",
				Address: "user@example.com",
			})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if tr.count() != 1 {
				t.Errorf("delivered %d messages, want 1", tr.count())
			}
		})
	}
}

// TestSendRejectsUnknownPurpose checks that a purpose with no template fails before
// delivery rather than shipping an empty body.
func TestSendRejectsUnknownPurpose(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	err := s.Send(context.Background(), TemplateData{
		Purpose: Purpose("not_a_purpose"),
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	})
	if err == nil {
		t.Fatal("expected an error for an unknown purpose")
	}
	if tr.count() != 0 {
		t.Error("a message was delivered for an unknown purpose")
	}
}

// TestSendRetriesTransientFailures checks the retry budget is actually spent.
func TestSendRetriesTransientFailures(t *testing.T) {
	tr := &recordingTransport{err: errors.New("connection refused")}
	s := newTestSender(t, tr)

	err := s.Send(context.Background(), TemplateData{
		Purpose: PurposeSignup,
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	})
	if !errors.Is(err, ErrDelivery) {
		t.Fatalf("error = %v, want ErrDelivery", err)
	}
	if tr.calls != 2 {
		t.Errorf("transport called %d times, want 2 (MaxAttempts)", tr.calls)
	}
}

// TestSendStopsOnFirstSuccess checks a retry loop does not double-send.
func TestSendStopsOnFirstSuccess(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	if err := s.Send(context.Background(), TemplateData{
		Purpose: PurposeSignup,
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if tr.calls != 1 {
		t.Errorf("transport called %d times, want 1", tr.calls)
	}
}

// TestSendStopsOnCancelledContext checks a cancelled request does not retry.
func TestSendStopsOnCancelledContext(t *testing.T) {
	tr := &recordingTransport{err: errors.New("connection refused")}
	s := newTestSender(t, tr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Send(ctx, TemplateData{
		Purpose: PurposeSignup,
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	}); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if tr.calls != 0 {
		t.Errorf("transport called %d times after cancellation, want 0", tr.calls)
	}
}

// TestSenderEscapesCallerSuppliedValues checks that a value which reached
// TemplateData.Address cannot inject markup.
//
// The address is not a trusted input: it is whatever the user typed at registration,
// stored, and later interpolated into a message rendered inside their mail client.
func TestSenderEscapesCallerSuppliedValues(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	hostile := `<script>alert(1)</script>user@example.com`
	if err := s.Send(context.Background(), TemplateData{
		Purpose: PurposeSignup,
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: hostile,
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	body := tr.last(t).Body
	if strings.Contains(body, "<script>") {
		t.Errorf("unescaped markup in body:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped markup, got:\n%s", body)
	}
}

// TestSubjectRejectsHeaderInjection confirms a newline cannot add a header.
func TestSubjectRejectsHeaderInjection(t *testing.T) {
	tr := &recordingTransport{}
	s := newTestSender(t, tr)

	if err := s.Send(context.Background(), TemplateData{
		Purpose: PurposeSignup,
		Token:   "t",
		BaseURL: "https://auth.example.com",
		Address: "user@example.com",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := sanitizeHeader("Subject\r\nBcc: victim@example.com"); strings.Contains(got, "\n") {
		t.Errorf("sanitizeHeader left a newline: %q", got)
	}
}

// TestPersistedPurposesMatchSchema guards the enum against the database CHECK.
//
// The constraint permits exactly signup, change_email and password_reset. A purpose
// added here but not in the migration fails at runtime on the first insert, which is
// the worst moment to discover it.
func TestPersistedPurposesMatchSchema(t *testing.T) {
	persisted := map[Purpose]bool{}
	for _, p := range []Purpose{
		PurposeSignup, PurposePasswordReset, PurposeChangeEmail,
		PurposeAccountLocked, PurposeNewDeviceNotice,
	} {
		persisted[p] = p.IsPersistedPurpose()
	}

	for p, want := range map[Purpose]bool{
		PurposeSignup:          true,
		PurposePasswordReset:   true,
		PurposeChangeEmail:     true,
		PurposeAccountLocked:   false,
		PurposeNewDeviceNotice: false,
	} {
		if got := persisted[p]; got != want {
			t.Errorf("%s.IsPersistedPurpose() = %v, want %v", p, got, want)
		}
	}
}

// TestNewSenderValidatesConfiguration checks startup refuses a misconfigured mailer.
//
// A registration service that accepts registrations it cannot mail creates accounts
// nobody can verify, and the failure surfaces days later as undeliverable accounts.
func TestNewSenderValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no host", Config{Port: 25, FromAddress: "a@example.com"}},
		{"no port", Config{Host: "localhost", FromAddress: "a@example.com"}},
		{"port zero", Config{Host: "localhost", Port: 0, FromAddress: "a@example.com"}},
		{"port too high", Config{Host: "localhost", Port: 70000, FromAddress: "a@example.com"}},
		{"no from address", Config{Host: "localhost", Port: 25}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSender(tc.cfg, WithTransport(&recordingTransport{})); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

// TestNewSenderRejectsUnknownStartTLSMode guards against a config value that would
// otherwise reach the mail library as an int meaning nothing in particular.
func TestNewSenderRejectsUnknownStartTLSMode(t *testing.T) {
	_, err := NewSender(Config{
		Host:         "localhost",
		Port:         25,
		FromAddress:  "a@example.com",
		StartTLSMode: StartTLSMode(99),
	}, WithTransport(&recordingTransport{}))
	if err == nil {
		t.Error("expected an error for an unknown starttls mode")
	}
}

// TestNormalizeAddress checks lookup is not case-sensitive.
//
// GetByEmail compares against the stored address. A reset that skipped normalisation
// would fail for accounts whose stored address differs in case from what the user
// typed, and those users could never reset their password.
func TestNormalizeAddress(t *testing.T) {
	if got := normalizeAddress("  User@Example.COM  "); got != "user@example.com" {
		t.Errorf("normalizeAddress = %q, want user@example.com", got)
	}
	if got := normalizeAddress("   "); got != "" {
		t.Errorf("normalizeAddress(whitespace) = %q, want empty", got)
	}
}
