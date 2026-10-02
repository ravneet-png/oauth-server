package audit

// Audit writer. Uses typed event structs rather than a free-form map, so that no code path can place personally identifiable data into an event by accident.

import (
	"context"
	"log/slog"
	"net/netip"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// Sink is the persistence an audit Logger writes to.
//
// An interface rather than *storage.AuditRepo so tests can assert on what was
// recorded without a database, and so an alternative sink (a shipper, a queue) can
// be substituted without touching call sites.
type Sink interface {
	Log(ctx context.Context, e *domain.AuditEvent) error
	LogBatch(ctx context.Context, events []domain.AuditEvent) error
}

// Logger records security events.
//
// Every method takes the pseudonymisation key rather than an address, so that no
// call site can pass raw personal data into an event by mistake: the conversion
// happens here, once, in one place that can be audited.
type Logger struct {
	sink   Sink
	pepper []byte
	log    *slog.Logger
}

// NewLogger builds a Logger writing to sink, pseudonymising actors with pepper.
//
// pepper must be the same secret used at erasure time. If it differs, anonymisation
// matches no rows and the erasure silently does nothing while reporting success,
// which is the failure mode this constructor exists to make impossible to reach by
// accident: the pepper is required, not optional.
func NewLogger(sink Sink, pepper []byte, logger *slog.Logger) *Logger {
	if len(pepper) == 0 {
		// An empty HMAC key still produces stable digests, so the code would
		// compile and every event would carry an unsalted-equivalent identifier.
		// Refusing is the only way to make a misconfiguration loud.
		panic("audit: NewLogger requires a non-empty pepper")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Logger{sink: sink, pepper: pepper, log: logger}
}

// Pseudonym converts an email address into the stable identifier stored in
// actor and target.
//
// HMAC-SHA256 under a server-side pepper, not a bare hash. An email address is low
// entropy and drawn from a small space: a plain SHA-256 of a known address is
// recoverable instantly from any rainbow table, or by brute force over the
// plausible list of a registrar's customers. With a pepper that never leaves the
// server, the same digest is not computable by anyone holding only the database.
//
// The identifier is deliberately stable rather than per-request random, because
// "every event for this user" is the query an incident response needs, and a
// per-request pseudonym would make it unanswerable.
func (l *Logger) Pseudonym(identifier string) string {
	if identifier == "" {
		return ""
	}
	return pseudonymousIdentifier(identifier, l.pepper)
}

// pseudonymousIdentifier is the package-level form, used by handlers that need to
// compute an audit identity without a Logger in hand (for example to match rows
// during erasure).
func pseudonymousIdentifier(identifier string, pepper []byte) string {
	return crypto.HMACIdentifierHex(identifier, pepper)
}

// Log records one event.
//
// A sink failure is returned AND logged, never swallowed silently. The security
// argument for returning it: a caller can choose to fail an operation it cannot
// audit, whereas nobody can detect a missing audit row after the fact. Swallowing
// here would make "we log all security events" false in exactly the situations where
// the database is already unhealthy.
func (l *Logger) Log(ctx context.Context, e domain.AuditEvent) error {
	if l.sink == nil {
		return nil
	}
	if err := l.sink.Log(ctx, &e); err != nil {
		l.log.Error("audit log write failed",
			"event", e.Event,
			"outcome", e.Outcome,
			"error", err.Error(),
		)
		return err
	}
	return nil
}

// LogBatch records several events as one unit.
func (l *Logger) LogBatch(ctx context.Context, events []domain.AuditEvent) error {
	if l.sink == nil || len(events) == 0 {
		return nil
	}
	if err := l.sink.LogBatch(ctx, events); err != nil {
		l.log.Error("audit log batch write failed", "count", len(events), "error", err.Error())
		return err
	}
	return nil
}

// RequestContext carries the per-request facts that attach to every event.
type RequestContext struct {
	CorrelationID string
	IPAddress     *netip.Addr
	UserAgent     string
	SessionID     string
}

// Apply stamps the request facts onto an event.
func (rc RequestContext) Apply(e domain.AuditEvent) domain.AuditEvent {
	if rc.CorrelationID != "" {
		e = e.WithCorrelation(rc.CorrelationID)
	}
	if rc.IPAddress != nil {
		e = e.WithClientIP(rc.IPAddress)
	}
	if rc.UserAgent != "" {
		e = e.WithUserAgent(rc.UserAgent)
	}
	if rc.SessionID != "" {
		e = e.WithSession(rc.SessionID)
	}
	return e
}

// Record is the common path: pseudonymise an actor, stamp the request context,
// and write.
//
// actorEmail is an email address or a raw user id; both are low-entropy and both are
// pseudonymised identically, because both are personal identifiers under GDPR and
// neither should appear in the log as given.
func (l *Logger) Record(ctx context.Context, rc RequestContext, e domain.AuditEvent, actorEmail string) error {
	if actorEmail != "" {
		p := l.Pseudonym(actorEmail)
		e.Actor = &p
	}
	e = rc.Apply(e)
	return l.Log(ctx, e)
}

// Ensure the storage package is referenced so a future Sink implementation here
// does not silently diverge from the repo's signature.
var _ Sink = (*storage.AuditRepo)(nil)
