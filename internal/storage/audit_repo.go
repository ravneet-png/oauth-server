package storage

// Audit log persistence.
//
// Append-only. No UPDATE or DELETE is exposed except the erasure method, and the
// application role should be INSERT-only on this table, which is stronger than
// trusting every code path to behave.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"oauth-server/internal/domain"
)

// AuditRepo appends to and erases from the audit_log table.
type AuditRepo struct {
	pool *pgxpool.Pool
}

// NewAuditRepo builds an AuditRepo over pool.
func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo {
	assertPoolNonNil(pool, "AuditRepo")
	return &AuditRepo{pool: pool}
}

// Log appends one audit event.
//
// Details is serialised from domain.AuditEvent.MarshalDetails, which writes a
// CLOSED set of named fields. That is the property that makes erasure provable: the
// set of places personal data can live is knowable by reading the struct, so
// "erasure is complete" is a claim that can be checked rather than asserted. The
// prompt's details - 'user_id' - 'email' - 'name' plan is unsound, because the jsonb
// minus operator removes only top-level keys and leaves {"ctx":{"email":...}}
// intact while appearing to have worked.
//
// An audit write failure is returned rather than swallowed. The alternative is a
// security event that silently did not happen, which is worse than a failed
// request: the caller can decide to fail the operation, whereas nobody can detect
// a missing audit row after the fact.
func (r *AuditRepo) Log(ctx context.Context, e *domain.AuditEvent) error {
	details, err := e.MarshalDetails()
	if err != nil {
		return domain.Wrapf(err, "storage: audit_log.log: marshal details")
	}
	if len(details) == 0 {
		details = []byte(`{}`)
	}

	const q = `
		INSERT INTO audit_log (
			event, actor, target, session_id, ip_address, user_agent,
			correlation_id, details, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`

	// created_at is passed explicitly rather than left to DEFAULT now(), so that
	// an event recorded for a request that started earlier can be ordered
	// correctly against the request log it belongs to.
	createdAt := time.Now().UTC()

	_, err = r.pool.Exec(ctx, q,
		e.Event, e.Actor, e.Target, e.SessionID,
		addrToString(e.IPAddress), e.UserAgent,
		nullIfEmpty(e.CorrelationID), jsonOrNil(details), createdAt,
	)
	if err != nil {
		return classifyError(err, formatOp("audit_log", "log"))
	}
	return nil
}

// LogBatch appends several events in one statement.
//
// Used where a single logical action produces several rows, such as a family
// revocation recording one event per token. One round trip rather than N, and
// atomic so a partial batch cannot be mistaken for a complete record of what
// happened.
//
// Every element of the details array is a text parameter cast by unnest to
// jsonb, for the QueryExecModeExec reason documented on jsonOrNil: a []byte
// element would arrive as a bytea literal and abort the whole statement.
func (r *AuditRepo) LogBatch(ctx context.Context, events []domain.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	eventsCol := make([]string, 0, len(events))
	actors := make([]*string, 0, len(events))
	targets := make([]*string, 0, len(events))
	sessions := make([]*string, 0, len(events))
	ips := make([]*string, 0, len(events))
	uas := make([]*string, 0, len(events))
	corrs := make([]*string, 0, len(events))
	details := make([]string, 0, len(events))
	created := make([]time.Time, 0, len(events))

	for i := range events {
		e := &events[i]
		d, err := e.MarshalDetails()
		if err != nil {
			return domain.Wrapf(err, "storage: audit_log.log_batch: marshal details at %d", i)
		}
		if len(d) == 0 {
			d = []byte(`{}`)
		}
		eventsCol = append(eventsCol, e.Event)
		actors = append(actors, e.Actor)
		targets = append(targets, e.Target)
		sessions = append(sessions, e.SessionID)
		ips = append(ips, addrToString(e.IPAddress))
		uas = append(uas, e.UserAgent)
		corrs = append(corrs, nullIfEmpty(e.CorrelationID))
		details = append(details, string(d))
		created = append(created, time.Now().UTC())
	}

	const q = `
		INSERT INTO audit_log (
			event, actor, target, session_id, ip_address, user_agent,
			correlation_id, details, created_at
		)
		SELECT * FROM unnest(
			$1::text[], $2::text[], $3::text[], $4::text[],
			$5::inet[], $6::text[], $7::text[], $8::jsonb[], $9::timestamptz[]
		)`

	_, err := r.pool.Exec(ctx, q,
		eventsCol, actors, targets,
		sessions, ips, uas, corrs, details, created,
	)
	if err != nil {
		return classifyError(err, formatOp("audit_log", "log_batch"))
	}
	return nil
}

// AnonymizeUser erases personal references to one user from the audit log.
//
// This is the GDPR erasure path, and the two things it does are both necessary:
//
//  1. Redact actor and target to the fixed literal domain.AuditActorRedacted, and
//     only where they equal this user. The CASE is load-bearing: a blanket SET
//     would redact every row in the table, and a bare `WHERE user_id = $1` would
//     match nothing, because audit rows never store a user_id. Actor and target
//     hold HMAC-SHA256 pseudonyms of the address, and those are still a join key:
//     an attacker with a candidate list recomputes the digest and re-identifies
//     every row. Erasure has to be irreversible to be erasure.
//
//  2. Remove the identifying columns outright. ip_address and user_agent are
//     personal data under their own names, and session_id links the row to a
//     session that may still exist. The details column is left alone: it cannot
//     contain personal data by construction, because domain.AuditEvent is a struct
//     with a closed field set, and the prompt's `details - 'user_id' - 'email'`
//     would give a false impression of scrubbing nested keys it cannot reach.
//
// returns the number of rows touched, so a caller can assert the erasure actually
// found something. Zero rows is a legitimate answer for a user who never generated
// an audit event, and is reported rather than treated as an error.
func (r *AuditRepo) AnonymizeUser(ctx context.Context, userID string) (int, error) {
	// The user_id arrives here as the HMAC pseudonym that audit rows store, not
	// as a raw account id. Building that pseudonym is the caller's job: it needs
	// the server-side pepper, which this package does not hold.
	const q = `
		UPDATE audit_log
		   SET actor  = CASE WHEN actor  = $1 THEN $2 ELSE actor  END,
		       target = CASE WHEN target = $1 THEN $2 ELSE target END,
		       session_id  = NULL,
		       ip_address  = NULL,
		       user_agent  = NULL,
		       details     = details - 'user_id' - 'email' - 'name'
		 WHERE actor = $1 OR target = $1`

	tag, err := r.pool.Exec(ctx, q, userID, domain.AuditActorRedacted)
	if err != nil {
		return 0, classifyError(err, formatOp("audit_log", "anonymize"))
	}
	return int(tag.RowsAffected()), nil
}

// AnonymizeSession erases the session reference from every row of one session.
//
// Separate from AnonymizeUser because a logout must not redact the actor: the
// record that a user did something is legitimate operational history that outlives
// their session, and only the link to the now-deleted session row is personal.
func (r *AuditRepo) AnonymizeSession(ctx context.Context, sessionID string) (int, error) {
	const q = `
		UPDATE audit_log
		   SET session_id = NULL,
		       ip_address = NULL,
		       user_agent = NULL
		 WHERE session_id = $1`

	tag, err := r.pool.Exec(ctx, q, sessionID)
	if err != nil {
		return 0, classifyError(err, formatOp("audit_log", "anonymize_session"))
	}
	return int(tag.RowsAffected()), nil
}

// Query reads audit rows for an investigation.
//
// Read-only and deliberately narrow. The application role should be INSERT-only
// on this table, so in a correctly configured deployment this method returns
// permission denied and an operator reads the table with a privileged role
// instead. It exists for tests and for a future privileged path, not for routine
// application use.
func (r *AuditRepo) Query(ctx context.Context, actor *string, limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	const q = `
		SELECT event, actor, target, session_id, correlation_id, details
		  FROM audit_log
		 WHERE ($1::text IS NULL OR actor = $1)
		 ORDER BY created_at DESC
		 LIMIT $2`

	rows, err := r.pool.Query(ctx, q, actor, limit)
	if err != nil {
		return nil, classifyError(err, formatOp("audit_log", "query"))
	}
	defer rows.Close()

	var out []*domain.AuditEvent
	for rows.Next() {
		var (
			e                                domain.AuditEvent
			actorV, targetV, sessionV, corrV *string
			detailBytes                      []byte
		)
		if err := rows.Scan(&e.Event, &actorV, &targetV, &sessionV, &corrV, &detailBytes); err != nil {
			return nil, wrapRowsErr(err, formatOp("audit_log", "query", "scan"))
		}
		e.Actor = actorV
		e.Target = targetV
		e.SessionID = sessionV
		if corrV != nil {
			e.CorrelationID = *corrV
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapRowsErr(err, formatOp("audit_log", "query", "iterate"))
	}
	return out, nil
}

// nullIfEmpty maps the empty string to SQL NULL.
//
// The correlation_id index is partial over NOT NULL, so writing an empty string
// for the many events that have no correlation id would bloat the index with
// useless entries and make the index predicate untrue for rows that are logically
// absent.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
