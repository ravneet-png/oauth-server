package authz

// Scope authorisation. Computes the grantable scope set for a user, client and request, filtering out scopes the user has not yet earned. Re-evaluated on every authorization, including the auto-skip path, not only at the consent screen.

import (
	"context"
	"time"

	"oauth-server/internal/domain"
)

// ErrScopesExceedRegistration is returned when a request asks for a scope the
// client is not registered for.
//
// RFC 6749 section 5.2 names invalid_scope for exactly this case: "the requested
// scope is invalid, unknown, malformed, or exceeds the scope granted by the
// resource owner." Exceeding the client's own registration is the last clause.
//
// A distinct sentinel from a generic invalid_request because the two failures have
// opposite remediations: an unregistered scope is a client registration bug the
// developer fixes, whereas a filtered scope is a correct refusal that the user can
// remedy by completing verification. Reporting both as invalid_request makes the
// first impossible to diagnose.
var ErrScopesExceedRegistration = domain.NewInvalidScope("requested scope is not registered for this client")

// Scopes that can only be granted to a user who has completed the corresponding
// proof. The mapping is the whole reason this package exists: an unconditional
// grant would issue an `email` claim for an address nobody has ever confirmed,
// which turns the authorization server into an unauthenticated email oracle for
// any client willing to ask.
var earnedScopes = map[string]func(*domain.User) bool{
	// An unverified address is not proof of anything. RFC 6749 allows `email` to
	// be withheld, so the honest answer is to omit the claim rather than emit an
	// unverified one, and the discovery document should say so.
	"email": func(u *domain.User) bool { return u.EmailVerified },
	// `profile` describes a human being rather than a client, so it requires a
	// verified address too: without one, the values it would return are
	// attacker-supplied strings rather than attributes of an account.
	"profile": func(u *domain.User) bool { return u.EmailVerified },
	// Consent to address the account at all depends on a working channel, which
	// an unverified address is not.
	"openid": nil, // handled separately below; always grantable
}

// Request is the input to a scope decision.
type Request struct {
	User   *domain.User
	Client *domain.Client

	// Requested is the scope set from the authorization request, already
	// normalised by domain.NormalizeScope.
	Requested []string

	// Consent is the standing grant for this user and client, or nil if there is
	// none. A lapsed grant is passed through rather than pre-filtered, so
	// ExpiredConsent can tell the consent screen whether to explain a re-prompt.
	Consent *domain.Consent

	// Now is the evaluation time. Passed in rather than read from the clock so
	// that expiry behaviour is testable without sleeping, and so one authorization
	// is evaluated against one instant even if it takes a few milliseconds.
	Now time.Time
}

// Decision is the outcome of a scope evaluation.
type Decision struct {
	// Granted is the subset that may be issued as claims. Always a subset of
	// Requested, and a subset of the client's registration.
	Granted []string

	// Withheld are the requested-but-unearned scopes. Reported to the consent
	// screen rather than silently dropped: a user who cannot tell that `email` was
	// refused has no way to learn that verifying their address is the fix.
	Withheld []string

	// NeedsConsent is true when a human decision is required before issuance.
	//
	// Distinct from len(Granted) == 0: an empty grant still renders the consent
	// screen, because a silent redirect back to a client that requested nothing
	// grantable leaves no code for the client to exchange and no explanation of
	// why.
	NeedsConsent bool

	// ExpiredConsent is true when a grant existed but has lapsed, which is the
	// one case the consent screen should phrase as "your access expired" rather
	// than "you are authorising this app".
	ExpiredConsent bool

	// AutoSkip is true when an active grant already covers the grantable set.
	AutoSkip bool
}

// Evaluator computes scope decisions.
//
// Depends on the interfaces rather than the concrete repos so the consent screen,
// the auto-skip path and the tests all evaluate scopes through one implementation.
type Evaluator interface {
	Evaluate(ctx context.Context, req Request) (Decision, error)
}

// EvaluatorFunc adapts a function to Evaluator.
type EvaluatorFunc func(ctx context.Context, req Request) (Decision, error)

// Evaluate calls f.
func (f EvaluatorFunc) Evaluate(ctx context.Context, req Request) (Decision, error) {
	return f(ctx, req)
}

// ScopeEvaluator is the default Evaluator. It is stateless, so a single instance
// serves the whole application and is safe for concurrent use.
type ScopeEvaluator struct{}

// NewScopeEvaluator builds a ScopeEvaluator.
func NewScopeEvaluator() *ScopeEvaluator { return &ScopeEvaluator{} }

// Evaluate computes the grantable scope set.
//
// Three filters, in this order, because each one narrows the input of the next:
//
//  1. Registration. A client may not receive a scope it is not registered for. This
//     is enforced at authorization time rather than only at registration because a
//     client record can be edited, and an authorization server that checks scope
//     legality only at registration accepts a request for an unregistered scope
//     against a client whose registration was later narrowed.
//  2. User attributes. The remaining scopes are split into those the user has
//     earned (see earnedScopes) and those grantable to anyone.
//  3. Consent. The set the user has already agreed to, narrowed to what remains
//     grantable, which is what allows auto-skip.
//
// The order matters for security: consent is never consulted for a scope that
// failed the earned check, so an existing grant cannot launder an unearned scope
// into issuance. A user who consented to `email` while unverified, then
// verifies nothing, still gets no `email` claim.
func (e *ScopeEvaluator) Evaluate(_ context.Context, req Request) (Decision, error) {
	// A missing user or client is a wiring bug, not a request the user got wrong.
	// server_error rather than a client-facing refusal: the operator needs to see
	// it as a 500 in the access log, and a user needs never be told that the
	// authorization server has no record of them.
	if req.User == nil {
		return Decision{}, domain.NewServerError("scope evaluation called without a user")
	}
	if req.Client == nil {
		return Decision{}, domain.NewServerError("scope evaluation called without a client")
	}

	requested := domain.NormalizeScopeSet(req.Requested)
	granted := make([]string, 0, len(requested))

	for _, s := range requested {
		if !domain.ScopeContains(req.Client.Scopes, s) {
			// A scope the client may not hold is a client error, not a user-facing
			// refusal. Failing the whole request is deliberate: silently dropping
			// it would return a code that grants less than the client asked for,
			// and the client would have no way to tell that one of its scopes was
			// discarded.
			return Decision{}, ErrScopesExceedRegistration
		}
		if !isEarned(req.User, s) {
			continue
		}
		granted = append(granted, s)
	}
	granted = domain.NormalizeScopeSet(granted)

	withheld := domain.ScopeMissing(requested, granted)
	if withheld == nil {
		withheld = []string{}
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	d := Decision{
		Granted:  granted,
		Withheld: withheld,
		// Default to prompting. Set to false only when a live grant is shown to
		// cover the whole grantable set, so a bug that fails to populate Consent
		// errs toward asking the user rather than toward silently authorising.
		NeedsConsent: true,
	}

	if req.Consent != nil {
		if req.Consent.IsExpired(now) {
			d.ExpiredConsent = true
		} else if req.Consent.Covers(granted) {
			// Auto-skip.
			//
			// Checked against `granted` rather than `requested`: a grant covering
			// [openid, email] plus a request for [openid, email, profile] where the
			// user has not earned `profile` must still skip, because there is
			// nothing new to ask about. Comparing against `requested` would loop
			// the user back to a screen offering a scope that will be withheld
			// again, for ever.
			d.NeedsConsent = false
			d.AutoSkip = true
		}
	}

	return d, nil
}

// isEarned reports whether the user has proved enough to hold this scope.
//
// A scope absent from the table is grantable to any user. That default is
// deliberate in one direction only: adding a scope to the table immediately makes
// it conditional, so the secure change is the additive one.
func isEarned(u *domain.User, scope string) bool {
	check, gated := earnedScopes[scope]
	if !gated {
		return true
	}
	if check == nil {
		// `openid`: registered as gated so it appears in the table and in review,
		// but unconditional in practice. It identifies a subject and requests no
		// attribute, so withholding it for an unverified user would break
		// sign-in without protecting anything.
		return true
	}
	return check(u)
}

// EarnedScopes returns the sorted list of scopes this package treats as
// conditional, for the consent screen's "verify your email to unlock" hint and for
// the documentation that has to match the code.
func EarnedScopes() []string {
	out := make([]string, 0, len(earnedScopes))
	for s := range earnedScopes {
		out = append(out, s)
	}
	return domain.NormalizeScopeSet(out)
}
