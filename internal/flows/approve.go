package flows

// Authorization approval: the step that turns a consented, authenticated request into
// an authorization code.
//
// This is deliberately separate from HandleAuthorize. That function's job ends when it
// decides *whether* a request is well formed and which screen to show; by the time
// approval happens a user has typed a password and pressed a button, and the set of
// things that can go wrong is different. Folding them together would put the consent
// decision and the code issuance in one function whose state has ten ways to be
// half-advanced.

import (
	"context"
	"fmt"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// ApproveParams is the input to ApproveAuthorization.
type ApproveParams struct {
	// AuthRequestID is the request being approved.
	AuthRequestID string

	// UserID is the authenticated subject. Checked against the request, not trusted:
	// a stale consent page left open across a logout/login must not mint a code for
	// the previous user.
	UserID string

	// SessionID and SID identify the browser session. SID is the per-client session
	// id that later appears in ID tokens and LogoutTokens, so it is generated here if
	// the caller has not resolved one.
	SessionID string
	SID       string

	// Scope is the set actually granted, after the consent screen has dropped any the
	// user refused. It must be a subset of what /authorize validated; the code carries
	// it so /token can re-check the exact value rather than re-reading the client row,
	// which may have changed in between.
	Scope []string

	// AuthTime is when the user actually authenticated, not when they clicked. It
	// flows into the ID token so a client can reject a session older than its policy
	// allows.
	AuthTime time.Time

	// CodeTTL is how long the issued code stays redeemable.
	CodeTTL time.Duration

	// RefreshAbsoluteTTL is the ceiling for the refresh-token family this grant seeds.
	// The family is created here, not at first refresh, because auth_codes.family_id is
	// a foreign key: a code carrying a minted id with no row behind it cannot be
	// inserted at all.
	RefreshAbsoluteTTL time.Duration
}

// ApproveAuthorization issues an authorization code for a consented request.
//
// Ordering is the whole design. The request is claimed first, with the conditional
// UPDATE that is the single-use guard, and only then is a code inserted. Reversing that
// — insert, then claim — lets two concurrent submissions of the same consent form each
// insert a code while only one claim succeeds, leaving a live code that no request
// references and no later step can revoke. Claim-then-issue can instead leave a claimed
// request with no code, which is a user who sees an error and retries; that is the safe
// direction and the only one of the two that fails closed.
//
// Returns the validated request so the caller can build the redirect from the stored
// values rather than from anything the client supplied at approval time.
func ApproveAuthorization(ctx context.Context,
	authReqRepo *storage.AuthRequestRepo,
	codeRepo *storage.AuthCodeRepo,
	clientSessRepo *storage.ClientSessionRepo,
	familyRepo *storage.TokenFamilyRepo,
	params ApproveParams,
) (*domain.AuthRequest, string, error) {

	if params.AuthRequestID == "" {
		return nil, "", domain.NewInvalidRequest("authorization request is required")
	}
	if params.UserID == "" {
		return nil, "", domain.NewAccessDenied("no authenticated user")
	}
	if params.CodeTTL <= 0 {
		return nil, "", domain.NewServerError("authorization code ttl is not configured")
	}

	now := time.Now().UTC()

	req, err := authReqRepo.GetByID(ctx, params.AuthRequestID)
	if err != nil {
		// Unknown, expired and reaped all report the same thing. A user who left the
		// consent page open overnight gets "start again", which is true, and an
		// attacker enumerating request ids learns nothing from the difference.
		return nil, "", domain.NewInvalidRequest("authorization request is unknown or has expired")
	}
	if req.IsCompleted() {
		return nil, "", domain.NewInvalidRequest("authorization request has already been completed")
	}
	if req.IsExpired(now) {
		return nil, "", domain.NewInvalidRequest("authorization request has expired")
	}
	// The request must belong to the user approving it. A NULL UserID means login
	// never completed, so approval is premature rather than merely suspicious; both
	// are refused with the same code.
	if req.UserID == nil || *req.UserID != params.UserID {
		return nil, "", domain.NewAccessDenied("authorization request does not belong to this user")
	}

	// Claim the request. This is the single-use guard for code issuance; without it a
	// double-submitted consent form mints two codes from one request.
	claimed, err := authReqRepo.MarkCompleted(ctx, req.ID)
	if err != nil {
		return nil, "", fmt.Errorf("flows: mark auth request complete: %w", err)
	}
	if !claimed {
		return nil, "", domain.NewInvalidRequest("authorization request has already been completed")
	}

	// Generate the code, its digest, and the two identifiers that let it be traced.
	code, err := crypto.RandomToken()
	if err != nil {
		return nil, "", fmt.Errorf("flows: generate authorization code: %w", err)
	}
	familyID, err := crypto.RandomToken()
	if err != nil {
		return nil, "", fmt.Errorf("flows: generate family ID: %w", err)
	}

	sid := params.SID
	if sid == "" {
		sid, err = crypto.RandomToken()
		if err != nil {
			return nil, "", fmt.Errorf("flows: generate sid: %w", err)
		}
	}

	// Attach the sid to the browser session before issuing the code, so a failure
	// here cannot leave a code whose sid exists in no client_sessions row. A logout
	// that could not find the sid would fail to terminate this client's session.
	sessionID := params.SessionID
	if sessionID == "" {
		return nil, "", domain.NewServerError("session id is not configured")
	}
	if err := clientSessRepo.Upsert(ctx, &domain.ClientSession{
		SID:       sid,
		SessionID: sessionID,
		ClientID:  req.ClientID,
	}); err != nil {
		return nil, "", fmt.Errorf("flows: attach client session: %w", err)
	}

	authTime := params.AuthTime
	if authTime.IsZero() {
		// The request recorded the moment of authentication; falling back to it is
		// correct, and falling back to now would overstate the freshness of a session
		// that may be hours old.
		if req.AuthTime != nil {
			authTime = *req.AuthTime
		} else {
			authTime = now
		}
	}

	// The family row first: the code below carries family_id, and it is a foreign key.
	// If this fails the user sees an error and retries a request that is still
	// unclaimed, because the claim is rolled back with the surrounding transaction
	// when the caller treats a failure as fatal.
	absoluteTTL := params.RefreshAbsoluteTTL
	if absoluteTTL <= 0 {
		return nil, "", domain.NewServerError("refresh absolute ttl is not configured")
	}
	if err := familyRepo.Ensure(ctx, &domain.TokenFamily{
		FamilyID:           familyID,
		UserID:             params.UserID,
		ClientID:           req.ClientID,
		SourceAuthCodeHash: nil,
		AbsoluteExpiresAt:  authTime.Add(absoluteTTL),
	}); err != nil {
		return nil, "", fmt.Errorf("flows: create token family: %w", err)
	}

	authCode := &domain.AuthCode{
		CodeHash:            crypto.SHA256Hex(code),
		ClientID:            req.ClientID,
		UserID:              params.UserID,
		SessionID:           stringPtr(sessionID),
		SID:                 stringPtr(sid),
		FamilyID:            stringPtr(familyID),
		Scope:               params.Scope,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		AuthTime:            &authTime,
		ExpiresAt:           now.Add(params.CodeTTL),
	}
	if err := codeRepo.Create(ctx, authCode); err != nil {
		return nil, "", fmt.Errorf("flows: create authorization code: %w", err)
	}

	// The code is returned in plaintext and exists in exactly two places: this return
	// value and the redirect the caller builds from it. Only the digest is stored.
	return req, code, nil
}

// DenyAuthorization records that the user refused a request.
//
// Marks the request complete so a back-button replay of the authorization URL cannot
// re-present the consent screen — or, worse, be approved — after the user has already
// said no. Nothing is issued and the caller redirects with access_denied.
//
// A failure to claim is not an error: it means the request was already consumed, and
// the only correct response to a denial is the same denial.
func DenyAuthorization(ctx context.Context,
	authReqRepo *storage.AuthRequestRepo,
	authRequestID string,
) error {
	if authRequestID == "" {
		return nil
	}
	if _, err := authReqRepo.MarkCompleted(ctx, authRequestID); err != nil {
		return fmt.Errorf("flows: claim denied auth request: %w", err)
	}
	return nil
}

// stringPtr returns a pointer to a copy of s.
//
// A helper rather than &s because Go reuses loop and parameter storage; taking the
// address of a parameter that a caller passes by value is fine, but the intent here is
// explicit because the resulting pointer is stored in the database and outlives the
// call.
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}
