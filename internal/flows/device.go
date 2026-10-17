package flows

// Device Authorization Grant (RFC 8628). Two halves live here: minting a device
// authorization at the device authorization endpoint, and the poll state machine the
// device drives against the token endpoint.
//
// The split between device_code and user_code is the security model of the whole
// grant, and it is enforced by which half touches which value. The device_code is a
// bearer secret that never leaves the device and is stored only as a digest; the
// user_code is a short, guildable string the user types on a *different* device, and
// it is not a credential at all. Redeeming tokens requires the device_code, so a
// person who sees the user_code on a screen cannot turn it into a token.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// DeviceSlowDownIncrement is how much RFC 8628 section 3.5 adds to the poll
// interval after a client polls too fast.
//
// Five seconds is the value the RFC names. A fixed increment rather than doubling:
// doubling lets one early poll from a client with a long interval push it so far out
// that the user gives up waiting for a login that had already succeeded.
const DeviceSlowDownIncrement = 5 * time.Second

// maxUserCodeAttempts bounds the retry loop that allocates a user_code.
//
// The partial unique index on live codes is what actually resolves a collision; this
// only exists so a pathological RNG or a corrupted index becomes an error instead of
// an infinite loop. Eight characters over a twenty-symbol alphabet make a collision
// negligible, so exhausting these attempts means something is wrong, not unlucky.
const maxUserCodeAttempts = 5

// DeviceAuthorization is a freshly issued device authorization, as returned to a
// client at the device authorization endpoint (RFC 8628 section 3.2).
type DeviceAuthorization struct {
	// DeviceCode is the high-entropy secret the device polls with. Returned once
	// and never stored in plaintext.
	DeviceCode string

	// UserCode is the short code the user types on the verification page, in its
	// display form (with the hyphen) for readability. Lookup normalises it.
	UserCode string

	ExpiresIn int
	Interval  int
	Scope     []string
}

// IssueDeviceAuthorization creates a device authorization for client.
//
// The device_code is minted here and only its digest is stored. The user_code may
// collide with a live one — the database enforces uniqueness — so allocation is a
// short retry loop that first clears an expired row still holding the code before
// drawing a fresh one.
func IssueDeviceAuthorization(ctx context.Context,
	client *domain.Client,
	requestedScope []string,
	deviceCodeRepo *storage.DeviceCodeRepo,
	auditRepo *storage.AuditRepo,
	ttl time.Duration,
	interval time.Duration,
) (*DeviceAuthorization, error) {

	if !client.SupportsGrant(domain.GrantDeviceCode) {
		return nil, domain.NewUnauthorizedClient("client is not registered for the device authorization grant")
	}
	// Both come from configuration and are validated at load time, but a zero here
	// would mint a code that is already expired or an interval that means "poll as
	// fast as you like", so it is checked rather than trusted.
	if ttl <= 0 {
		return nil, domain.NewServerError("device code ttl is not configured")
	}
	if interval <= 0 {
		return nil, domain.NewServerError("device code interval is not configured")
	}

	// An omitted scope is an empty set, not "all of them". The client may only ever
	// receive scopes it is registered for, so the requested set has to be a subset of
	// the registration and never the other way round.
	if requestedScope == nil {
		requestedScope = []string{}
	}
	if !domain.ScopeContainsAll(client.Scopes, requestedScope) {
		return nil, domain.NewInvalidScope("requested scopes not permitted for client")
	}

	raw, err := crypto.RandomToken()
	if err != nil {
		return nil, fmt.Errorf("flows: generate device code: %w", err)
	}
	hash := crypto.SHA256Hex(raw)

	now := time.Now().UTC()
	var userCode string
	for attempt := 0; attempt < maxUserCodeAttempts; attempt++ {
		display, err := domain.GenerateUserCode()
		if err != nil {
			return nil, fmt.Errorf("flows: generate user code: %w", err)
		}
		candidate := domain.NormalizeUserCode(display)

		dc := &domain.DeviceCode{
			DeviceCodeHash: hash,
			UserCode:       candidate,
			ClientID:       client.ClientID,
			Scope:          requestedScope,
			Status:         domain.DeviceStatusPending,
			Interval:       interval,
			CreatedAt:      now,
			ExpiresAt:      now.Add(ttl),
		}
		err = deviceCodeRepo.Create(ctx, dc)
		if err == nil {
			userCode = display
			break
		}
		if !errors.Is(err, domain.ErrConflict) {
			return nil, fmt.Errorf("flows: create device code: %w", err)
		}
		// The collision is with a row the reaper has not collected yet. Clear the
		// expired holder of the code and try another; a live collision is resolved by
		// drawing a different code, not by evicting the live one.
		if delErr := deviceCodeRepo.DeleteExpiredByUserCode(ctx, candidate); delErr != nil {
			return nil, fmt.Errorf("flows: clear expired user code: %w", delErr)
		}
	}
	if userCode == "" {
		return nil, domain.NewServerError("could not allocate a unique user code")
	}

	// No actor: at this point nobody has authenticated, which is the point of the
	// grant. The client is recorded in its own column so an operator can see which
	// application asked and when.
	if auditRepo != nil {
		evt := domain.NewAuditEvent(domain.AuditDeviceCodeIssued, domain.AuditOutcomeSuccess, nil).
			WithClient(client.ClientID).
			WithResource("client", client.ClientID).
			WithReason("device authorization requested")
		_ = auditRepo.Log(ctx, &evt)
	}

	return &DeviceAuthorization{
		DeviceCode: raw,
		UserCode:   userCode,
		ExpiresIn:  int(ttl.Seconds()),
		Interval:   int(interval.Seconds()),
		Scope:      requestedScope,
	}, nil
}

// ExchangeDeviceCode performs one poll of the device authorization grant at the token
// endpoint (RFC 8628 sections 3.4 and 3.5).
//
// Each of the four outcomes the RFC defines maps to one error code. Only the pending
// case mutates anything: a well-timed poll is stamped so the next one can be judged, a
// too-fast poll is refused with slow_down and widens the interval, and an approved code
// is atomically consumed before any token is minted.
func ExchangeDeviceCode(ctx context.Context,
	client *domain.Client,
	deviceCode string,
	deviceCodeRepo *storage.DeviceCodeRepo,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	familyRepo *storage.TokenFamilyRepo,
	userRepo *storage.UserRepo,
	auditRepo *storage.AuditRepo,
	accessBuilder *tokens.AccessTokenBuilder,
	idBuilder *tokens.IDTokenBuilder,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	idTTL time.Duration,
	familyAbsoluteTTL time.Duration,
	tokenEndpoint string,
) (*TokenResponse, error) {

	if !client.SupportsGrant(domain.GrantDeviceCode) {
		return nil, domain.NewUnauthorizedClient("client is not registered for the device authorization grant")
	}

	hash := crypto.SHA256Hex(deviceCode)
	dc, err := deviceCodeRepo.GetByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("flows: get device code: %w", err)
	}
	// Unknown and reaped are the same answer as expired. A client that keeps polling a
	// code the server no longer holds must stop, and the two are deliberately
	// indistinguishable from outside.
	if dc == nil {
		return nil, domain.NewExpiredToken("device code is invalid or has expired")
	}
	// A device_code is only redeemable by the client it was issued to. checked before
	// expiry so that a wrong-client probe yields invalid_grant rather than leaking
	// whether the code exists and is live.
	if !dc.OwnedBy(client.ClientID) {
		return nil, domain.NewInvalidGrant("device code was not issued to this client")
	}

	now := time.Now().UTC()
	// Expiry before status: a lapsed approval must not be redeemable just because the
	// user once said yes.
	if dc.IsExpired(now) {
		return nil, domain.NewExpiredToken("device code has expired")
	}

	switch {
	case dc.IsDenied():
		return nil, domain.NewTokenAccessDenied("the user denied the request")

	case dc.IsConsumed():
		return nil, domain.NewInvalidGrant("device code has already been used")

	case dc.IsApproved():
		claimed, err := deviceCodeRepo.Consume(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("flows: consume device code: %w", err)
		}
		// Lost the race to a concurrent poll of the same approved code. Exactly one
		// token set is minted; the loser gets invalid_grant.
		if claimed == nil {
			return nil, domain.NewInvalidGrant("device code has already been used")
		}
		return issueDeviceTokens(ctx, claimed, client,
			userRepo, accessTokenRepo, refreshTokenRepo, familyRepo, auditRepo,
			accessBuilder, idBuilder, accessTTL, refreshTTL, idTTL, familyAbsoluteTTL, tokenEndpoint)

	default:
		// Pending. Stamp the poll if it respected the interval, otherwise widen the
		// interval and tell the client to slow down.
		admitted, err := deviceCodeRepo.RecordPoll(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("flows: record poll: %w", err)
		}
		if !admitted {
			// Best effort: the interval bump is a mitigation, and failing the request
			// here would answer server_error instead of the slow_down the client needs
			// to see in order to correct itself.
			_ = deviceCodeRepo.BumpInterval(ctx, hash, DeviceSlowDownIncrement)
			return nil, domain.NewSlowDown("polling too frequently")
		}
		return nil, domain.NewAuthorizationPending("the user has not yet approved the request")
	}
}

// issueDeviceTokens mints the token set for an approved device authorization.
//
// Called with the row Consume returned, so this runs at most once per device code.
// Tokens are issued to the user who approved on the verification page and are not tied
// to a browser session: the device is the holder, and scoping revocation to the
// approver's session would strand the device's refresh token when that browser logs
// out.
func issueDeviceTokens(ctx context.Context,
	claimed *domain.DeviceCode,
	client *domain.Client,
	userRepo *storage.UserRepo,
	accessTokenRepo *storage.AccessTokenRepo,
	refreshTokenRepo *storage.RefreshTokenRepo,
	familyRepo *storage.TokenFamilyRepo,
	auditRepo *storage.AuditRepo,
	accessBuilder *tokens.AccessTokenBuilder,
	idBuilder *tokens.IDTokenBuilder,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	idTTL time.Duration,
	familyAbsoluteTTL time.Duration,
	tokenEndpoint string,
) (*TokenResponse, error) {

	// The subject constraint guarantees an approved row has a user, but a nil here
	// would mint a token identifying nobody, so it is checked rather than dereferenced
	// blind.
	if claimed.UserID == nil || *claimed.UserID == "" {
		return nil, domain.NewServerError("approved device code has no subject")
	}
	userID := *claimed.UserID

	now := time.Now().UTC()

	familyID, err := crypto.RandomToken()
	if err != nil {
		return nil, fmt.Errorf("flows: generate family id: %w", err)
	}
	// The family row first: refresh_tokens.family_id is a foreign key. The family's
	// absolute ceiling bounds how long rotation can keep this grant alive.
	if err := familyRepo.Ensure(ctx, &domain.TokenFamily{
		FamilyID:          familyID,
		UserID:            userID,
		ClientID:          client.ClientID,
		AbsoluteExpiresAt: now.Add(familyAbsoluteTTL),
	}); err != nil {
		return nil, fmt.Errorf("flows: ensure token family: %w", err)
	}

	user, err := userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("flows: get user: %w", err)
	}

	accessResp, err := accessBuilder.Build(ctx, tokens.AccessTokenParams{
		UserID:   user.UserID,
		ClientID: client.ClientID,
		Audience: tokenEndpoint,
		Scopes:   claimed.Scope,
		TTL:      accessTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("flows: build access token: %w", err)
	}

	// No session id, deliberately. A device token belongs to the device, not to the
	// browser that approved it; recording the approver's session here would let a
	// logout in that browser revoke a token the device still legitimately holds.
	if err := accessTokenRepo.Track(ctx, &domain.IssuedAccessToken{
		JTI:       accessResp.JTI,
		UserID:    &userID,
		ClientID:  client.ClientID,
		Scope:     claimed.Scope,
		ExpiresAt: accessResp.ExpiresAt,
	}); err != nil {
		return nil, fmt.Errorf("flows: track access token: %w", err)
	}

	rt, err := tokens.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("flows: generate refresh token: %w", err)
	}
	if err := refreshTokenRepo.Create(ctx, &domain.RefreshToken{
		TokenHash: rt.Hash,
		FamilyID:  familyID,
		ClientID:  client.ClientID,
		UserID:    userID,
		Scope:     claimed.Scope,
		ExpiresAt: now.Add(refreshTTL),
		CreatedAt: now,
	}); err != nil {
		return nil, fmt.Errorf("flows: create refresh token: %w", err)
	}

	// An ID token only when the grant carried `openid`. A device flow without it is a
	// plain OAuth grant, and an ID token there would assert an identity nobody asked
	// to verify.
	var idToken string
	if domain.ScopeContains(claimed.Scope, "openid") {
		idToken, err = idBuilder.Build(ctx, tokens.IDTokenParams{
			User:        user,
			ClientID:    client.ClientID,
			AccessToken: accessResp.Token,
			Scopes:      claimed.Scope,
			TTL:         idTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("flows: build id token: %w", err)
		}
	}

	if auditRepo != nil {
		evt := domain.NewAuditEvent(domain.AuditTokenIssued, domain.AuditOutcomeSuccess, &userID).
			WithClient(client.ClientID).
			WithReason("device_code grant")
		_ = auditRepo.Log(ctx, &evt)
	}

	return &TokenResponse{
		AccessToken:  accessResp.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: rt.Opaque,
		IDToken:      idToken,
		Scope:        domain.JoinScope(claimed.Scope),
	}, nil
}
