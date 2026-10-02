package flows

// Client credentials grant. Public clients are refused, and openid is rejected because there is no subject.
//
// The token subject is the client_id (RFC 9068 section 2.1) and user_id stays NULL
// through persistence. Both halves matter: a client-credentials token that claimed a
// user subject would let a client present tokens as though a person had authorised
// them, and one with an empty subject would be un-attributable at the resource server.

import (
	"context"
	"fmt"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// ExchangeClientCredentials exchanges client credentials for an access token.
//
// Public clients are refused. openid scope is rejected because there is no
// end-user subject. No refresh token is issued.
func ExchangeClientCredentials(ctx context.Context,
	client *domain.Client,
	requestedScope []string,
	accessTokenRepo *storage.AccessTokenRepo,
	auditRepo *storage.AuditRepo,
	accessBuilder *tokens.AccessTokenBuilder,
	accessTTL time.Duration,
	tokenEndpoint string,
) (*TokenResponse, error) {

	// Public clients cannot use client_credentials
	if !client.IsConfidential() {
		return nil, domain.NewUnauthorizedClient("public clients cannot use client_credentials")
	}

	// The client must have been registered for this grant. Without the check a client
	// registered only for authorization_code could mint a machine token, which is a
	// privilege escalation performed entirely within the rules the client was given.
	if !client.SupportsGrant(domain.GrantClientCredentials) {
		return nil, domain.NewUnauthorizedClient("client is not registered for client_credentials")
	}

	// Requested scope is optional. The repository writes the scope array straight to a
	// NOT NULL column, and a nil slice becomes SQL NULL, so an omitted scope would
	// otherwise fail the insert and surface as a 500 on a perfectly valid request.
	if requestedScope == nil {
		requestedScope = []string{}
	}

	// Validate scopes
	if !domain.ScopeContainsAll(client.Scopes, requestedScope) {
		return nil, domain.NewInvalidScope("requested scopes not permitted for client")
	}

	// openid is not allowed
	if domain.ScopeContains(requestedScope, "openid") {
		return nil, domain.NewInvalidScope("openid scope not allowed for client_credentials")
	}

	// Build the access token.
	//
	// Subject is the client_id, not empty.
	//
	// There is no end user in this grant, but "no subject" cannot be expressed as an
	// empty string: the builder rejects it precisely because a token with no subject
	// is valid-looking and identifies nobody, so a resource server asked "who is this"
	// gets a blank answer it may not check. RFC 9068 section 2.1 resolves this
	// explicitly — for a client-credentials token the subject is the client_id — so
	// the token says "this is client X acting for itself" rather than nothing.
	//
	// The user_id column of issued_access_tokens stays NULL. The subject is the
	// client; recording the client there would make every client-credentials token
	// look like it was issued to a user of that name, and erasure would try to act
	// on it.
	accessTokenResp, err := accessBuilder.Build(ctx, tokens.AccessTokenParams{
		UserID:   client.ClientID,
		ClientID: client.ClientID,
		Audience: tokenEndpoint,
		Scopes:   requestedScope,
		TTL:      accessTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("flows: build access token: %w", err)
	}

	accessToken := accessTokenResp.Token
	jti := accessTokenResp.JTI
	exp := accessTokenResp.ExpiresAt

	// Track issued token
	issuedAccess := &domain.IssuedAccessToken{
		JTI:                jti,
		UserID:             nil,
		ClientID:           client.ClientID,
		Scope:              requestedScope,
		SessionID:          nil,
		SourceAuthCodeHash: nil,
		ExpiresAt:          exp,
	}
	if err := accessTokenRepo.Track(ctx, issuedAccess); err != nil {
		return nil, fmt.Errorf("flows: track access token: %w", err)
	}

	// Audit
	if auditRepo != nil {
		evt := domain.NewAuditEvent(domain.AuditTokenIssued, domain.AuditOutcomeSuccess, nil).
			WithClient(client.ClientID).
			WithReason("client credentials access token issued")
		_ = auditRepo.Log(ctx, &evt)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		Scope:       domain.JoinScope(requestedScope),
	}, nil
}
