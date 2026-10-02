package consent

// Consent management: filtering scopes, checking existing grants, recording new ones.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// Manager handles consent operations.
type Manager struct {
	consentRepo *storage.ConsentRepo
	userRepo    *storage.UserRepo
}

// NewManager builds a consent manager.
func NewManager(consentRepo *storage.ConsentRepo, userRepo *storage.UserRepo) (*Manager, error) {
	if consentRepo == nil {
		return nil, fmt.Errorf("consent: NewManager: consentRepo is nil")
	}
	if userRepo == nil {
		return nil, fmt.Errorf("consent: NewManager: userRepo is nil")
	}
	return &Manager{
		consentRepo: consentRepo,
		userRepo:    userRepo,
	}, nil
}

// ScopeExclusion records a scope that was requested but cannot be granted, and why.
type ScopeExclusion struct {
	Scope  string
	Reason string
}

// Exclusion reasons.
//
// A fixed set rather than a formatted string per call site: these are shown to a user
// deciding whether to trust an application, so the wording is part of the interface and
// must not vary with the caller that happened to filter the scope.
const (
	ReasonNotRegistered   = "This application is not registered for this permission."
	ReasonEmailUnverified = "Your email address is not verified yet, so it cannot be shared."
)

// FilterGrantableScopes returns the subset of requested scopes that may be
// granted to this user for this client.
//
// 1. Removes scopes not in clientAllowedScopes.
// 2. If "email" is requested and user.EmailVerified == false → removes "email".
// This is the fix: unverified email must not be implicitly granted.
//
// Use ExplainScopeExclusions when the user will see the outcome, so a dropped scope is
// visible rather than silently missing from the consent screen. Silently dropping
// "email" leaves the user believing the application received it.
func (m *Manager) FilterGrantableScopes(ctx context.Context, userID string, requestedScopes, clientAllowedScopes []string) ([]string, error) {
	grantable, _, err := m.explainScopeExclusions(ctx, userID, requestedScopes, clientAllowedScopes)
	return grantable, err
}

// ExplainScopeExclusions reports which requested scopes cannot be granted and why.
//
// Separated from FilterGrantableScopes so the filtering rule has exactly one
// implementation. Two copies of "email needs a verified address" would eventually
// disagree, and the disagreement would be a scope granted that should not have been.
func (m *Manager) ExplainScopeExclusions(ctx context.Context, userID string, requestedScopes, clientAllowedScopes []string) ([]string, []ScopeExclusion, error) {
	return m.explainScopeExclusions(ctx, userID, requestedScopes, clientAllowedScopes)
}

func (m *Manager) explainScopeExclusions(ctx context.Context, userID string, requestedScopes, clientAllowedScopes []string) ([]string, []ScopeExclusion, error) {
	if userID == "" {
		return nil, nil, fmt.Errorf("consent: FilterGrantableScopes: userID is empty")
	}

	// Get user to check email verification
	user, err := m.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("consent: FilterGrantableScopes: get user: %w", err)
	}

	// Build allowed set from client's allowed scopes
	allowed := make(map[string]struct{}, len(clientAllowedScopes))
	for _, s := range clientAllowedScopes {
		allowed[s] = struct{}{}
	}

	var grantable []string
	var excluded []ScopeExclusion
	for _, s := range requestedScopes {
		// Must be in client's allowed scopes
		if _, ok := allowed[s]; !ok {
			excluded = append(excluded, ScopeExclusion{Scope: s, Reason: ReasonNotRegistered})
			continue
		}
		// email requires verified email
		if s == "email" && !user.EmailVerified {
			excluded = append(excluded, ScopeExclusion{Scope: s, Reason: ReasonEmailUnverified})
			continue
		}
		grantable = append(grantable, s)
	}

	return grantable, excluded, nil
}

// HasFullConsent reports whether the user has an existing consent that covers
// all grantable scopes for this client.
//
// Returns true if a consent exists, is unexpired, and covers every scope in
// grantableScopes. Used by the authorize flow to auto-skip the consent screen.
func (m *Manager) HasFullConsent(ctx context.Context, userID, clientID string, grantableScopes []string) (bool, error) {
	if userID == "" || clientID == "" {
		return false, fmt.Errorf("consent: HasFullConsent: empty argument")
	}

	consent, err := m.consentRepo.Get(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("consent: HasFullConsent: %w", err)
	}
	if consent == nil {
		// The repo answers "not granted yet" with (nil, nil). First-time consent is
		// the common case on this path, so treating it as anything else panics on
		// exactly the flow that is supposed to work first.
		return false, nil
	}

	now := time.Now().UTC()
	return consent.IsActive(now, grantableScopes), nil
}

// GrantConsent records or updates the user's consent for this client.
//
// If a consent already exists, it is replaced (scopes widened/narrowed as
// requested). The grant is indefinite (ExpiresAt = nil) because explicit
// user consent should not silently expire.
func (m *Manager) GrantConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if userID == "" || clientID == "" {
		return fmt.Errorf("consent: GrantConsent: empty argument")
	}

	now := time.Now().UTC()
	consent := &domain.Consent{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: now,
		ExpiresAt: nil, // indefinite
	}

	if err := m.consentRepo.Upsert(ctx, consent); err != nil {
		return fmt.Errorf("consent: GrantConsent: %w", err)
	}
	return nil
}
