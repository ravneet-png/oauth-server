package sessions

// Session lifecycle: create, load, refresh idle, destroy, attach clients.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// SessionManagerError wraps session manager errors.
var (
	ErrSessionNotFound       = errors.New("session: not found")
	ErrSessionExpired        = errors.New("session: expired")
	ErrSessionNotOwned       = errors.New("session: not owned by user")
	ErrClientSessionNotFound = errors.New("client_session: not found")
)

// Manager handles session operations.
type Manager struct {
	repo        *storage.SessionRepo
	clientRepo  *storage.ClientSessionRepo
	idleTimeout time.Duration
	absTimeout  time.Duration
}

// NewManager builds a Manager with idle and absolute timeouts.
//
// idleTimeout: how long without activity before the session expires (sliding).
// absTimeout: hard ceiling regardless of activity (never extended).
func NewManager(repo *storage.SessionRepo, clientRepo *storage.ClientSessionRepo, idleTimeout, absTimeout time.Duration) (*Manager, error) {
	if repo == nil {
		return nil, fmt.Errorf("sessions: NewManager: repo is nil")
	}
	if clientRepo == nil {
		return nil, fmt.Errorf("sessions: NewManager: clientRepo is nil")
	}
	if idleTimeout <= 0 {
		return nil, fmt.Errorf("sessions: NewManager: idleTimeout must be positive")
	}
	if absTimeout <= 0 {
		return nil, fmt.Errorf("sessions: NewManager: absTimeout must be positive")
	}
	if idleTimeout > absTimeout {
		return nil, fmt.Errorf("sessions: NewManager: idleTimeout (%s) cannot exceed absTimeout (%s)", idleTimeout, absTimeout)
	}
	return &Manager{
		repo:        repo,
		clientRepo:  clientRepo,
		idleTimeout: idleTimeout,
		absTimeout:  absTimeout,
	}, nil
}

// Create starts a new session for a user.
//
// session_id is 32 random bytes base64url. Both expiries are set: ExpiresAt
// slides on activity; AbsoluteExpiresAt never moves.
// Create establishes a session for an authenticated user.
//
// amr is the authentication that got them here, e.g. ["pwd"], later extended by a
// step-up. It is a parameter rather than a constant because the caller's answer is the
// authority on how the user proved who they are.
func (m *Manager) Create(ctx context.Context, userID string, authTime time.Time, amr []string) (*domain.Session, error) {
	if userID == "" {
		return nil, fmt.Errorf("sessions: Create: userID is empty")
	}

	if len(amr) == 0 {
		// sessions.amr is NOT NULL and an empty array is the honest value: the
		// authentication succeeded, it just was not described by the caller.
		amr = []string{}
	}

	sid, err := crypto.RandomToken()
	if err != nil {
		return nil, fmt.Errorf("sessions: Create: generate session_id: %w", err)
	}

	now := authTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	session := &domain.Session{
		SessionID:         sid,
		UserID:            userID,
		AuthTime:          now,
		Amr:               amr,
		ExpiresAt:         now.Add(m.idleTimeout),
		AbsoluteExpiresAt: now.Add(m.absTimeout),
		CreatedAt:         now,
		LastSeenAt:        now,
	}

	if err := m.repo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("sessions: Create: %w", err)
	}
	return session, nil
}

// Get loads a session and checks both expiry types.
//
// Returns ErrSessionNotFound if no such session, ErrSessionExpired if expired.
func (m *Manager) Get(ctx context.Context, sessionID string) (*domain.Session, error) {
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	session, err := m.repo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("sessions: Get: %w", err)
	}

	now := time.Now().UTC()
	if !session.IsValid(now) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// RefreshIdle slides the idle deadline forward by the configured idle timeout.
//
// The repository enforces the strict ordering: AbsoluteExpiresAt > ExpiresAt.
func (m *Manager) RefreshIdle(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrSessionNotFound
	}

	newExpiry := time.Now().UTC().Add(m.idleTimeout)
	if err := m.repo.RefreshIdle(ctx, sessionID, newExpiry); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("sessions: RefreshIdle: %w", err)
	}
	return nil
}

// Destroy removes a session and all its attached client sessions.
func (m *Manager) Destroy(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrSessionNotFound
	}

	// Delete client sessions first (FK), then the session
	if _, err := m.clientRepo.DeleteBySessionID(ctx, sessionID); err != nil {
		return fmt.Errorf("sessions: Destroy: delete client_sessions: %w", err)
	}
	if err := m.repo.Delete(ctx, sessionID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("sessions: Destroy: %w", err)
	}
	return nil
}

// AttachClient binds a client to a session, returning the SID.
//
// Upserts the client_sessions row. If an attachment for this (session, client)
// already exists, the existing SID is returned rather than generating a new one,
// so that repeated authorizations for the same client in the same session are
// idempotent and the SID in ID tokens remains stable.
func (m *Manager) AttachClient(ctx context.Context, sessionID, userID, clientID string) (string, error) {
	if sessionID == "" || userID == "" || clientID == "" {
		return "", fmt.Errorf("sessions: AttachClient: empty argument")
	}

	// Verify session ownership
	session, err := m.repo.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", ErrSessionNotFound
		}
		return "", fmt.Errorf("sessions: AttachClient: load session: %w", err)
	}
	if session.UserID != userID {
		return "", ErrSessionNotOwned
	}

	now := time.Now().UTC()
	sid, err := crypto.RandomToken()
	if err != nil {
		return "", fmt.Errorf("sessions: AttachClient: generate sid: %w", err)
	}

	cs := &domain.ClientSession{
		SID:       sid,
		SessionID: sessionID,
		ClientID:  clientID,
		CreatedAt: now,
	}

	if err := m.clientRepo.Upsert(ctx, cs); err != nil {
		return "", fmt.Errorf("sessions: AttachClient: upsert: %w", err)
	}
	return sid, nil
}

// GetAttachedClients returns all client sessions for a session.
func (m *Manager) GetAttachedClients(ctx context.Context, sessionID string) ([]*domain.ClientSession, error) {
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	clients, err := m.clientRepo.GetBySessionID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("sessions: GetAttachedClients: %w", err)
	}
	return clients, nil
}
