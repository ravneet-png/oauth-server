package sessions

// MFA pending state: short-lived Redis store for the MFA step.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// MFA pending state errors.
var (
	ErrMFAInvalidPendingID = errors.New("mfa: invalid pending ID")
	ErrMFANotFound         = errors.New("mfa: not found")
)

// MFAPendingStore wraps a Redis client for MFA pending state.
type MFAPendingStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewMFAPendingStore builds an MFA pending store.
//
// ttl is how long a pending MFA state lives (default 5 min).
func NewMFAPendingStore(client *redis.Client, ttl time.Duration) *MFAPendingStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MFAPendingStore{client: client, ttl: ttl}
}

// Store saves a pending MFA state.
//
// pendingID is the opaque ID returned to the user. userID and authRequestID
// are what the next step needs to resume the authorization.
func (s *MFAPendingStore) Store(ctx context.Context, pendingID, userID, authRequestID string) error {
	if pendingID == "" || userID == "" {
		return fmt.Errorf("mfa: Store: empty argument")
	}

	key := fmt.Sprintf("mfa_pending:%s", pendingID)
	// authRequestID may be empty: an MFA challenge that is not part of an authorization
	// request (a bare sign-in) still needs the user to be held pending, and rejecting
	// that would make MFA impossible outside the authorization code flow. The empty
	// value round-trips as an empty second field.
	value := fmt.Sprintf("%s|%s", userID, authRequestID)

	if err := s.client.Set(ctx, key, value, s.ttl).Err(); err != nil {
		return fmt.Errorf("mfa: Store: %w", err)
	}
	return nil
}

// Get retrieves a pending MFA state.
func (s *MFAPendingStore) Get(ctx context.Context, pendingID string) (userID, authRequestID string, err error) {
	if pendingID == "" {
		return "", "", ErrMFAInvalidPendingID
	}

	key := fmt.Sprintf("mfa_pending:%s", pendingID)
	value, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", "", ErrMFANotFound
		}
		return "", "", fmt.Errorf("mfa: Get: %w", err)
	}

	// Parse "userID|authRequestID"
	for i := 0; i < len(value); i++ {
		if value[i] == '|' {
			return value[:i], value[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("mfa: Get: malformed value")
}

// Delete removes a pending MFA state.
func (s *MFAPendingStore) Delete(ctx context.Context, pendingID string) error {
	if pendingID == "" {
		return ErrMFAInvalidPendingID
	}

	key := fmt.Sprintf("mfa_pending:%s", pendingID)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("mfa: Delete: %w", err)
	}
	return nil
}
