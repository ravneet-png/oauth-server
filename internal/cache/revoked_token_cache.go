package cache

// Low-latency view of the revocation list, keyed by jti with the same TTL as the token. Write-through from Postgres. Outage behaviour is explicit and fail-closed by default.

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RevokedTokenCache wraps a Redis client for revocation and jti replay checks.
type RevokedTokenCache struct {
	client *redis.Client
}

// NewRevokedTokenCache builds a RevokedTokenCache.
func NewRevokedTokenCache(client *redis.Client) *RevokedTokenCache {
	return &RevokedTokenCache{client: client}
}

// IsRevoked checks if a jti is in the revocation set.
func (c *RevokedTokenCache) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if c.client == nil {
		return false, nil
	}
	exists, err := c.client.Exists(ctx, "revoked:"+jti).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// AddRevoked adds a jti to the revocation set with TTL.
func (c *RevokedTokenCache) AddRevoked(ctx context.Context, jti string, ttl time.Duration) error {
	if c.client == nil {
		return nil
	}
	return c.client.Set(ctx, "revoked:"+jti, "1", ttl).Err()
}

// AddJTI adds a jti to the replay prevention set using SET NX.
//
// Returns (true, nil) if the jti was added (not seen before).
// Returns (false, nil) if the jti already existed (replay detected).
// Returns (false, error) on Redis error.
func (c *RevokedTokenCache) AddJTI(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if c.client == nil {
		return true, nil
	}
	key := "jti:" + jti
	added, err := c.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return added, nil
}
