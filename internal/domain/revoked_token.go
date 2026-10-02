// An entry in the revocation list. Postgres is the durable source; cache holds
// the same set for low-latency resource-server checks.

package domain

import "time"

// RevokedToken is one entry on the self-contained-token deny list, keyed by jti.
//
// The entry exists because an access token is a self-contained JWT: a resource
// server that validates it locally accepts it with no database round-trip, and
// therefore also accepts it after revocation until it expires. This table is the
// record that lets /introspect and any local validation cache answer "has this
// been revoked" correctly.
//
// It carries an ExpiresAt so the entry can be reaped the moment the token it
// denies could no longer be presented. Rows outliving their token are pure write
// amplification in the deny-list lookup.
type RevokedToken struct {
	JTI string

	// ExpiresAt is the expiry of the DENIED token, not of this row.
	ExpiresAt time.Time

	// Reason is populated only when known. Logout-driven revocations are not
	// interesting enough to enumerate in a hot-path table.
	Reason string

	RevokedAt time.Time
}

// IsStale reports whether the denied token has expired, meaning this entry no
// longer denies anything and can be deleted.
func (t *RevokedToken) IsStale(now time.Time) bool {
	return !t.ExpiresAt.After(now)
}

// StillDenied reports whether the token this entry refers to could still be
// presented, which is the condition for consulting it at all.
func (t *RevokedToken) StillDenied(now time.Time) bool {
	return t.ExpiresAt.After(now)
}
