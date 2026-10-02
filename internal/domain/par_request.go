package domain

// A pushed authorization request. Single use, enforced with a conditional
// UPDATE, and rejected on any second presentation.

import (
	"encoding/json"
	"time"
)

// PARRequest is a stored, pushed authorization request, addressed by an opaque
// request_uri.
//
// The request_uri is itself a bearer credential: anyone holding it can start the
// authorization. It is therefore random, single-use, and short-lived.
//
// Single use is the whole point of RFC 9126. A replayable request_uri would let
// an attacker who observes one redirect start an authorization with the victim's
// parameters, or replay it after the legitimate client has consumed it. The
// schema's par_requests_params_chk additionally refuses to store client
// credentials inside the payload, because the request_uri is handed to a browser
// and the row would otherwise hold a secret in a table the reaper only clears on
// expiry.
type PARRequest struct {
	// RequestURI is the urn:ietf:params:oauth:request_uri:... reference.
	RequestURI string
	ClientID   string

	// ParamsJSON holds the validated authorization request verbatim. Raw JSON
	// rather than a struct so that the exact set of parameters presented is
	// preserved: every parameter validated at /authorize and then dropped is a
	// bug waiting to happen, and prompt and max_age in particular must survive
	// to the login decision or prompt=none becomes impossible to honour.
	ParamsJSON json.RawMessage

	ExpiresAt time.Time

	// ConsumedAt is the single-use marker. NULL means unused.
	//
	// The schema column is present precisely so that consumption can be a
	// conditional UPDATE guarded on consumed_at IS NULL. Without it the
	// reference URI stays replayable for its whole lifetime.
	ConsumedAt *time.Time

	CreatedAt time.Time
}

// IsConsumed reports whether the single-use marker is set.
func (p *PARRequest) IsConsumed() bool {
	return p.ConsumedAt != nil
}

// IsExpired reports whether the request has outlived its TTL at time now.
func (p *PARRequest) IsExpired(now time.Time) bool {
	return !p.ExpiresAt.After(now)
}

// IsRedeemable reports whether the request is neither consumed nor expired.
func (p *PARRequest) IsRedeemable(now time.Time) bool {
	return p.ConsumedAt == nil && p.ExpiresAt.After(now)
}

// OwnedBy reports whether this request was pushed by clientID. Checked before
// consumption: a request_uri is only redeemable by the client that pushed it.
func (p *PARRequest) OwnedBy(clientID string) bool {
	return p.ClientID == clientID
}
