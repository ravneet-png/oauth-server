package tokens

// The JWKS endpoint payload.
//
// RFC 7517 says a JWK Set is an object with a "keys" member holding an array of
// JWKs. This file is the only place that shape is produced, so there is one answer
// to what the endpoint returns rather than one per handler that happens to serve
// it.

import (
	"context"
	"encoding/json"
	"fmt"

	"oauth-server/internal/keys"
)

// jwksDocument is the wire shape of a JWK Set.
//
// A named struct rather than a bare map, so the "keys" member is always present.
// A JWKS with no keys is `{"keys":[]}`, not `{}`: RFC 7517 requires the member, and
// a client that reads `keys` unconditionally gets undefined behaviour from `{}`.
type jwksDocument struct {
	Keys []json.RawMessage `json:"keys"`
}

// BuildJWKSResponse returns the JWK Set for the key manager, as JSON.
//
// Reads the stored public JWKs. No private half is decrypted on this path, so the
// endpoint costs one indexed query and no AES work, which matters because it is
// polled by every relying party on a cache miss and by every client that has just
// seen an unknown `kid`.
//
// A key that fails to parse is skipped rather than returned as an error. One
// corrupt row must not take the whole endpoint down: skipping it makes tokens signed
// by that key fail verification, which is loud and points at one key, whereas
// returning 500 makes every token unverifiable at once and hides the cause.
func BuildJWKSResponse(ctx context.Context, mgr *keys.Manager) ([]byte, error) {
	if mgr == nil {
		return nil, fmt.Errorf("tokens: BuildJWKSResponse: key manager is nil")
	}

	set, err := mgr.GetJWKS(ctx)
	if err != nil {
		return nil, err
	}

	doc := jwksDocument{Keys: make([]json.RawMessage, 0, set.Len())}
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			// Unreachable for a set built by GetJWKS, which appends and iterates
			// under the same lock. Skipped rather than panicked on so that a future
			// concurrent mutation degrades into a short JWKS instead of a crash in
			// the middle of serving a public endpoint.
			continue
		}
		raw, err := json.Marshal(k)
		if err != nil {
			continue
		}
		doc.Keys = append(doc.Keys, raw)
	}

	// Marshal rather than json.Marshal on a jwk.Set: the set's own encoding is
	// correct too, but it derives the member order and includes fields whose
	// presence we do not control. Marshalling a document we built makes the
	// response shape an explicit decision.
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("tokens: BuildJWKSResponse: marshal: %w", err)
	}
	return body, nil
}
