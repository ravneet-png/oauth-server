// Refresh token rotation chain and cross-client isolation.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
)

func TestRefreshTokenRotationChain(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-rot-1", "alice-rot@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-rot-1", "client-secret-for-rot-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens1 := f.exchange(t, e, code)
	if tokens1.RefreshToken == "" {
		t.Fatal("initial refresh token missing")
	}

	tokens2 := f.refresh(t, e, tokens1.RefreshToken)
	if tokens2.RefreshToken == "" || tokens2.RefreshToken == tokens1.RefreshToken {
		t.Fatalf("second refresh token = %q, want distinct non-empty token", tokens2.RefreshToken)
	}

	tokens3 := f.refresh(t, e, tokens2.RefreshToken)
	if tokens3.RefreshToken == "" || tokens3.RefreshToken == tokens2.RefreshToken {
		t.Fatalf("third refresh token = %q, want distinct non-empty token", tokens3.RefreshToken)
	}

	// Verify predecessor linkage in PostgreSQL.
	r1, err := e.App.Deps.RefreshToks.GetByHash(context.Background(), crypto.SHA256Hex(tokens1.RefreshToken))
	if err != nil {
		t.Fatalf("get R1: %v", err)
	}
	if r1.RevocationReason == nil || *r1.RevocationReason != domain.RevocationReasonRotated {
		t.Errorf("R1 revocation_reason = %v, want %q", r1.RevocationReason, domain.RevocationReasonRotated)
	}
	wantR2Hash := crypto.SHA256Hex(tokens2.RefreshToken)
	if r1.ReplacedByHash == nil || *r1.ReplacedByHash != wantR2Hash {
		t.Errorf("R1 replaced_by_hash = %v, want %q", r1.ReplacedByHash, wantR2Hash)
	}
}

func TestRefreshTokenWrongClientDoesNotRevokeOwnerToken(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-rot-2", "bob-rot@example.test", "correct horse battery", true)

	owner := newConfidentialFlow(t, e, "app-rot-owner", "owner-secret-rot-2")
	stranger := newConfidentialFlow(t, e, "app-rot-stranger", "stranger-secret-rot-2")

	owner.start(t, e)
	owner.signIn(t, e, user.Email, "correct horse battery")
	code := owner.allow(t, e)
	tokens1 := owner.exchange(t, e, code)

	// Stranger attempts to refresh using owner's refresh token.
	probe := e.postFormBasic("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens1.RefreshToken},
	}, stranger.client.ClientID, stranger.secret)
	if probe.StatusCode != http.StatusBadRequest {
		t.Fatalf("stranger refresh status = %d, want 400; body = %s", probe.StatusCode, body(t, probe))
	}

	// Owner's refresh token must remain unrevoked and usable.
	tokens2 := owner.refresh(t, e, tokens1.RefreshToken)
	if tokens2.AccessToken == "" || tokens2.RefreshToken == "" {
		t.Fatal("owner refresh failed after wrong-client probe")
	}
}
