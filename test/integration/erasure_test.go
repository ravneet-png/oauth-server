// Erasure removes access, preserves required records, and leaves no personal data anywhere in the database.

package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestGDPREraseUserRemovesAllData(t *testing.T) {
	e := newEnv(t)

	// Second client in a FRESH env to avoid session reuse.
	// newEnv truncates the DB, so the user must be created after it.
	e2 := newEnv(t)
	user := createUserWithPassword(t, e2, "user-erase-1", "alice@example.test", "correct horse battery", true)

	// Authenticate with multiple clients to create tokens, sessions, consents
	f1 := newConfidentialFlow(t, e, "app-erase-1", "client-secret-erase-1")
	f1.start(t, e)
	f1.signIn(t, e, user.Email, "correct horse battery")
	code1 := f1.allow(t, e)
	_ = f1.exchange(t, e, code1)
	f2 := newConfidentialFlow(t, e2, "app-erase-2", "client-secret-erase-2")
	f2.start(t, e2)
	f2.signIn(t, e2, user.Email, "correct horse battery")
	code2 := f2.allow(t, e2)
	_ = f2.exchange(t, e2, code2)

	// Get session cookie from first env
	_ = getSessionCookie(t, e)

	// Verify all data exists before erasure
	// 1. User exists
	var userCount int
	err := e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE user_id = $1`, user.UserID).Scan(&userCount)
	if err != nil {
		t.Fatalf("user query: %v", err)
	}
	if userCount != 1 {
		t.Errorf("user count before erasure = %d, want 1", userCount)
	}

	// 2. Sessions exist
	var sessionCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, user.UserID).Scan(&sessionCount)
	if err != nil {
		t.Fatalf("session query: %v", err)
	}
	if sessionCount < 1 {
		t.Errorf("session count before erasure = %d, want >= 1", sessionCount)
	}

	// 3. Token families exist
	var familyCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM token_families WHERE user_id = $1`, user.UserID).Scan(&familyCount)
	if err != nil {
		t.Fatalf("family query: %v", err)
	}
	if familyCount < 1 {
		t.Errorf("family count before erasure = %d, want >= 1", familyCount)
	}

	// 4. Refresh tokens exist
	var rtCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, user.UserID).Scan(&rtCount)
	if err != nil {
		t.Fatalf("refresh token query: %v", err)
	}
	if rtCount < 1 {
		t.Errorf("refresh token count before erasure = %d, want >= 1", rtCount)
	}

	// 5. Consents exist
	var consentCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM consents WHERE user_id = $1`, user.UserID).Scan(&consentCount)
	if err != nil {
		t.Fatalf("consent query: %v", err)
	}
	if consentCount < 1 {
		t.Errorf("consent count before erasure = %d, want >= 1", consentCount)
	}

	// 6. Access tokens exist (issued_access_tokens)
	var atCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM issued_access_tokens WHERE user_id = $1`, user.UserID).Scan(&atCount)
	if err != nil {
		t.Fatalf("access token query: %v", err)
	}
	if atCount < 1 {
		t.Errorf("access token count before erasure = %d, want >= 1", atCount)
	}

	// 7. Revoked tokens exist (join via issued_access_tokens for user_id)
	var revokedCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM revoked_tokens rt JOIN issued_access_tokens iat ON rt.jti = iat.jti WHERE iat.user_id = $1`, user.UserID).Scan(&revokedCount)
	if err != nil {
		t.Fatalf("revoked token query: %v", err)
	}

	// 8. Auth codes exist
	var codeCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM auth_codes WHERE user_id = $1`, user.UserID).Scan(&codeCount)
	if err != nil {
		t.Fatalf("auth code query: %v", err)
	}
	if codeCount < 1 {
		t.Errorf("auth code count before erasure = %d, want >= 1", codeCount)
	}

	// 9. Audit log has entries (audit_log has no user_id column; count all entries)
	var auditCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log`).Scan(&auditCount)
	if err != nil {
		t.Fatalf("audit log query: %v", err)
	}
	if auditCount < 1 {
		t.Errorf("audit log count before erasure = %d, want >= 1", auditCount)
	}

	// NOW: Perform erasure through the real administrative endpoint, so the test covers
	// the handler's own work — token revocation, session and client-session teardown,
	// audit pseudonymisation and back-channel delivery — rather than only the repository
	// delete it delegates to. A direct Users.Delete call would leave the handler
	// untested while still passing every assertion below.
	admin := createAdmin(t, e2, "admin-erase-1", "admin-erase@example.test", "correct horse battery")
	csrf := signInAdmin(t, e2, admin.Email, "correct horse battery")
	resp := e2.deleteWithCSRF("/users/"+url.PathEscape(user.UserID), csrf)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("erase user status = %d, want 204; body = %s", resp.StatusCode, body(t, resp))
	}

	// Verify ALL personal data is removed
	// User should be gone
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE user_id = $1`, user.UserID).Scan(&userCount)
	if err != nil {
		t.Fatalf("user query after erasure: %v", err)
	}
	if userCount != 0 {
		t.Errorf("user count after erasure = %d, want 0", userCount)
	}

	// Sessions should be cascade deleted
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, user.UserID).Scan(&sessionCount)
	if err != nil {
		t.Fatalf("session query after erasure: %v", err)
	}
	if sessionCount != 0 {
		t.Errorf("session count after erasure = %d, want 0", sessionCount)
	}

	// Token families cascade
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM token_families WHERE user_id = $1`, user.UserID).Scan(&familyCount)
	if err != nil {
		t.Fatalf("family query after erasure: %v", err)
	}
	if familyCount != 0 {
		t.Errorf("family count after erasure = %d, want 0", familyCount)
	}

	// Refresh tokens cascade
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, user.UserID).Scan(&rtCount)
	if err != nil {
		t.Fatalf("refresh token query after erasure: %v", err)
	}
	if rtCount != 0 {
		t.Errorf("refresh token count after erasure = %d, want 0", rtCount)
	}

	// Consents cascade
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM consents WHERE user_id = $1`, user.UserID).Scan(&consentCount)
	if err != nil {
		t.Fatalf("consent query after erasure: %v", err)
	}
	if consentCount != 0 {
		t.Errorf("consent count after erasure = %d, want 0", consentCount)
	}

	// Access tokens cascade
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM issued_access_tokens WHERE user_id = $1`, user.UserID).Scan(&atCount)
	if err != nil {
		t.Fatalf("access token query after erasure: %v", err)
	}
	if atCount != 0 {
		t.Errorf("access token count after erasure = %d, want 0", atCount)
	}

	// Auth codes cascade
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM auth_codes WHERE user_id = $1`, user.UserID).Scan(&codeCount)
	if err != nil {
		t.Fatalf("auth code query after erasure: %v", err)
	}
	if codeCount != 0 {
		t.Errorf("auth code count after erasure = %d, want 0", codeCount)
	}

	// MFA backup codes cascade
	var mfaCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM mfa_backup_codes WHERE user_id = $1`, user.UserID).Scan(&mfaCount)
	if err != nil {
		t.Fatalf("mfa backup codes query after erasure: %v", err)
	}
	if mfaCount != 0 {
		t.Errorf("mfa backup codes count after erasure = %d, want 0", mfaCount)
	}

	// Email verifications cascade
	var evCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM email_verifications WHERE user_id = $1`, user.UserID).Scan(&evCount)
	if err != nil {
		t.Fatalf("email verifications query after erasure: %v", err)
	}
	if evCount != 0 {
		t.Errorf("email verifications count after erasure = %d, want 0", evCount)
	}

	// PAR requests cascade (par_requests has no user_id column; count all)
	var parCount int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM par_requests`).Scan(&parCount)
	if err != nil {
		t.Fatalf("par requests query after erasure: %v", err)
	}
	if parCount != 0 {
		t.Errorf("par requests count after erasure = %d, want 0", parCount)
	}

	// Audit log: the trail survives for compliance, but the subject is no longer
	// referenced. The audit trail records the subject in more than one encoding, so the
	// test checks all of them are gone: the raw account id and email, and the HMAC
	// pseudonym of each, must not appear in the actor column, and the rows that were
	// redacted must have had their identifying columns cleared.
	var auditAfter int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log`).Scan(&auditAfter)
	if err != nil {
		t.Fatalf("audit log after erasure: %v", err)
	}
	if auditAfter == 0 {
		t.Error("audit log was emptied; the trail must survive erasure for compliance")
	}

	var redacted int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE actor = 'DELETED' AND session_id IS NULL AND ip_address IS NULL AND user_agent IS NULL`).Scan(&redacted)
	if err != nil {
		t.Fatalf("audit log redaction query: %v", err)
	}
	if redacted == 0 {
		t.Error("no audit entry was redacted to actor='DELETED' with its identifying columns cleared")
	}

	// The pseudonym is a join key: given the pepper and a candidate address it
	// re-identifies every row, so an actor that still carries it is not erased. The
	// erasure event itself names the subject in its target — the record that the erasure
	// happened — so it is the actor column this asserts on.
	pseudonymID := e2.App.Deps.AuditLog.Pseudonym(user.UserID)
	pseudonymEmail := e2.App.Deps.AuditLog.Pseudonym(user.Email)
	var lingeringPseudonym int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE actor = $1 OR actor = $2`, pseudonymID, pseudonymEmail).Scan(&lingeringPseudonym)
	if err != nil {
		t.Fatalf("audit log pseudonym query: %v", err)
	}
	if lingeringPseudonym != 0 {
		t.Errorf("audit log still attributes %d rows to the erased user's pseudonym", lingeringPseudonym)
	}

	// No raw identifier may survive in any column that can hold one.
	var rawPII int
	err = e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log
		  WHERE actor IN ($1, $2) OR target IN ($1, $2)
		     OR details::text ILIKE '%' || $1 || '%'
		     OR details::text ILIKE '%' || $2 || '%'`, user.UserID, user.Email).Scan(&rawPII)
	if err != nil {
		t.Fatalf("audit log PII query: %v", err)
	}
	if rawPII > 0 {
		t.Errorf("audit log still contains the erasure subject's raw identifiers after erasure")
	}
}
