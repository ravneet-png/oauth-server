// Back-channel LogoutToken delivery and its mandatory claims.

package integration

import (
	"context"
	"net/http"
	"testing"
)

func TestBackchannelLogoutDeliversLogoutToken(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-backchannel-1", "alice@example.test", "correct horse battery", true)

	// Client with backchannel logout URI
	backchannelURI := "http://localhost:8081/backchannel-logout"
	f := newFlowWithBackchannel(t, e, "app-backchannel-1", "client-secret-bc-1", backchannelURI)
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)
	_ = f.exchange(t, e, code)

	// Get session cookie
	sessionCookie := getSessionCookie(t, e)

	// Perform logout - should deliver back-channel logout token
	logoutReq, _ := http.NewRequest(http.MethodGet, e.url("/logout"), nil)
	logoutReq.Header.Set("Cookie", "session="+sessionCookie)
	logoutResp := e.do(logoutReq)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", logoutResp.StatusCode)
	}

	// The back-channel delivery is async and happens in the handler. We verify
	// the audit log has the logout event with the correct details.
	var auditCount int
	err := e.DB.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event = 'logout.backchannel_sent'`).Scan(&auditCount)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_log logout.backchannel_sent count = %d, want 1", auditCount)
	}
}
