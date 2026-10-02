// Fires many concurrent consumers at one code and one refresh token, asserting that exactly one wins.

package integration

import (
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentCodeConsumption(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-concurrent-1", "alice@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-concurrent-1", "client-secret-for-concurrent-1")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var failureCount atomic.Int32

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := e.postFormBasic("/token", url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"code_verifier": {f.verifier},
				"redirect_uri":  {testRedirectURI},
			}, f.client.ClientID, f.secret)

			if resp.StatusCode == http.StatusOK {
				successCount.Add(1)
			} else {
				failureCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := successCount.Load(); got != 1 {
		t.Errorf("exactly 1 concurrent code exchange should succeed, got %d", got)
	}
	if got := failureCount.Load(); got != 9 {
		t.Errorf("exactly 9 concurrent code exchanges should fail, got %d", got)
	}
}

// TestConcurrentRefreshConsumption fires 10 concurrent requests with the same refresh token.
func TestConcurrentRefreshConsumption(t *testing.T) {
	e := newEnv(t)

	user := createUserWithPassword(t, e, "user-concurrent-2", "bob@example.test", "correct horse battery", true)

	f := newConfidentialFlow(t, e, "app-concurrent-2", "client-secret-for-concurrent-2")
	f.start(t, e)
	f.signIn(t, e, user.Email, "correct horse battery")
	code := f.allow(t, e)

	tokens := f.exchange(t, e, code)
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var failureCount atomic.Int32

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := e.postFormBasic("/token", url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {tokens.RefreshToken},
			}, f.client.ClientID, f.secret)

			if resp.StatusCode == http.StatusOK {
				successCount.Add(1)
			} else {
				failureCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if got := successCount.Load(); got != 1 {
		t.Errorf("exactly 1 concurrent refresh should succeed, got %d", got)
	}
	if got := failureCount.Load(); got != 9 {
		t.Errorf("exactly 9 concurrent refreshes should fail, got %d", got)
	}
}
