package client_auth

// ssrf_test.go — Behaviour of the jwks_uri network policy.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// allowPrivate is used by tests that must fetch from httptest servers.
func allowPrivate() *http.Client {
	return allowPrivateNets()
}

func TestGuardedClientRejectsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := guardedClient(500 * time.Millisecond)
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("guardedClient allowed loopback fetch")
	}
}

func TestGuardedClientRejectsLinkLocalIPv4(t *testing.T) {
	// 169.254.169.254 is the AWS metadata service. If this ever connects, the policy
	// has failed.
	c := guardedClient(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guardedClient allowed link-local IPv4 fetch")
	}
}

func TestGuardedClientRejectsPrivateIPv4Literal(t *testing.T) {
	c := guardedClient(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://192.168.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guardedClient allowed private IPv4 fetch")
	}
}

func TestGuardedClientRejectsIPv6LoopbackLiteral(t *testing.T) {
	c := guardedClient(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://[::1]/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guardedClient allowed ::1 fetch")
	}
}

func TestGuardedClientRefusesRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		u := url.URL{Scheme: "http", Host: r.Host, Path: "/next"}
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Use the policy client. Even though httptest is loopback, the redirect-following
	// is what we want to assert. We cannot reach the loopback body without the redirect
	// following, so the error is either redirect refusal or blocked loopback. We check
	// for the redirect-specific refusal first: http.Client returns the last response +
	// error in some cases? Actually, with CheckRedirect returning ErrUseLastResponse,
	c := guardedClient(500 * time.Millisecond)
	cNoBlock := allowPrivate()
	cNoBlock.Timeout = 500 * time.Millisecond
	cNoBlock.CheckRedirect = c.CheckRedirect
	resp, err := cNoBlock.Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("wanted redirect response, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
