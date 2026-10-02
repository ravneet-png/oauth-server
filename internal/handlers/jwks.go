package handlers

// GET /.well-known/jwks.json — the public signing key set.
//
// Public, cached aggressively. The document is served with a max-age rather than
// no-store precisely because resource servers are expected to cache it; the key rotation
// interval is chosen to exceed that cache lifetime, so a verifier never holds a set that
// predates a key it needs to trust.

import (
	"net/http"

	"oauth-server/internal/httpapi"
	"oauth-server/internal/tokens"
)

// JWKS handles the JSON Web Key Set document.
func (d *Deps) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}

	body, err := tokens.BuildJWKSResponse(r.Context(), d.Keys)
	if err != nil {
		httpapi.ServerError(w)
		return
	}

	// Set the cache headers *after* any helper that might set no-store, so this
	// response's caching policy is the one that wins. JWKS is the one endpoint where
	// no-store would be actively harmful: every verifier would refetch on every
	// request.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Del("Pragma")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
