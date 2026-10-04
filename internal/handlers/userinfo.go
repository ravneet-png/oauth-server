package handlers

// GET and POST /userinfo — the OIDC userinfo endpoint.
//
// A machine endpoint authenticated by a bearer access token, not a cookie. The scopes
// carried by the token decide which claims are returned: a token granted only `openid`
// must not leak an email address because the resource happened to ask.

import (
	"net/http"
	"strings"

	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
	"oauth-server/internal/tokens"
)

// UserInfo handles userinfo requests.
func (d *Deps) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	if r.Method == http.MethodPost && !parseForm(r) {
		httpapi.OAuthError(w, oautherr.Newf("invalid_request", "malformed request body"))
		return
	}

	bearer, ok := bearerToken(r)
	if !ok {
		// RFC 6750 section 3: a request with no credentials gets 401 and a challenge
		// that tells the caller which scheme to use.
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "a bearer access token is required")
		return
	}

	tok, err := d.Verifier.Verify(r.Context(), bearer, tokens.TypeJWT)
	if err != nil {
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "the access token is not valid")
		return
	}

	// An ID token presented as an access token must not be accepted. Both are signed
	// with the same key and the verifier checks the type header, which does not
	// distinguish them; the audience does. Access tokens minted here carry the token
	// endpoint as `aud`, so that is the value this endpoint expects, with the issuer
	// accepted for tokens issued by an older builder that carried no audience.
	if !audienceContains(tok, d.Config.TokenEndpoint) && !audienceContains(tok, d.Config.Issuer) {
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "the access token was not issued for this endpoint")
		return
	}

	userID := tok.Subject()
	if userID == "" {
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "the access token has no subject")
		return
	}

	user, err := d.Users.GetByID(r.Context(), userID)
	if err != nil {
		// A token for a deleted user is no longer usable. Report it as an invalid
		// token rather than a server error: from the resource server's point of view
		// the credential is simply not good any more.
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "the access token is not valid")
		return
	}
	if user.DisabledAt != nil {
		unauthorizedBearer(w, domain.ErrCodeInvalidToken, "the access token is not valid")
		return
	}

	granted := scopeSetOf(tok)

	claims := map[string]any{"sub": user.UserID}
	if granted["profile"] {
		if user.Name != nil {
			claims["name"] = *user.Name
		}
	}
	if granted["email"] {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}

	httpapi.JSON(w, http.StatusOK, claims)
}

// bearerToken extracts a bearer token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// unauthorizedBearer writes a 401 with the RFC 6750 challenge.
func unauthorizedBearer(w http.ResponseWriter, code, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+description+`"`)
	httpapi.OAuthError(w, oautherr.Newf(code, "%s", description))
}

// audienceContains reports whether the token's audience includes want.
func audienceContains(tok interface {
	Audience() []string
}, want string) bool {
	for _, aud := range tok.Audience() {
		if aud == want {
			return true
		}
	}
	return false
}

// scopeSetOf returns the token's scope claim as a set.
func scopeSetOf(tok interface{ Get(string) (any, bool) }) map[string]bool {
	set := map[string]bool{}
	raw, ok := tok.Get("scope")
	if !ok {
		return set
	}
	s, ok := raw.(string)
	if !ok {
		return set
	}
	for _, scope := range strings.Fields(s) {
		set[scope] = true
	}
	return set
}
