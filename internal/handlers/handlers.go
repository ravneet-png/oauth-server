// Package handlers implements the HTTP surface: one file per endpoint.
//
// The division of responsibility is fixed and narrow. A handler does exactly four
// things: read and validate the request, call a flow function, format the result, and
// apply the response policy for its endpoint class. Business logic lives in
// internal/flows and persistence in internal/storage. A handler that contains a
// conditional on token state is a handler that cannot be tested without a database.
//
// The one judgement a handler does own is *where* an error may be delivered. That
// depends on whether redirect_uri has been validated, which only the handler knows, so
// the rule is a named type rather than a convention — see redirectPolicy in
// authorize.go, and httpapi.RedirectError for the rendering.
package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"oauth-server/internal/audit"
	"oauth-server/internal/authn"
	"oauth-server/internal/backchannel"
	"oauth-server/internal/cache"
	"oauth-server/internal/client_auth"
	"oauth-server/internal/consent"
	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/email"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/keys"
	"oauth-server/internal/middleware"
	"oauth-server/internal/sessions"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
	"oauth-server/internal/ui"
)

// Deps is every dependency a handler needs.
//
// One struct rather than a constructor per handler. Nineteen constructors with
// overlapping argument subsets are nineteen chances to forget one, and the failure is a
// nil dereference at request time rather than a compile error.
type Deps struct {
	Config *Config
	Logger *slog.Logger

	// Pool is the database connection pool. Held directly only so /health can probe
	// connectivity; every data access goes through a repository.
	Pool *storage.Pool

	// Repositories.
	Users       *storage.UserRepo
	Clients     *storage.ClientRepo
	Sessions    *storage.SessionRepo
	ClientSess  *storage.ClientSessionRepo
	Codes       *storage.AuthCodeRepo
	AuthReqs    *storage.AuthRequestRepo
	PARs        *storage.PARRepo
	AccessToks  *storage.AccessTokenRepo
	RefreshToks *storage.RefreshTokenRepo
	Revoked     *storage.RevokedTokenRepo
	Consent     *storage.ConsentRepo
	Families    *storage.TokenFamilyRepo
	MFA         *storage.MFARepo
	EmailVerif  *storage.EmailVerificationRepo
	Audit       *storage.AuditRepo
	SigningKeys *storage.SigningKeyRepo

	// Signing and token issuance.
	Keys       *keys.Manager
	KeyRotator *keys.Rotator
	Signer     *tokens.Signer
	Verifier   *tokens.Verifier
	AccessBldr *tokens.AccessTokenBuilder
	IDBldr     *tokens.IDTokenBuilder
	LogoutBldr *tokens.LogoutTokenBuilder

	// Request processing.
	ClientAuth  *client_auth.Dispatcher
	SessionMgr  *sessions.Manager
	MFAPending  *sessions.MFAPendingStore
	ConsentMgr  *consent.Manager
	Passwords   *authn.Authenticator
	MFAVerify   *authn.Verifier
	Backchannel *backchannel.Sender

	// ArgonParams are the parameters used to hash new passwords at registration and
	// reset. Held alongside the authenticator rather than inside it because the
	// authenticator only verifies; this is the one place the server derives a hash.
	ArgonParams crypto.Argon2Params

	// Infrastructure.
	Cache    *cache.Client
	Replay   *cache.ReplayCache
	Sender   *email.Sender
	Renderer *ui.Renderer
	AuditLog *audit.Logger

	// Cipher opens record-level secrets (the encrypted TOTP seed). Held here because
	// authn.Verifier deliberately takes a decrypted secret: the encryption key must not
	// enter a package that handles user-supplied codes.
	Cipher *crypto.AESCipher
}

// Config is the handler-facing slice of application configuration.
//
// A projection rather than *config.Config because handlers need time.Duration where the
// stored config has integer seconds. With the raw config that conversion is optional, so
// it gets made wrong: once, somewhere, a 900-second TTL becomes 900 nanoseconds and the
// symptom is tokens that expire before the client uses them. Here the conversion has
// already happened in one place and the field types make the mistake inexpressible.
type Config struct {
	Issuer string

	// Endpoint URLs, derived from the issuer during construction so that discovery and
	// the handlers cannot disagree about where /token lives.
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
	RevocationEndpoint    string
	IntrospectionEndpoint string
	PAREndpoint           string
	EndSessionEndpoint    string
	// RegistrationEndpoint is the dynamic client registration endpoint.
	RegistrationEndpoint string

	// MFAIssuer is the display name used in TOTP provisioning URIs.
	//
	// Separate from Issuer because a URL-shaped issuer (the normal OAuth issuer)
	// contains a colon, which the otpauth URI format uses as a separator and
	// cannot contain inside the issuer field.
	MFAIssuer string

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	// RefreshAbsoluteTTL is the hard ceiling on one grant's refresh lineage, as
	// opposed to RefreshTTL, which slides. A client that rotates forever still loses
	// the family at this point.
	RefreshAbsoluteTTL time.Duration

	IDTTL         time.Duration
	AuthCodeTTL   time.Duration
	PARTTL        time.Duration
	AuthReqTTL    time.Duration
	ClientCredTTL time.Duration

	MinPasswordLen int

	// ClientRegistrationEnabled gates POST /register.
	//
	// False produces 404 rather than 403: an endpoint that is administratively
	// disabled should not be discoverable by probing for it, and a 403 confirms it
	// exists.
	ClientRegistrationEnabled bool

	// InitialAccessToken is the bearer required by POST /register when enabled.
	InitialAccessToken string

	// BackchannelMaxAttempts bounds logout token delivery attempts per session.
	BackchannelMaxAttempts int

	// BackchannelTTL bounds how long a delivery is retried.
	BackchannelTTL time.Duration

	// SessionIdleTTL and SessionAbsoluteTTL bound a browser session's life.
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration

	// SessionCookieSecure sets the Secure attribute on the session cookie. False is
	// only correct for plain-http development; config validation enforces the pairing.
	SessionCookieSecure bool

	// EmailVerificationTTL is how long a signup token stays redeemable.
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration

	// HealthDependencies makes /health probe the database and Redis. A liveness probe
	// in a deployment that has no database (a test chain) wants false.
	HealthDependencies bool
}

// ErrNoSession reports that a request requiring a session had none.
var ErrNoSession = errors.New("handlers: no session in context")

// newOpaqueID returns a URL-safe random identifier for a short-lived pending state.
//
// Empty signals the RNG failed. Callers must treat that as fatal to the request: a
// predictable pending id is a session a stranger could complete.
func newOpaqueID() string {
	token, err := crypto.RandomToken()
	if err != nil {
		return ""
	}
	return token
}

// reqState is the per-request context assembled once and reused by every audit call.
type reqState struct {
	correlationID string
	clientIP      *netip.Addr
	userAgent     string
	sessionID     string
	userID        string
}

// state builds the request state from values middleware put in the context.
//
// Correlation id, client IP and user agent are assembled here rather than at each call
// site so that no audit event can be written without them. That is the difference
// between a log an operator can act on and one that names a timestamp.
func (d *Deps) state(r *http.Request) reqState {
	st := reqState{
		correlationID: middleware.GetCorrelationID(r.Context()),
		userAgent:     r.UserAgent(),
		userID:        middleware.GetUserID(r.Context()),
	}
	if s := middleware.GetSession(r.Context()); s != nil {
		st.sessionID = s.SessionID
	}
	// Resolved by the trusted-proxy middleware. Absent that middleware there is no
	// client IP to record: the raw peer address is a proxy's address, and recording it
	// as the client's would poison every rate-limit decision made from these rows.
	if addr := middleware.ClientAddrFromContext(r); addr != "" {
		if ip, err := netip.ParseAddr(addr); err == nil {
			st.clientIP = &ip
		}
	}
	return st
}

// auditRC converts the request state into an audit request context.
func (st reqState) auditRC() audit.RequestContext {
	return audit.RequestContext{
		CorrelationID: st.correlationID,
		IPAddress:     st.clientIP,
		UserAgent:     st.userAgent,
		SessionID:     st.sessionID,
	}
}

// hasSession reports whether a valid session was resolved.
func (st reqState) hasSession() bool { return st.sessionID != "" && st.userID != "" }

// session returns the resolved session, or nil.
func sessionOf(r *http.Request) *domain.Session {
	return middleware.GetSession(r.Context())
}

// base builds the fields every rendered page needs.
//
// Nonce and CSRF token are read from the request context, where the CSRF and security
// middlewares put them on safe requests. Reading them here rather than letting a handler
// generate its own means a page cannot be rendered without the nonce that makes its
// inline script executable under CSP, or without the token that makes its form
// submittable.
func (d *Deps) base(r *http.Request, title string) ui.Base {
	return ui.Base{
		Nonce:     ui.MustNonce(),
		CSRFToken: middleware.GetCSRFToken(r.Context()),
		Title:     title,
		RequestID: middleware.GetCorrelationID(r.Context()),
	}
}

// renderError renders the local error page.
//
// For errors that must not be redirected: an unvalidated redirect_uri, an unknown
// client, or a machine-endpoint failure that has no browser to send anywhere. The code
// shown is the OAuth code so a client developer recognises it, and no description is
// rendered — the description is for logs, and a page that echoes it is a page that
// reflects attacker-supplied text.
func (d *Deps) renderError(w http.ResponseWriter, r *http.Request, status int, code string) {
	if d.Renderer == nil {
		renderPlainError(w, status, code)
		return
	}
	data := ui.ErrorData{
		Base: d.base(r, "Error"),
		Code: code,
	}
	httpapi.RenderPage(w, d.Renderer, ui.PageError, status, data)
}

// renderPlainError renders an error page without the renderer.
//
// The fallback for the case where the template renderer itself is the problem, or when
// a handler runs before one is configured (a test, or a health check). A handler that
// needs a full page and cannot get one should still answer with something a person can
// read rather than a blank 500.
func renderPlainError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("error: " + code + "\n"))
}
