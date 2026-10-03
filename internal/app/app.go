// Dependency graph. Owns construction and wiring of every repository, service, flow and handler, and the teardown order. Uses hand-rolled constructor injection: no DI framework, no reflection, fully greppable.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"oauth-server/internal/audit"
	"oauth-server/internal/authn"
	"oauth-server/internal/backchannel"
	"oauth-server/internal/cache"
	"oauth-server/internal/client_auth"
	"oauth-server/internal/config"
	"oauth-server/internal/consent"
	"oauth-server/internal/crypto"
	"oauth-server/internal/email"
	"oauth-server/internal/handlers"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/keys"
	"oauth-server/internal/middleware"
	"oauth-server/internal/sessions"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
	"oauth-server/internal/ui"
)

// Options is the input to New.
type Options struct {
	Config  *config.Config
	Secrets config.Secrets
	Logger  *slog.Logger
}

// App is a fully constructed server graph.
//
// It exposes the router and the background rotator rather than starting an
// http.Server itself: the process lifecycle, including signals and graceful shutdown,
// belongs to main, and a graph that also owns a listener cannot be built in a test.
type App struct {
	Config  *config.Config
	Secrets config.Secrets
	Log     *slog.Logger

	Deps   *handlers.Deps
	Router *httpapi.Router

	Pool    *storage.Pool
	Cache   *cache.Client
	Rotator *keys.Rotator
	Reaper  *Reaper
}

// New constructs the whole graph.
//
// Ordering is by dependency, not by file: repositories first, then the crypto and
// session primitives that read them, then the token services, then handlers. The first
// error is returned and nothing already built is left running, because every resource
// here is owned by the returned App or was never started.
//
// Both failing constructors and sql errors are wrapped with the step name. The panic
// alternative — a nil field discovered at request time — turns a boot misconfiguration
// into a 500 on one endpoint under traffic.
func New(ctx context.Context, opts Options) (*App, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	cfg := opts.Config

	// Database. The pool is handed to every repository, and to /health, which is why
	// the App keeps it rather than only the repos.
	pool, err := storage.NewPool(ctx, storage.Config{
		URL:              cfg.Database.URL,
		MaxConnections:   cfg.Database.MaxConnections,
		MinConnections:   cfg.Database.MinConnections,
		StatementTimeout: cfg.Database.StatementTimeout(),
		ConnectTimeout:   cfg.Database.ConnectTimeout(),
	})
	if err != nil {
		return nil, fmt.Errorf("app: database pool: %w", err)
	}

	raw := pool.GetPool()
	userRepo := storage.NewUserRepo(raw)
	clientRepo := storage.NewClientRepo(raw)
	sessionRepo := storage.NewSessionRepo(raw)
	clientSessionRepo := storage.NewClientSessionRepo(raw)
	authCodeRepo := storage.NewAuthCodeRepo(raw)
	authRequestRepo := storage.NewAuthRequestRepo(raw)
	parRepo := storage.NewPARRepo(raw)
	accessTokenRepo := storage.NewAccessTokenRepo(raw)
	refreshTokenRepo := storage.NewRefreshTokenRepo(raw)
	// The refresh lineage. Both issuance paths write families: consent creates one so
	// the authorization code's family_id foreign key resolves, and the code exchange
	// tops up a family for codes minted without one.
	tokenFamilyRepo := storage.NewTokenFamilyRepo(raw)
	revokedTokenRepo := storage.NewRevokedTokenRepo(raw)
	consentRepo := storage.NewConsentRepo(raw)
	mfaRepo := storage.NewMFARepo(raw)
	emailVerificationRepo := storage.NewEmailVerificationRepo(raw)
	auditRepo := storage.NewAuditRepo(raw)
	signingKeyRepo := storage.NewSigningKeyRepo(raw)

	if !cfg.Security.SessionCookieSecure {
		issuer := strings.TrimRight(cfg.Server.Issuer, "/")
		if err := clientRepo.EnsureDemoClient(
			ctx,
			[]string{issuer + "/callback"},
			[]string{issuer + "/"},
		); err != nil {
			log.Warn("app: ensure demo-client failed", "error", err)
		}
	}

	// Encryption at rest. One key opens both the signing keys and the TOTP seeds; a
	// second secret would double the rotation ceremony without separating anything,
	// since both are only as safe as the process memory that holds them.
	cipher, err := crypto.NewAESCipher(opts.Secrets.KeyEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("app: field cipher: %w", err)
	}

	// Signing keys. The active key is loaded, and the first one is generated when the
	// table is empty, so a fresh database boots without a manual provisioning step.
	keyManager, err := keys.NewManager(signingKeyRepo, opts.Secrets.KeyEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("app: keys.Manager: %w", err)
	}
	if _, err := keyManager.LoadActive(ctx); err != nil {
		if !errors.Is(err, keys.ErrNoActiveKey) {
			return nil, fmt.Errorf("app: load active signing key: %w", err)
		}
		log.Info("no active signing key, generating the first one")
		if _, err := keyManager.GenerateAndStore(ctx); err != nil {
			return nil, fmt.Errorf("app: generate first signing key: %w", err)
		}
		if _, err := keyManager.LoadActive(ctx); err != nil {
			return nil, fmt.Errorf("app: load first signing key: %w", err)
		}
	}

	rotator, err := keys.NewRotator(keyManager, keys.Config{
		RotationAfter: cfg.Keys.RotationAfter(),
		Retention:     cfg.Keys.Retention(),
		CheckInterval: 24 * time.Hour,
		Logger:        log,
	})
	if err != nil {
		return nil, fmt.Errorf("app: keys.Rotator: %w", err)
	}

	// Token issuance and verification.
	signer, err := tokens.NewSigner(keyManager)
	if err != nil {
		return nil, fmt.Errorf("app: tokens.NewSigner: %w", err)
	}
	accessBuilder, err := tokens.NewAccessTokenBuilder(signer, cfg.Server.Issuer)
	if err != nil {
		return nil, fmt.Errorf("app: tokens.NewAccessTokenBuilder: %w", err)
	}
	idBuilder, err := tokens.NewIDTokenBuilder(signer, cfg.Server.Issuer)
	if err != nil {
		return nil, fmt.Errorf("app: tokens.NewIDTokenBuilder: %w", err)
	}
	logoutBuilder, err := tokens.NewLogoutTokenBuilder(signer, cfg.Server.Issuer)
	if err != nil {
		return nil, fmt.Errorf("app: tokens.NewLogoutTokenBuilder: %w", err)
	}

	// Redis. One client is shared by the cache, the rate limiter, the CSRF store and the
	// replay cache; separate connections would multiply pool size without adding
	// isolation.
	cacheCfg := cache.DefaultConfig()
	cacheCfg.URL = cfg.Redis.URL
	cacheClient, err := cache.New(ctx, cacheCfg, log)
	if err != nil {
		return nil, fmt.Errorf("app: cache.New: %w", err)
	}
	revokedCache := cache.NewRevokedTokenCache(cacheClient.Raw())

	// The verifier consults the database deny list, not Redis.
	//
	// Revocation is written to revoked_tokens by the revoke and logout paths, so a
	// verifier pointed at a cache that nothing populates answers "not revoked" for
	// every token: revocation would return 200 and change nothing.
	verifier, err := tokens.NewVerifier(keyManager, revokedTokenRepo)
	if err != nil {
		return nil, fmt.Errorf("app: tokens.NewVerifier: %w", err)
	}

	// Client authentication. The dispatcher tries each method and the private_key_jwt
	// authenticator needs the revocation cache so a replayed client assertion is
	// rejected even after its short lifetime.
	clientAuth := client_auth.NewDispatcher(
		clientRepo,
		client_auth.NewSecretBasicAuthenticator(clientRepo),
		client_auth.NewSecretPostAuthenticator(clientRepo),
		client_auth.NewPrivateKeyJWTAuthenticator(clientRepo, revokedCache, cfg.Server.Issuer+"/token"),
		client_auth.NewNoneAuthenticator(clientRepo),
	)

	// Sessions and the MFA pending store.
	sessionMgr, err := sessions.NewManager(
		sessionRepo, clientSessionRepo,
		cfg.Security.SessionIdleTimeout(), cfg.Security.SessionAbsoluteTimeout(),
	)
	if err != nil {
		return nil, fmt.Errorf("app: sessions.NewManager: %w", err)
	}
	mfaPending := sessions.NewMFAPendingStore(cacheClient.Raw(), cfg.Tokens.MFAPendingTTL())

	// Authn, consent and the backchannel sender.
	argonParams := argonParams(cfg.Security.Argon2)
	passwords, err := authn.NewAuthenticator(userRepo, argonParams)
	if err != nil {
		return nil, fmt.Errorf("app: authn.NewAuthenticator: %w", err)
	}
	mfaVerifier, err := authn.NewVerifier(userRepo, mfaRepo)
	if err != nil {
		return nil, fmt.Errorf("app: authn.NewVerifier: %w", err)
	}
	consentMgr, err := consent.NewManager(consentRepo, userRepo)
	if err != nil {
		return nil, fmt.Errorf("app: consent.NewManager: %w", err)
	}
	backchannelSender := backchannel.NewSender(backchannel.WithMaxAttempts(cfg.Backchannel.MaxAttempts))

	// Audit. The sink is the repository, so an audit write is a database write and
	// cannot be lost by a crash between "log" and "commit".
	auditLog := audit.NewLogger(auditRepo, opts.Secrets.AuditPepper, log)

	// Email. The SMTP password is read here rather than from config because
	// config.Config is non-secret by design; a password field in the YAML would be a
	// password committed to git.
	emailSender, err := email.NewSender(email.Config{
		Host:         cfg.Email.SMTPHost,
		Port:         cfg.Email.SMTPPort,
		Username:     cfg.Email.SMTPUsername,
		Password:     os.Getenv("OAUTH_EMAIL_SMTP_PASSWORD"),
		FromAddress:  cfg.Email.FromAddress,
		FromName:     cfg.Email.FromName,
		Timeout:      10 * time.Second,
		StartTLSMode: email.TLSOpportunistic,
		MaxAttempts:  3,
	}, email.WithLogger(log))
	if err != nil {
		return nil, fmt.Errorf("app: email.NewSender: %w", err)
	}

	renderer, err := ui.NewRenderer(cfg.Server.Issuer)
	if err != nil {
		return nil, fmt.Errorf("app: ui.NewRenderer: %w", err)
	}

	// Handler config is a projection with endpoint URLs derived once from the issuer, so
	// discovery and the handlers cannot disagree about where an endpoint lives.
	issuer := cfg.Server.Issuer
	deps := &handlers.Deps{
		Config: &handlers.Config{
			Issuer:                    issuer,
			AuthorizationEndpoint:     issuer + "/authorize",
			TokenEndpoint:             issuer + "/token",
			UserInfoEndpoint:          issuer + "/userinfo",
			JWKSURI:                   issuer + "/.well-known/jwks.json",
			RevocationEndpoint:        issuer + "/revoke",
			IntrospectionEndpoint:     issuer + "/introspect",
			PAREndpoint:               issuer + "/par",
			EndSessionEndpoint:        issuer + "/logout",
			RegistrationEndpoint:      issuer + "/register",
			MFAIssuer:                 cfg.Security.MFAIssuer,
			AccessTTL:                 cfg.Tokens.AccessTTL(),
			RefreshTTL:                cfg.Tokens.RefreshIdleTTL(),
			RefreshAbsoluteTTL:        cfg.Tokens.RefreshAbsoluteTTL(),
			IDTTL:                     cfg.Tokens.IDTokenTTL(),
			AuthCodeTTL:               cfg.Tokens.AuthorizationCodeTTL(),
			PARTTL:                    cfg.Tokens.PARTTL(),
			AuthReqTTL:                cfg.Tokens.AuthRequestTTL(),
			ClientCredTTL:             cfg.Tokens.ClientCredentialsTTL(),
			MinPasswordLen:            cfg.Security.PasswordMinLength,
			ClientRegistrationEnabled: cfg.Registration.ClientRegistrationEnabled,
			InitialAccessToken:        opts.Secrets.ClientRegistrationInitialAccessToken,
			BackchannelMaxAttempts:    cfg.Backchannel.MaxAttempts,
			BackchannelTTL:            time.Duration(cfg.Backchannel.TimeoutSeconds) * time.Second,
			SessionIdleTTL:            cfg.Security.SessionIdleTimeout(),
			SessionAbsoluteTTL:        cfg.Security.SessionAbsoluteTimeout(),
			SessionCookieSecure:       cfg.Security.SessionCookieSecure,
			EmailVerificationTTL:      cfg.Tokens.EmailVerificationTTL(),
			PasswordResetTTL:          email.DefaultResetTTL,
			HealthDependencies:        true,
		},
		Logger:      log,
		Pool:        pool,
		Users:       userRepo,
		Clients:     clientRepo,
		Sessions:    sessionRepo,
		ClientSess:  clientSessionRepo,
		Codes:       authCodeRepo,
		AuthReqs:    authRequestRepo,
		PARs:        parRepo,
		AccessToks:  accessTokenRepo,
		RefreshToks: refreshTokenRepo,
		Revoked:     revokedTokenRepo,
		Consent:     consentRepo,
		Families:    tokenFamilyRepo,
		MFA:         mfaRepo,
		EmailVerif:  emailVerificationRepo,
		Audit:       auditRepo,
		SigningKeys: signingKeyRepo,

		Keys:       keyManager,
		KeyRotator: rotator,
		Signer:     signer,
		Verifier:   verifier,
		AccessBldr: accessBuilder,
		IDBldr:     idBuilder,
		LogoutBldr: logoutBuilder,

		ClientAuth:  clientAuth,
		SessionMgr:  sessionMgr,
		MFAPending:  mfaPending,
		ConsentMgr:  consentMgr,
		Passwords:   passwords,
		MFAVerify:   mfaVerifier,
		Backchannel: backchannelSender,

		ArgonParams: argonParams,

		Cache:    cacheClient,
		Replay:   cache.NewReplayCache(cacheClient),
		Sender:   emailSender,
		Renderer: renderer,
		AuditLog: auditLog,
		Cipher:   cipher,
	}

	router := httpapi.NewRouter(handlerTable(deps), middlewareConfig(cfg, deps, log))

	return &App{
		Config:  cfg,
		Secrets: opts.Secrets,
		Log:     log,
		Deps:    deps,
		Router:  router,
		Pool:    pool,
		Cache:   cacheClient,
		Rotator: rotator,
		Reaper:  NewReaper(deps, log),
	}, nil
}

// handlerTable binds every route field to a method on Deps.
//
// http.HandlerFunc is applied here rather than the methods returning http.Handler:
// a method value with the handler signature is assignable to http.HandlerFunc, and
// keeping the methods plain functions is what lets them be called directly in unit
// tests without a ResponseRecorder wrapper.
func handlerTable(d *handlers.Deps) httpapi.Handlers {
	return httpapi.Handlers{
		Authorize:  http.HandlerFunc(d.Authorize),
		PAR:        http.HandlerFunc(d.PAR),
		Token:      http.HandlerFunc(d.Token),
		Introspect: http.HandlerFunc(d.Introspect),
		Revoke:     http.HandlerFunc(d.Revoke),
		UserInfo:   http.HandlerFunc(d.UserInfo),
		JWKS:       http.HandlerFunc(d.JWKS),
		Discovery:  http.HandlerFunc(d.Discovery),

		ClientRegister: http.HandlerFunc(d.ClientRegister),

		Home:           http.HandlerFunc(d.Home),
		Callback:       http.HandlerFunc(d.Callback),
		Signup:         http.HandlerFunc(d.Signup),
		VerifyEmailDev: http.HandlerFunc(d.VerifyEmailDev),
		Login:          http.HandlerFunc(d.Login),
		Logout:    http.HandlerFunc(d.Logout),
		MFA:       http.HandlerFunc(d.MFAChallenge),
		MFAEnroll: http.HandlerFunc(d.MFAEnroll),
		Consent:   http.HandlerFunc(d.ConsentDecision),

		UserRegister:   http.HandlerFunc(d.UserRegister),
		EmailVerify:    http.HandlerFunc(d.EmailVerify),
		PasswordReset:  http.HandlerFunc(d.PasswordResetPage),
		ForgotPassword: http.HandlerFunc(d.ForgotPassword),
		ResetPassword:  http.HandlerFunc(d.ResetPassword),

		EraseUser:  http.HandlerFunc(d.EraseUser),
		RotateKeys: http.HandlerFunc(d.RotateKeys),

		NotFound: http.NotFoundHandler(),
		Health:   http.HandlerFunc(d.Health),
	}
}

// middlewareConfig assembles the middleware chain.
//
// The rate-limit map uses the keys the router looks up. Entries are omitted when rate
// limiting is disabled, and the router skips missing keys, so the same code path serves
// both a limited and an unlimited deployment.
func middlewareConfig(cfg *config.Config, d *handlers.Deps, log *slog.Logger) httpapi.MiddlewareConfig {
	mw := httpapi.MiddlewareConfig{
		Recover: middleware.RecoverMiddlewareWithLogger(log),
		Headers: headersMiddleware(cfg, log),
		Access:  middleware.AccessLogMiddleware(log),
		CSRF:    csrfMiddleware(cfg, d),
		Session: middleware.SessionMiddleware(d.Sessions),
		Admin:   middleware.RequireAdmin("/login", d.Users),
	}

	if cfg.RateLimit.Enabled {
		rl := middleware.NewRateLimiter(d.Cache.Raw())
		mw.RateLimit = map[string]func(http.Handler) http.Handler{
			"login":    middleware.LoginLimit(rl),
			"mfa":      middleware.MFALimit(rl),
			"par":      middleware.PARLimit(rl),
			"token":    middleware.TokenLimit(rl),
			"register": middleware.RegisterLimit(rl),
		}
	}

	return mw
}

// headersMiddleware applies the security headers, and the trusted-proxy resolver when
// one is configured. The resolver is skipped entirely when the trust list is empty,
// which is the normal case and also the safe one: an empty list means X-Forwarded-For is
// ignored, and installing a resolver with nothing to trust would be a no-op with a
// failure mode.
func headersMiddleware(cfg *config.Config, log *slog.Logger) func(http.Handler) http.Handler {
	headers := middleware.SecurityHeadersMiddleware
	if len(cfg.Server.TrustedProxies) == 0 {
		return headers
	}
	proxy, err := middleware.NewTrustedProxy(cfg.Server.TrustedProxies)
	if err != nil {
		log.Error("trusted proxy configuration rejected; X-Forwarded-For will be ignored", "error", err)
		return headers
	}
	return combineMiddleware(headers, proxy.Middleware)
}

// csrfMiddleware builds the CSRF protector over Redis so the token survives a restart
// and is shared by every process behind the load balancer.
func csrfMiddleware(cfg *config.Config, d *handlers.Deps) func(http.Handler) http.Handler {
	csrfCfg := middleware.CSRFConfig{
		CookieName:           "oauth_csrf",
		CookiePath:           "/",
		CookieMaxAge:         3600,
		CookieSecure:         cfg.Security.SessionCookieSecure,
		CookieSameSite:       http.SameSiteLaxMode,
		AllowedInternalPaths: cfg.Security.AllowedInternalPaths,
		TokenLength:          32,
	}
	return middleware.NewCSRFMiddleware(csrfCfg, middleware.NewRedisCSRFStore(d.Cache.Raw())).Protect
}

// combineMiddleware applies outer, then inner.
func combineMiddleware(outer, inner func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if outer == nil {
		return inner
	}
	if inner == nil {
		return outer
	}
	return func(next http.Handler) http.Handler {
		return outer(inner(next))
	}
}

// argonParams projects the config's Argon2 settings into the crypto type.
func argonParams(c config.Argon2Config) crypto.Argon2Params {
	return crypto.Argon2Params{
		Memory:      c.MemoryKiB,
		Iterations:  c.Iterations,
		Parallelism: c.Parallelism,
		SaltLength:  c.SaltLength,
		KeyLength:   c.KeyLength,
	}
}

// Close releases the long-lived resources in reverse construction order.
//
// The rotator is not stopped here because it is started by the caller that starts the
// server; stopping an unstarted rotator is harmless, but leaving the ordering to one
// place avoids a double Stop after the pool closes.
func (a *App) Close() {
	if a.Cache != nil {
		_ = a.Cache.Close()
	}
	if a.Pool != nil {
		a.Pool.Close()
	}
}
