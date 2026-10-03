// The single router constructor. Integration tests build the router through this function so that they exercise the real middleware chain rather than a test-only approximation.

package httpapi

// Routing and the composed middleware chain.
//
// One constructor, and it is the only way to get a handler in this process. That is what
// makes "what does a request to /token actually pass through" answerable by reading one
// file: if a test can construct its own chain, the chain it tests is not the chain that
// ships, and the difference is always exactly the part that was wrong.

import (
	"net/http"
	"time"

	"oauth-server/internal/ui"
)

// Handlers holds every route handler, grouped by the endpoint family it serves.
//
// A struct of values rather than a map, so adding a route is a compile error at the one
// place that must be updated rather than a silent 404 at runtime.
//
// One field per route, and a field handles every method that route accepts. The handlers
// themselves dispatch on the method, so the router does not need to know that /login is
// a GET page and a POST form: it registers the same value for both and lets the handler
// answer 405 for anything else. The alternative, a GET and a POST field per route, is
// two names for one endpoint and two chances to wire them to different code.
type Handlers struct {
	// Protocol endpoints. JSON in, JSON out, no browser session.
	Authorize      http.Handler
	PAR            http.Handler
	Token          http.Handler
	Introspect     http.Handler
	Revoke         http.Handler
	UserInfo       http.Handler
	JWKS           http.Handler
	Discovery      http.Handler
	ClientRegister http.Handler

	// Browser endpoints. Session cookie, CSRF token, HTML pages.
	Home           http.Handler
	Callback       http.Handler
	Signup         http.Handler
	VerifyEmailDev http.Handler
	Login          http.Handler
	Logout         http.Handler
	MFA            http.Handler
	MFAEnroll      http.Handler
	Consent        http.Handler

	// Account endpoints. Registration and reset are machine endpoints (JSON in and out);
	// verification is a browser navigation from an emailed link.
	UserRegister   http.Handler
	EmailVerify    http.Handler
	PasswordReset  http.Handler
	ForgotPassword http.Handler
	ResetPassword  http.Handler

	// Administrative endpoints. Guarded by middleware.RequireAdmin, which is not
	// optional and is applied in NewRouter rather than by the handler: a guard that
	// lives inside the handler is one `next.ServeHTTP` call away from being skipped,
	// and the endpoint it guards erases user data.
	EraseUser  http.Handler
	RotateKeys http.Handler

	NotFound http.Handler
	Health   http.Handler
}

// MiddlewareConfig describes the chain to build.
type MiddlewareConfig struct {
	// Global, applied to every route including health.
	//
	// All three have the middleware shape func(http.Handler) http.Handler, which is
	// why they are stored as functions rather than as built handlers: a handler built
	// before the route is known cannot be, since it would have nothing to delegate to.
	Recover func(http.Handler) http.Handler
	Headers func(http.Handler) http.Handler
	Access  func(http.Handler) http.Handler

	// CSRF applies to state-changing requests. PerRoute below decides where.
	CSRF func(http.Handler) http.Handler

	// Rate limits, keyed by the endpoint they protect. Optional entries are skipped,
	// which is how a test chain runs without Redis.
	RateLimit map[string]func(http.Handler) http.Handler

	// Session resolves the session cookie. Optional.
	Session func(http.Handler) http.Handler

	// Admin gates the administrative endpoints. Optional in the type because the
	// integration harness builds chains without a database, but NewRouter refuses to
	// register an admin route without it: see adminRequired below.
	Admin func(http.Handler) http.Handler
}

// adminRequired returns a gate that refuses everything.
//
// Used when no admin middleware was supplied while admin routes are registered. This
// fails closed and loudly rather than admitting the request: the alternative is
// mounting the erasure endpoint unprotected because a test harness forgot a field, and
// the failure would be invisible until someone's data was deleted.
func adminRequired() func(http.Handler) http.Handler {
	return func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			NoCacheHeaders(w)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"administrative access control is not configured"}`))
		})
	}
}

// withMiddleware applies a chain in the given order.
//
// Order matters and is the argument order, innermost last. This helper exists so a chain
// is one expression instead of six assignments where a later edit could reverse two.
func withMiddleware(h http.Handler, chain ...func(http.Handler) http.Handler) http.Handler {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i] != nil {
			h = chain[i](h)
		}
	}
	return h
}

// CSRFChain is the middleware that requires a CSRF token on a browser POST.
//
// It is not applied to /token, /revoke or /introspect. Those authenticate with a client
// secret and are not reachable by a browser in a way a CSRF token helps: a CSRF
// defence on a non-cookie-authenticated endpoint either does nothing or breaks the
// client. Applying it there is a common way to break server-to-server flows while
// believing it is safer.
func CSRFChain(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if mw == nil {
			return next
		}
		return mw(next)
	}
}

// GlobalChain returns the middleware applied to every route, outermost first.
//
// The order is deliberate and load-bearing:
//
//   - Recover is outermost. It is the only thing that can convert a panic into a 500,
//     and it can only do that if it is outside everything that can panic. Inside the
//     session lookup it would catch only panics from the handler, leaving the database
//     driver ones to kill the process.
//   - Headers is next, so a recovered panic still returns a response with the security
//     headers rather than a bare 500 that a browser might render as a foreign document.
//   - Session is last of the three. It is the most expensive and the only one that
//     touches Redis on a public endpoint, and nothing it does needs to happen before a
//     response header is decided.
func (c MiddlewareConfig) GlobalChain() []func(http.Handler) http.Handler {
	chain := make([]func(http.Handler) http.Handler, 0, 4)
	if c.Recover != nil {
		chain = append(chain, c.Recover)
	}
	if c.Headers != nil {
		chain = append(chain, c.Headers)
	}
	if c.Session != nil {
		chain = append(chain, c.Session)
	}
	if c.Access != nil {
		chain = append(chain, c.Access)
	}
	return chain
}

// Router dispatches by method and path.
type Router struct {
	// mux uses Go 1.22's method+pattern matching. Chosen over a hand-rolled map
	// because its precedence rules are defined, and the precedence bugs in
	// hand-rolled routers are always in the paths nobody tested.
	mux *http.ServeMux
}

// NewRouter builds the router with the full route table.
func NewRouter(h Handlers, mw MiddlewareConfig) *Router {
	global := mw.GlobalChain()

	r := &Router{mux: http.NewServeMux()}

	// resolve picks the handler for a field, falling back to a clear 404 so a missing
	// wiring shows up as an obvious message rather than a panic on the first request.
	resolve := func(name string, h http.Handler) http.Handler {
		if h != nil {
			return h
		}
		return notWired(name)
	}

	// browser registers a route whose handler accepts both GET and POST. CSRF is part
	// of the chain because the middleware is method-aware: on a safe method it issues a
	// token for the form, and only on an unsafe method does it require one. That is why
	// one registration covers a page and its submission without the router having to
	// know which is which.
	browser := func(pattern string, handler http.Handler, rateLimitKey string) {
		chain := append(append([]func(http.Handler) http.Handler{}, global...), CSRFChain(mw.CSRF))
		if rl, ok := mw.RateLimit[rateLimitKey]; ok && rl != nil {
			chain = append(chain, rl)
		}
		r.mux.Handle(http.MethodGet+" "+pattern, withMiddleware(resolve(pattern+" GET", handler), chain...))
		r.mux.Handle(http.MethodPost+" "+pattern, withMiddleware(resolve(pattern+" POST", handler), chain...))
	}

	// page registers a GET-only browser page. CSRF is in the chain because the
	// renderer needs a token to put in a form the page may contain.
	page := func(pattern string, handler http.Handler) {
		chain := append(append([]func(http.Handler) http.Handler{}, global...), CSRFChain(mw.CSRF))
		r.mux.Handle(http.MethodGet+" "+pattern, withMiddleware(resolve(pattern+" GET", handler), chain...))
	}

	// api registers a machine endpoint behind the global chain and, where configured,
	// its rate limit.
	api := func(pattern, method string, handler http.Handler, rateLimitKey string) {
		chain := global
		if rl, ok := mw.RateLimit[rateLimitKey]; ok && rl != nil {
			chain = append(chain, rl)
		}
		r.mux.Handle(method+" "+pattern, withMiddleware(resolve(pattern, handler), chain...))
	}

	// Protocol endpoints.
	api("/authorize", http.MethodGet, h.Authorize, "authorize")
	api("/par", http.MethodPost, h.PAR, "par")
	api("/token", http.MethodPost, h.Token, "token")
	api("/revoke", http.MethodPost, h.Revoke, "")
	api("/introspect", http.MethodPost, h.Introspect, "")
	api("/userinfo", http.MethodGet, h.UserInfo, "")
	api("/userinfo", http.MethodPost, h.UserInfo, "")
	api("/.well-known/openid-configuration", http.MethodGet, h.Discovery, "")
	api("/.well-known/jwks.json", http.MethodGet, h.JWKS, "")
	api("/register", http.MethodPost, h.ClientRegister, "register")

	// Account endpoints. Registration, reset request and reset completion are machine
	// endpoints: JSON in, JSON out, no cookie. They are rate limited by the same key as
	// dynamic registration because they are all unauthenticated write paths.
	api("/users/register", http.MethodPost, h.UserRegister, "register")
	api("/forgot-password", http.MethodPost, h.ForgotPassword, "register")
	api("/reset-password", http.MethodPost, h.ResetPassword, "register")

	// Browser endpoints.
	if h.Home != nil {
		page("/{$}", h.Home)
	}
	if h.Callback != nil {
		page("/callback", h.Callback)
	}
	if h.Signup != nil {
		browser("/signup", h.Signup, "register")
		page("/register", h.Signup)
	}
	if h.VerifyEmailDev != nil {
		browser("/signup/verify-dev", h.VerifyEmailDev, "")
	}
	browser("/login", h.Login, "login")
	browser("/logout", h.Logout, "")
	browser("/mfa", h.MFA, "mfa")
	browser("/mfa/enroll", h.MFAEnroll, "")
	browser("/consent", h.Consent, "")

	// Email verification is a top-level navigation from a mail client, so it is a GET.
	// The path the templates generate is /verify-email; /users/verify-email is the
	// documented alias, and both must work or a correct link 404s.
	browser("/verify-email", h.EmailVerify, "")
	browser("/users/verify-email", h.EmailVerify, "")

	// The reset link's landing page is a GET; the reset itself is the machine POST
	// registered above, so only the GET is registered here.
	page("/reset-password", h.PasswordReset)

	// Administrative endpoints. The admin gate goes on AFTER the session middleware,
	// because RequireAdmin reads the user id the session middleware put in context —
	// mounted outside it, every request would look unauthenticated. RequireSession is
	// expected to be part of mw.Admin's own construction.
	adminGate := mw.Admin
	if adminGate == nil {
		adminGate = adminRequired()
	}
	if h.EraseUser != nil || h.RotateKeys != nil {
		// CSRF applies. These endpoints mutate server state using the session cookie,
		// which is exactly what a CSRF token is for; a browser tricked into POSTing to
		// /keys/rotate would otherwise rotate the signing key on demand.
		r.mux.Handle("DELETE /users/{id}", withMiddleware(resolve("/users/{id}", h.EraseUser),
			append(append([]func(http.Handler) http.Handler{}, global...), adminGate, CSRFChain(mw.CSRF))...))
		r.mux.Handle("POST /keys/rotate", withMiddleware(resolve("/keys/rotate", h.RotateKeys),
			append(append([]func(http.Handler) http.Handler{}, global...), adminGate, CSRFChain(mw.CSRF))...))
	}

	// Operational endpoints stay on the global chain only. They are health checks
	// called by a load balancer over a network this server does not control, so they
	// must answer even when a session store or Redis is down.
	r.mux.Handle(http.MethodGet+" /health", withMiddleware(resolve("/health", h.Health), global...))

	// Static assets are served from the embedded FS with a long cache. Content-addressed
	// is not used here, so the ETag plus no-transform below is what stops a stale
	// stylesheet from outliving a deploy.
	r.mux.Handle("GET /assets/", resolve("/assets/", staticHandler()))

	// Everything unmatched. Registered without a method so it catches any verb.
	r.mux.Handle("/", resolve("/", h.NotFound))

	return r
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// notWired returns a handler that explains a missing wiring instead of panicking.
//
// A 500 with the route name is the single most useful thing to see when a handler was
// left out of the struct: a panic at the first request produces a stack trace pointing
// at the router, which tells you nothing about which of nineteen handlers is absent.
func notWired(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		NoCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error","error_description":"handler not wired: ` + name + `"}`))
	})
}

// staticHandler serves the embedded asset FS.
//
// Long max-age because assets are served under a versioned path, and no-transform so an
// intermediary does not re-compress into a variant the ETag no longer matches.
func staticHandler() http.Handler {
	assets, err := ui.StaticFS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "assets unavailable", http.StatusInternalServerError)
		})
	}

	fileServer := http.StripPrefix("/assets/", http.FileServer(http.FS(assets)))

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable, no-transform")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, req)
	})
}

// defaultTimeout is the per-request budget applied by the server, not the router.
//
// Named here because it documents the number rather than leaving a bare literal in
// main.go: a request that has not finished in this long is a request holding a database
// connection, and the pool is finite.
const defaultTimeout = 30 * time.Second

// DefaultTimeout returns the per-request budget.
func DefaultTimeout() time.Duration { return defaultTimeout }
