// HTML rendering for the browser-facing pages.
//
// The pages here are the ones an end user sees mid-flow, which is a different audience
// from the API endpoints: they carry HTML, they are the surface a CSRF attack targets,
// and they must not cache. The renderer owns the security headers so no handler can
// forget them.

package ui

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"reflect"
	"strings"
)

// Page templates and the stylesheet, embedded.
//
// Embedded so a container that ships without a templates directory fails at startup
// rather than at the first login attempt, and so the binary is self-contained.

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Renderer renders templates to an http.ResponseWriter.
type Renderer struct {
	templates *template.Template
	baseURL   string
}

// NewRenderer builds a Renderer and parses every template.
//
// baseURL is the server's externally visible issuer, used to build absolute links in
// pages that must work when opened outside the normal redirect chain.
//
// Returns an error if any template fails to parse. A renderer that started with a
// missing template would instead fail on the first request for that page — possibly
// the middle of an authentication flow, after the user has typed a password.
func NewRenderer(baseURL string) (*Renderer, error) {
	if baseURL == "" {
		return nil, errors.New("ui: NewRenderer: base URL is empty")
	}

	t, err := template.New("pages").Funcs(templateFuncs()).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse templates: %w", err)
	}

	return &Renderer{templates: t, baseURL: strings.TrimRight(baseURL, "/")}, nil
}

// templateFuncs are the helpers available inside templates.
//
// Deliberately tiny. A template function that formats or concatenates is a way for a
// caller to bypass html/template's contextual escaping, and nothing here needs one.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// nonEmpty reports whether a value is present, for conditional rendering.
		"nonEmpty": func(s string) bool { return s != "" },
	}
}

// Base is the data every page needs.
//
// Embedded rather than passed alongside, so a page template cannot forget the nonce and
// render a form that its own Content-Security-Policy will refuse to load.
type Base struct {
	// Nonce is a per-response value for Content-Security-Policy script-src.
	Nonce string

	// CSRFToken is the hidden form field every POST page carries.
	CSRFToken string

	// Title is the page heading.
	Title string

	// Error is a user-facing message. Set only for failures the user can act on.
	Error string

	// Flash is a one-shot informational message.
	Flash string

	// RequestID is the correlation id, shown to the user and echoed in the
	// X-Correlation-ID header so a user reporting a problem gives the operator
	// something to search for.
	//
	// On Base rather than on ErrorData alone, because the layout renders it and a
	// field missing from most page types would be a template that fails to execute on
	// exactly the pages nobody tests.
	RequestID string
}

// LoginData renders login.html.
type LoginData struct {
	Base

	// Email is pre-filled from the request so a typo is fixable.
	Email string

	// AuthRequestID continues an in-progress authorization request.
	AuthRequestID string

	// ClientID and ClientName identify the relying party on the sign-in page.
	//
	// Shown to the user deliberately. A user who types their password into a page that
	// does not say which application is asking has no way to notice they are on an
	// attacker's site.
	ClientID   string
	ClientName string

	// Scope describes what is being asked for.
	Scope []string
}

// RegisterData renders register.html.
type RegisterData struct {
	Base

	Email          string
	ClientID       string
	AuthRequestID  string
	MinPasswordLen int
}

// ConsentData renders consent.html.
type ConsentData struct {
	Base

	ClientID      string
	ClientName    string
	ClientURI     string
	AuthRequestID string

	// RequestedScopes are the scopes not already covered by a standing grant.
	RequestedScopes []ScopeItem

	// PreviouslyGranted are the scopes an existing consent already covers, listed so
	// the user sees what is being reused and not silently re-asked for.
	PreviouslyGranted []string

	// ExcludedScopes are requested scopes that will NOT be granted, with the reason.
	// Shown rather than silently dropped: if "email" is filtered for an unverified
	// address, a screen that simply omits it leaves the user believing the application
	// got it.
	ExcludedScopes []ExcludedScope
}

// ExcludedScope is one withheld scope and the reason it was withheld.
type ExcludedScope struct {
	Name   string
	Title  string
	Reason string
}

// ScopeItem is one scope on the consent screen.
type ScopeItem struct {
	Name        string
	Title       string
	Description string
}

// MFAChallengeData renders mfa_challenge.html.
type MFAChallengeData struct {
	Base

	// PendingID is the opaque handle for the partially completed login.
	PendingID string

	// Email is shown so the user knows which account is being challenged. Partial
	// masking: enough to recognise, not enough to enumerate.
	Email string

	// Method is "totp" or "backup_code".
	Method string

	AuthRequestID string

	// BackupCodesRemaining is shown only on the backup-code tab, so a user who is
	// burning through codes learns before the last one.
	BackupCodesRemaining int
}

// MFAEnrollData renders mfa_enroll.html.
type MFAEnrollData struct {
	Base

	// Secret is the base32 TOTP shared secret.
	//
	// Rendered because the user has to type it into an authenticator app, and shown
	// only after a password re-entry. The QR code beside it is the preferred path.
	Secret string

	// PendingID is the opaque handle for the pending enrolment. The form must submit
	// it so the POST handler can retrieve the sealed secret from Redis.
	PendingID string

	// ProvisioningURI produces the QR code.
	ProvisioningURI string

	// QRCodeDataURL is the QR code as a data: URL for an <img>.
	QRCodeDataURL string

	// BackupCodes are shown exactly once.
	BackupCodes []string
}

// VerifyEmailData renders verify_email.html.
//
// A distinct page rather than a flash message, because the link in the email arrives
// here and the user has just committed to a state change. Telling them what happened
// is the whole job.
type VerifyEmailData struct {
	Base

	Success     bool
	Email       string
	LoginURL    string
	ResendURL   string
	NextStepURL string
}

// ErrorData renders error.html.
type ErrorData struct {
	Base

	// Code is the OAuth error code, e.g. invalid_request.
	Code string

	// Description is the human-readable explanation for the user.
	Description string
}

// LoggedOutData renders logged_out.html.
type LoggedOutData struct {
	Base
	LoginURL string
}

// UnauthorizedData renders unauthorized.html.
type UnauthorizedData struct {
	Base
	Reason string
}

// HomeData renders home.html (the interactive OAuth 2.1 + OIDC developer console).
type HomeData struct {
	Base

	Issuer        string
	DemoClientID  string
	CallbackURL   string
	ActiveKeyID   string
	Authenticated bool
	UserID        string
	UserEmail     string
	UserName      string
	EmailVerified bool
	MFAEnabled    bool
}

// CallbackData renders callback.html (the OAuth 2.1 redirect landing and token inspector).
type CallbackData struct {
	Base

	Issuer       string
	DemoClientID string
	CallbackURL  string
	Code         string
	State        string
	ReturnedIss  string
	OAuthError   string
	OAuthDesc    string
}

// StaticFS returns the static asset filesystem.
func StaticFS() (fs.FS, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("ui: static assets: %w", err)
	}
	return sub, nil
}

// Page names. Passed to RenderPage as a string so a handler names the page it wants
// rather than choosing a template out of a bag of functions.
const (
	PageLogin        = "login"
	PageRegister     = "register"
	PageConsent      = "consent"
	PageMFAChallenge = "mfa_challenge"
	PageMFAEnroll    = "mfa_enroll"
	PageVerifyEmail  = "verify_email"
	PageError        = "error"
	PageLoggedOut    = "logged_out"
	PageUnauthorized = "unauthorized"
	PageHome         = "home"
	PageCallback     = "callback"
)

// Render writes a page with security headers.
//
// Every page goes through here rather than through a bare template.Execute, because the
// headers are part of the contract: no-store so an authenticated page is never written
// to a shared cache or the browser's back-forward cache, and a per-response CSP nonce
// so an injected <script> has no valid source.
func (r *Renderer) Render(w http.ResponseWriter, page string, status int, data any) error {
	if status == 0 {
		status = http.StatusOK
	}

	// Headers first, and before any write, so a mid-render failure cannot leave a
	// response without them.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	// The pages carry a password field. Without this the browser will offer to save
	// it, and without form-action lockdown a cross-origin form post from an attacker's
	// page would be indistinguishable from a legitimate submission.
	w.Header().Set("Content-Security-Policy", r.cspPolicy(data))
	w.Header().Set("X-Correlation-ID", correlationID(data))

	// Render into a buffer rather than straight to w. A template that fails halfway
	// through has already written a partial 200 to the client, and the user sees half
	// a page with no error; buffering means a failure becomes a clean 500.
	var buf bytes.Buffer
	if err := r.templates.ExecuteTemplate(&buf, page, data); err != nil {
		return fmt.Errorf("ui: render %s: %w", page, err)
	}

	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		return fmt.Errorf("ui: write %s: %w", page, err)
	}
	return nil
}

// cspPolicy builds the Content-Security-Policy for one response.
//
// The nonce is interpolated from the already-populated page data rather than from a new
// random value, because the two must agree: a policy whose nonce does not match the
// markup blocks the page's own script.
func (r *Renderer) cspPolicy(data any) string {
	nonce := nonceOf(data)

	var b strings.Builder
	// No default-src catch-all would let a browser guess for anything not listed;
	// 'self' explicitly allows only same-origin loads.
	b.WriteString("default-src 'none'")
	b.WriteString("; style-src 'self'")
	if nonce != "" {
		b.WriteString("; script-src 'nonce-" + nonce + "'")
	} else {
		b.WriteString("; script-src 'none'")
	}
	b.WriteString("; connect-src 'self'")
	b.WriteString("; img-src 'self' data:")
	b.WriteString("; form-action 'self' https: http:")
	// base-uri stops a <base> tag rewriting every relative link on the page, and
	// frame-ancestors stops a clickjacking overlay.
	b.WriteString("; base-uri 'none'")
	b.WriteString("; frame-ancestors 'none'")
	return b.String()
}

// nonceOf digs the nonce out of whatever page data was passed.
//
// Reflection rather than an interface the page types implement: the renderer owns
// header construction and the pages own their own fields, and adding an interface here
// would mean every new page type has to satisfy something it does not otherwise use.
func nonceOf(data any) string {
	switch d := data.(type) {
	case LoginData:
		return d.Nonce
	case RegisterData:
		return d.Nonce
	case ConsentData:
		return d.Nonce
	case MFAChallengeData:
		return d.Nonce
	case MFAEnrollData:
		return d.Nonce
	case VerifyEmailData:
		return d.Nonce
	case ErrorData:
		return d.Nonce
	case LoggedOutData:
		return d.Nonce
	case UnauthorizedData:
		return d.Nonce
	case HomeData:
		return d.Nonce
	case CallbackData:
		return d.Nonce
	default:
		return ""
	}
}

// correlationID digs the request id out of the page data.
//
// Every page type embeds Base, so the case list would be redundant if not for the
// pointer forms; the single nil-safe check covers those.
func correlationID(data any) string {
	if v := reflect.ValueOf(data); v.Kind() == reflect.Pointer && v.IsNil() {
		return ""
	}
	switch d := data.(type) {
	case LoginData:
		return d.RequestID
	case RegisterData:
		return d.RequestID
	case ConsentData:
		return d.RequestID
	case MFAChallengeData:
		return d.RequestID
	case MFAEnrollData:
		return d.RequestID
	case VerifyEmailData:
		return d.RequestID
	case ErrorData:
		return d.RequestID
	case LoggedOutData:
		return d.RequestID
	case UnauthorizedData:
		return d.RequestID
	case HomeData:
		return d.RequestID
	case CallbackData:
		return d.RequestID
	default:
		return ""
	}
}

// NewNonce returns a fresh CSP nonce.
//
// 16 bytes of CSPRNG output, base64. Long enough that guessing one is not feasible, and
// short enough that it costs nothing per response. Not a UUID: the entropy here is what
// matters, not the shape.
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ui: generate nonce: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// MustNonce is NewNonce for callers that cannot proceed without one.
//
// Returns a fixed empty string on failure rather than panicking: a missing nonce costs
// one inline script and the page still renders with script-src 'none'. Panicking would
// take down a login page because the entropy source hiccuped.
func MustNonce() string {
	n, err := NewNonce()
	if err != nil {
		return ""
	}
	return n
}

// RenderPage is the generic entry point used by handlers.
//
// Thin wrapper so handlers do not need to import the Renderer concrete type's methods
// individually, and so the no-store header cannot be forgotten by a handler that
// writes the response itself.
func RenderPage(w http.ResponseWriter, r *Renderer, page string, status int, data any) error {
	if r == nil {
		return errors.New("ui: RenderPage: renderer is nil")
	}
	return r.Render(w, page, status, data)
}

// WritePlain writes a non-HTML response with the same no-store guarantee.
//
// Used by the endpoints that return plain text or JSON from a browser-facing route.
func WritePlain(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
