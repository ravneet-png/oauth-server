package flows

// Authorization endpoint business logic. Validates parameters, honours prompt and max_age, and creates the server-side authorization request. Performs no HTTP writing.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// Params holds the validated authorization request parameters.
type Params struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	State               *string
	Nonce               *string
	CodeChallenge       string
	CodeChallengeMethod string

	// Prompt is the space-delimited prompt parameter, split into values. The empty
	// slice and the absent parameter are the same thing here: OIDC defines no default
	// other than "no prompt requested".
	Prompt []string

	// MaxAge, when present, forces re-authentication if the session's auth_time is
	// older than this many seconds.
	MaxAge *int

	// LoginHint pre-fills the login form. It is never trusted as an identity: a hint
	// that named another user's address would otherwise let a client steer an
	// authentication at a victim's account.
	LoginHint string
}

// prompt values defined by OIDC Core section 3.1.2.1.
const (
	promptNone          = "none"
	promptLogin         = "login"
	promptConsent       = "consent"
	promptSelectAccount = "select_account"
)

// validatePrompt checks the prompt parameter against the OIDC-defined set.
//
// An unrecognised value is rejected rather than ignored. Ignoring it would answer a
// different request than the client made — for example, silently continuing with a live
// session when the client asked for `none`, which produces an authentication the client
// believed required no interaction. `none` combined with any other value is likewise an
// error: the combination is contradictory, and choosing one interpretation would make
// the response depend on parameter order.
func validatePrompt(values []string) error {
	if len(values) == 0 {
		return nil
	}
	sawNone := false
	for _, v := range values {
		switch v {
		case promptNone:
			sawNone = true
		case promptLogin, promptConsent, promptSelectAccount:
		default:
			return domain.NewInvalidRequest(fmt.Sprintf("prompt value %q is not supported", v))
		}
	}
	if sawNone && len(values) > 1 {
		return domain.NewInvalidRequest("prompt=none must not be combined with other values")
	}
	return nil
}

// hasPrompt reports whether the prompt set contains want.
func hasPrompt(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// HandleAuthorize processes an authorization request.
//
// If requestURI is provided, it consumes the PAR request atomically.
// Otherwise, params are parsed from query string.
// Returns the authRequestID and the next step ("login" or "consent").
//
// extraParams names the query parameters that arrived alongside request_uri, other
// than request_uri itself. It exists so the "must not carry other parameters" rule of
// RFC 9126 section 2.2 can be enforced against what the client actually sent.
//
// That check cannot live in this function's own params, because params is about to be
// overwritten by the stored copy — by the time this code could look at it, the evidence
// is gone. Handlers pass the names in and this validates them BEFORE GetAndDelete, so
// a malformed request cannot consume the request_uri it came with and leave a client
// holding a burned reference after a single typo.
func HandleAuthorize(ctx context.Context,
	authReqRepo *storage.AuthRequestRepo,
	parRepo *storage.PARRepo,
	clientRepo *storage.ClientRepo,
	sessionID *string,
	sessionUserID *string,
	sessionAuthTime *time.Time,
	requestURI string, // empty means query params
	extraParams []string, // query parameter names sent alongside request_uri
	params Params,
	ttl time.Duration,
) (authRequestID string, nextStep string, err error) {

	// 1. If request_uri, the stored parameters are authoritative and the query
	// string is not read at all.
	//
	// RFC 9126 section 2.2: a request carrying request_uri must not carry the
	// other authorization parameters, and the values in the stored request are the
	// ones that were validated at /par. So the stored copy REPLACES params rather
	// than being compared with it.
	if requestURI != "" {
		// client_id is the one parameter tolerated next to request_uri, because
		// clients that batch requests by client need to say whose they are asking
		// about. It is still checked against the stored value below. Everything else
		// is refused: honouring it would let a request_uri be paired with parameters
		// that were validated in a different request, and ignoring it silently would
		// answer a different question than the one the client asked.
		for _, name := range extraParams {
			if name != "client_id" {
				return "", "", domain.NewInvalidRequest("request_uri must not be combined with other authorization parameters")
			}
		}

		// A client_id that disagrees with the pushed request is rejected before the
		// consumption. Ignoring it lets an attacker who can append client_id=... to
		// another party's request_uri attribute the authorization to their own
		// client, and the check has to happen here rather than after GetAndDelete so
		// the victim's request_uri survives the rejection.
		if params.ClientID != "" {
			stored, lookupErr := parRepo.ClientIDFor(ctx, requestURI)
			if lookupErr != nil {
				return "", "", domain.NewInvalidRequest("request_uri is unknown, expired, or already used")
			}
			// An empty result means the request_uri is unknown, consumed or expired.
			// Reporting that as a client_id mismatch instead would tell a caller who
			// is guessing request_uris which of the two it hit, and a mismatching
			// client_id against a *live* request_uri is a different problem with a
			// different fix. Both stay invalid_request, but the descriptions have to
			// collapse to one answer or the pair becomes an existence oracle.
			if stored == "" || params.ClientID != stored {
				return "", "", domain.NewInvalidRequest("request_uri is unknown, expired, or already used")
			}
		}

		par, err := parRepo.GetAndDelete(ctx, requestURI)
		if err != nil {
			// Consumption already happened inside GetAndDelete, so a replayed or
			// expired request_uri arrives here and is indistinguishable from one
			// that never existed. Both are invalid_request.
			return "", "", domain.NewInvalidRequest("request_uri is unknown, expired, or already used")
		}

		if err := json.Unmarshal(par.ParamsJSON, &params); err != nil {
			return "", "", domain.Wrapf(err, "flows: unmarshal PAR params")
		}
	}

	// A missing response_type is a malformed request, not an unsupported one.
	// unsupported_response_type means the client asked for something the server
	// does not implement; it said nothing at all here.
	if params.ResponseType == "" {
		return "", "", domain.NewInvalidRequest("response_type is required")
	}
	if params.ResponseType != "code" {
		return "", "", domain.NewUnsupportedResponseType("only response_type=code is supported")
	}

	// prompt is validated before the client is looked up because an unknown prompt
	// value is a malformed request regardless of who is asking, and a client must not
	// learn whether it is registered from the difference between two errors.
	if err := validatePrompt(params.Prompt); err != nil {
		return "", "", err
	}

	if params.ClientID == "" {
		return "", "", domain.NewInvalidRequest("client_id is required")
	}
	if params.RedirectURI == "" {
		return "", "", domain.NewInvalidRequest("redirect_uri is required")
	}

	// Validate client
	client, err := clientRepo.GetByID(ctx, params.ClientID)
	if err != nil {
		// unknown_client is not an RFC 6749 code. The error is NOT redirected to
		// the client, because at this point the redirect target has not been
		// validated, and redirecting to an unvalidated URI with an error is the
		// open-redirect primitive. The handler renders this locally.
		return "", "", domain.NewInvalidClient("client is not registered")
	}
	if !client.IsEnabled() {
		return "", "", domain.NewInvalidClient("client is disabled")
	}

	// redirect_uri exact match
	if !client.RedirectURIAllowed(params.RedirectURI) {
		return "", "", domain.NewInvalidRequest("redirect_uri not registered for client")
	}
	if !client.SupportsGrant(domain.GrantAuthorizationCode) {
		return "", "", domain.NewUnauthorizedClient("client is not registered for authorization_code")
	}

	// code_challenge required, method must be S256
	if params.CodeChallenge == "" {
		return "", "", domain.NewInvalidRequest("code_challenge is required")
	}
	if params.CodeChallengeMethod != crypto.MethodS256 {
		return "", "", domain.NewInvalidRequest("code_challenge_method must be S256")
	}
	// Shape-checked here rather than only at /token: a malformed challenge cannot
	// match any verifier, so accepting it now only defers the rejection to a
	// point where the user has already authenticated.
	if !crypto.ValidCodeChallenge(params.CodeChallenge) {
		return "", "", domain.NewInvalidRequest("code_challenge is malformed")
	}

	// Scopes subset of client.Scopes
	if !domain.ScopeContainsAll(client.Scopes, params.Scope) {
		return "", "", domain.NewInvalidScope("requested scopes not permitted for client")
	}

	// If client.PARRequired && no request_uri
	if client.PARRequired && requestURI == "" {
		return "", "", domain.NewInvalidRequest("PAR required for this client")
	}

	if ttl <= 0 {
		return "", "", domain.NewServerError("auth request ttl is not configured")
	}

	now := time.Now().UTC()

	// Authentication decision.
	//
	// Four inputs, one outcome: whether this request can proceed without a login. The
	// session may exist, but prompt=login and max_age both mean "that session is not
	// good enough". select_account is treated as a forced re-authentication because
	// this server has exactly one account per session and cannot present a chooser;
	// answering it with the existing session would silently ignore the request.
	authenticated := sessionID != nil && *sessionID != ""
	if authenticated && hasPrompt(params.Prompt, promptLogin) {
		authenticated = false
	}
	if authenticated && hasPrompt(params.Prompt, promptSelectAccount) {
		authenticated = false
	}
	if authenticated && params.MaxAge != nil && sessionAuthTime != nil {
		maxAge := time.Duration(*params.MaxAge) * time.Second
		if now.Sub(*sessionAuthTime) > maxAge {
			authenticated = false
		}
	}

	// prompt=none is a promise to the client that no page will be rendered. If a
	// login would be required, the only correct response is login_required delivered
	// on the validated redirect_uri. The handler decides where that goes; here it is
	// enough to refuse to create an auth_request that would be shown to a user.
	if hasPrompt(params.Prompt, promptNone) && !authenticated {
		return "", "", domain.NewLoginRequired("prompt=none but no active session")
	}

	// Create auth_request.
	authReqID, err := crypto.RandomToken()
	if err != nil {
		return "", "", fmt.Errorf("flows: generate auth_request ID: %w", err)
	}

	authReq := &domain.AuthRequest{
		ID:                  authReqID,
		ClientID:            client.ClientID,
		RedirectURI:         params.RedirectURI,
		ResponseType:        params.ResponseType,
		Scope:               params.Scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           now.Add(ttl),
		CreatedAt:           now,
	}

	// An already-authenticated request is bound to the session that authenticated it,
	// here and now. Without this the request reaches /consent with a nil UserID and is
	// refused as "does not belong to this session", so every returning user - the only
	// user who has already consented - could never complete a second authorization.
	// login attaches the same two fields on the path that goes through /login.
	if authenticated && sessionUserID != nil {
		authReq.UserID = sessionUserID
		authReq.SessionID = sessionID
	}

	// ParamsJSON holds complete validated request
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return "", "", fmt.Errorf("flows: marshal params: %w", err)
	}
	authReq.ParamsJSON = paramsJSON

	if err := authReqRepo.Create(ctx, authReq); err != nil {
		return "", "", fmt.Errorf("flows: create auth_request: %w", err)
	}

	// Determine next step.
	//
	// A live session goes to consent and a missing one to login. Consent is checked
	// rather than skipped here: the consent flow's own scope evaluation decides
	// whether an existing grant auto-skips, and sending every authenticated request
	// to /consent would render a screen for a request the user already approved.
	//
	// Under prompt=none the consent handler is entered with the same instruction and
	// must not render: it either auto-approves or answers consent_required. That check
	// lives there because it needs the consent store, which this function does not.
	if authenticated {
		return authReq.ID, string(domain.NextStepConsent), nil
	}
	return authReq.ID, string(domain.NextStepLogin), nil
}
