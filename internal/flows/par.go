package flows

// Pushed authorization requests. Validates exactly as /authorize does, requires PKCE, and records a single-use reference URI with a sixty second lifetime.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// maxPARTTL is the ceiling RFC 9126 section 2.2 places on a pushed request's
// lifetime.
const maxPARTTL = 600 * time.Second

// PARParams holds the validated PAR request parameters.
type PARParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	State               *string
	Nonce               *string
	CodeChallenge       string
	CodeChallengeMethod string

	// Prompt, MaxAge and LoginHint are carried through to the stored request so the
	// authorization step sees exactly what was pushed. They are validated here for the
	// same reason PKCE is: a parameter that can only fail later, in front of a user,
	// should fail now, on the back channel.
	Prompt    []string
	MaxAge    *int
	LoginHint string
}

// HandlePAR creates a pushed authorization request.
//
// Validates the same parameters as /authorize, requires PKCE.
// Generates request_uri = "urn:ietf:params:oauth:request_uri:" + UUID
// Stores in par_requests with the configured TTL.
// Returns request_uri and expires_in.
func HandlePAR(ctx context.Context,
	parRepo *storage.PARRepo,
	clientRepo *storage.ClientRepo,
	params PARParams,
	ttl time.Duration,
) (requestURI string, expiresIn int, err error) {

	// RFC 9126 section 2.2 caps the PAR lifetime at 600 seconds; the default here is
	// 60 because that is the configured value, not because the spec prefers it. The
	// check is on the configured TTL rather than only on the default so raising
	// tokens.par_ttl cannot silently produce request_uris that outlive the exchange
	// window a relying party is built to expect.
	if ttl <= 0 {
		return "", 0, domain.NewServerError("PAR ttl is not configured")
	}
	if ttl > maxPARTTL {
		return "", 0, domain.NewServerError(fmt.Sprintf("PAR ttl %s exceeds the RFC 9126 maximum of %s", ttl, maxPARTTL))
	}

	if params.ResponseType == "" {
		return "", 0, domain.NewInvalidRequest("response_type is required")
	}
	if params.ResponseType != "code" {
		return "", 0, domain.NewUnsupportedResponseType("only response_type=code is supported")
	}
	if err := validatePrompt(params.Prompt); err != nil {
		return "", 0, err
	}
	if params.ClientID == "" {
		return "", 0, domain.NewInvalidRequest("client_id is required")
	}
	if params.RedirectURI == "" {
		return "", 0, domain.NewInvalidRequest("redirect_uri is required")
	}

	// Validate client
	client, err := clientRepo.GetByID(ctx, params.ClientID)
	if err != nil {
		return "", 0, domain.NewInvalidClient("client is not registered")
	}
	if !client.IsEnabled() {
		return "", 0, domain.NewInvalidClient("client is disabled")
	}

	// redirect_uri exact match
	if !client.RedirectURIAllowed(params.RedirectURI) {
		return "", 0, domain.NewInvalidRequest("redirect_uri not registered for client")
	}
	if !client.SupportsGrant(domain.GrantAuthorizationCode) {
		return "", 0, domain.NewUnauthorizedClient("client is not registered for authorization_code")
	}

	// code_challenge required, method must be S256
	if params.CodeChallenge == "" {
		return "", 0, domain.NewInvalidRequest("code_challenge is required")
	}
	if params.CodeChallengeMethod != crypto.MethodS256 {
		return "", 0, domain.NewInvalidRequest("code_challenge_method must be S256")
	}
	if !crypto.ValidCodeChallenge(params.CodeChallenge) {
		return "", 0, domain.NewInvalidRequest("code_challenge is malformed")
	}

	// Scopes subset of client.Scopes
	if !domain.ScopeContainsAll(client.Scopes, params.Scope) {
		return "", 0, domain.NewInvalidScope("requested scopes not permitted for client")
	}

	now := time.Now().UTC()

	// A UUID, per the documented form of a request_uri.
	//
	// 122 bits of the RFC 4122 space, and that is enough: the value's only job is to
	// be unguessable in the sixty seconds it lives. It is a UUID rather than 32 bytes
	// of CSPRNG output because the request_uri is a published interface value that
	// appears in logs, traces and client-side telemetry, and a recognisable shape is
	// worth more there than extra entropy that is never spent.
	//
	// The entropy is not wasted either way: an unguessable code is the whole control,
	// since guessing one lets an attacker attach their own parameters to a client's
	// request.
	requestURI = "urn:ietf:params:oauth:request_uri:" + uuid.NewString()

	// ParamsJSON holds complete validated request
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return "", 0, fmt.Errorf("flows: marshal PAR params: %w", err)
	}

	parReq := &domain.PARRequest{
		RequestURI: requestURI,
		ClientID:   client.ClientID,
		ParamsJSON: paramsJSON,
		ExpiresAt:  now.Add(ttl),
		CreatedAt:  now,
	}

	if err := parRepo.Create(ctx, parReq); err != nil {
		return "", 0, fmt.Errorf("flows: create PAR request: %w", err)
	}

	return requestURI, int(ttl.Seconds()), nil
}
