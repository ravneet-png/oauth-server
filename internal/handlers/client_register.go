package handlers

// POST /register — RFC 7591 dynamic client registration.
//
// Disabled by default and, when enabled, gated by an initial access token. The endpoint
// is deliberately boring about failures: an operator probing it learns only that it is
// off (404) or that their bearer is wrong (401), never anything about existing clients.
//
// `implicit` and `password` are rejected outright. They are the two grants this server
// does not implement, and accepting a registration for them would let a client discover
// that only later, at the token endpoint, with a user in the middle of a flow.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oauth-server/internal/crypto"
	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
)

// clientRegistrationRequest is the accepted subset of RFC 7591 metadata.
type clientRegistrationRequest struct {
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	Scope                   string          `json:"scope"`
	JWKSURI                 string          `json:"jwks_uri"`
	JWKS                    json.RawMessage `json:"jwks"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI    string          `json:"backchannel_logout_uri"`
}

// ClientRegister handles dynamic client registration.
func (d *Deps) ClientRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	st := d.state(r)

	// Disabled registration answers 404, not 403: a 403 confirms the endpoint exists
	// and is worth probing further.
	if !d.Config.ClientRegistrationEnabled {
		httpapi.JSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}

	if !d.registrationAuthorised(r) {
		// Bearer failures are 401 with the same body whatever went wrong, including a
		// missing header, so the endpoint does not distinguish "no token" from "wrong
		// token" for a prober.
		httpapi.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	var req clientRegistrationRequest
	if err := decodeJSONBody(r, &req); err != nil {
		httpapi.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "body is not valid JSON"})
		return
	}

	client, secret, err := d.buildClientFromRegistration(req)
	if err != nil {
		httpapi.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}

	if err := d.Clients.Create(r.Context(), client); err != nil {
		d.Logger.Error("client_register: create", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditClientRegistered, domain.AuditOutcomeSuccess, nil), client.ClientID)

	resp := map[string]any{
		"client_id":                  client.ClientID,
		"client_id_issued_at":        client.ClientIDIssuedAt.Unix(),
		"client_secret_expires_at":   0,
		"client_name":                client.ClientName,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"scope":                      strings.Join(client.Scopes, " "),
		"post_logout_redirect_uris":  client.PostLogoutRedirectURIs,
	}
	if secret != "" {
		// Returned exactly once. There is no endpoint that can retrieve it again.
		resp["client_secret"] = secret
	}
	if client.JWKSURI != nil {
		resp["jwks_uri"] = *client.JWKSURI
	}
	if len(client.JWKSet) > 0 {
		resp["jwks"] = client.JWKSet
	}
	if client.BackchannelLogoutURI != nil {
		resp["backchannel_logout_uri"] = *client.BackchannelLogoutURI
	}

	httpapi.JSON(w, http.StatusCreated, resp)
}

// registrationAuthorised checks the initial access token.
func (d *Deps) registrationAuthorised(r *http.Request) bool {
	if d.Config.InitialAccessToken == "" {
		return false
	}
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimSpace(header[len(prefix):])
	// Constant-time comparison against the configured token via its digest.
	return secureEqual(d.Config.InitialAccessToken, provided)
}

// buildClientFromRegistration validates metadata and constructs the client.
//
// Validation is strict and up front. A client that is registered for a grant the server
// cannot perform, or with a redirect URI that cannot be safely used, is a future
// incident; refusing it here costs the developer one clear error message.
func (d *Deps) buildClientFromRegistration(req clientRegistrationRequest) (*domain.Client, string, error) {
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = domain.AuthMethodClientSecretBasic
	}
	switch authMethod {
	case domain.AuthMethodClientSecretBasic, domain.AuthMethodClientSecretPost, domain.AuthMethodPrivateKeyJWT, domain.AuthMethodNone:
	default:
		return nil, "", errInvalidMetadata("token_endpoint_auth_method is not supported")
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{domain.GrantAuthorizationCode}
	}
	for _, g := range grantTypes {
		switch g {
		case domain.GrantAuthorizationCode, domain.GrantRefreshToken, domain.GrantClientCredentials:
		case "implicit", "password":
			return nil, "", errInvalidMetadata("implicit and password grants are not supported")
		default:
			return nil, "", errInvalidMetadata("unknown grant_type")
		}
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, rt := range responseTypes {
		if rt != "code" {
			return nil, "", errInvalidMetadata("only response_type=code is supported")
		}
	}

	needsRedirect := false
	for _, g := range grantTypes {
		if g == domain.GrantAuthorizationCode {
			needsRedirect = true
		}
	}
	if needsRedirect && len(req.RedirectURIs) == 0 {
		return nil, "", errInvalidMetadata("redirect_uris is required for authorization_code")
	}
	for _, u := range req.RedirectURIs {
		if err := validRegistrationRedirectURI(u); err != nil {
			return nil, "", err
		}
	}
	for _, u := range req.PostLogoutRedirectURIs {
		if err := validRegistrationRedirectURI(u); err != nil {
			return nil, "", err
		}
	}

	if authMethod == domain.AuthMethodPrivateKeyJWT && req.JWKSURI == "" && len(req.JWKS) == 0 {
		return nil, "", errInvalidMetadata("private_key_jwt requires jwks or jwks_uri")
	}
	if req.JWKSURI != "" {
		parsed, err := url.Parse(req.JWKSURI)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, "", errInvalidMetadata("jwks_uri must be an absolute https URL")
		}
	}

	now := time.Now().UTC()
	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	postLogoutURIs := req.PostLogoutRedirectURIs
	if postLogoutURIs == nil {
		postLogoutURIs = []string{}
	}
	parsedScopes := strings.Fields(req.Scope)
	if parsedScopes == nil {
		parsedScopes = []string{}
	}
	client := &domain.Client{
		ClientID:                newOpaqueID(),
		ClientIDIssuedAt:        now,
		ClientName:              req.ClientName,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  parsedScopes,
		Contacts:                []string{},
		SubjectType:             "public",
		TokenEndpointAuthMethod: authMethod,
		TokenTTL:                d.Config.AccessTTL,
		RefreshIdleTTL:          d.Config.RefreshTTL,
		ClientCredentialsTTL:    d.Config.ClientCredTTL,
		PostLogoutRedirectURIs:  postLogoutURIs,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if client.ClientID == "" {
		return nil, "", errInvalidMetadata("could not allocate a client id")
	}
	if req.JWKSURI != "" {
		uri := req.JWKSURI
		client.JWKSURI = &uri
	}
	if len(req.JWKS) > 0 {
		client.JWKSet = req.JWKS
	}
	if req.BackchannelLogoutURI != "" {
		uri := req.BackchannelLogoutURI
		client.BackchannelLogoutURI = &uri
	}

	if authMethod == domain.AuthMethodNone {
		return client, "", nil
	}

	secret, err := crypto.RandomToken()
	if err != nil {
		return nil, "", errInvalidMetadata("could not allocate a client secret")
	}
	hash := crypto.SHA256Hex(secret)
	client.ClientSecretHash = &hash
	return client, secret, nil
}

// validRegistrationRedirectURI applies the RFC 7591 redirect_uri rules.
func validRegistrationRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errInvalidMetadata("redirect_uri must be an absolute URL")
	}
	// HTTPS only. A plaintext redirect leaks the authorization code on the network,
	// which defeats PKCE for exactly the attacker PKCE exists to stop.
	if u.Scheme != "https" {
		return errInvalidMetadata("redirect_uri must use https")
	}
	// A fragment or userinfo component makes the URI ambiguous about where the code
	// lands, and registered fragments have historically been an open-redirect vector.
	if u.Fragment != "" {
		return errInvalidMetadata("redirect_uri must not contain a fragment")
	}
	if u.User != nil {
		return errInvalidMetadata("redirect_uri must not contain userinfo")
	}
	return nil
}

// errInvalidMetadata is a local error type for registration validation.
type errInvalidMetadata string

func (e errInvalidMetadata) Error() string { return string(e) }
