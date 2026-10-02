package client_auth

// private_key_jwt.go — Private key JWT client authentication.
//
// Client sends client_assertion_type and client_assertion in the form body.
// The assertion is a JWT signed with the client's private key.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"oauth-server/internal/cache"
	"oauth-server/internal/domain"
	"oauth-server/internal/storage"
)

// ErrReplayDetected means the client_assertion jti was already used.
var ErrReplayDetected = errors.New("client assertion replay detected")

// jwksFetchLimit bounds a jwks_uri response.
//
// A client's published key set is small. A limit this far above it is not a
// convenience allowance, it is the ceiling on how much an endpoint this server was told
// to trust can make it allocate per token request.
const jwksFetchLimit = 64 << 10

// jwksFetchTimeout bounds one jwks_uri fetch.
const jwksFetchTimeout = 5 * time.Second

// PrivateKeyJWTAuthenticator authenticates clients using signed JWT assertions.
type PrivateKeyJWTAuthenticator struct {
	repo     *storage.ClientRepo
	revCache *cache.RevokedTokenCache // reused for jti replay cache
	tokenURL string                   // expected aud

	// httpClient fetches jwks_uri. Injected so a test can serve a key set from an
	// httptest server and so the transport policy lives in one place. The default
	// carries the SSRF network policy from ssrf.go.
	httpClient *http.Client

	// jwksCache holds fetched key sets so a jwks_uri is not re-fetched per token
	// request, and fetches groups concurrent misses onto one outbound request.
	jwksCache  *jwksCache
	fetchGroup *jwksFetchGroup
}

// WithHTTPClient replaces the client used to fetch jwks_uri and returns the
// authenticator for chaining.
//
// Replacing it also drops any cached key set: the new client may be pointed at a
// different transport, and serving a previously fetched key set over it would not be
// the fetch the caller asked for.
func (a *PrivateKeyJWTAuthenticator) WithHTTPClient(c *http.Client) *PrivateKeyJWTAuthenticator {
	a.httpClient = c
	if a.jwksCache != nil {
		// The cache is keyed per client, not per transport, so it cannot survive a
		// transport swap without the risk of replaying a key set through a policy the
		// caller did not intend.
		a.jwksCache = newJWKSCache(a.jwksCache.ttl)
	}
	return a
}

// WithJWKSCacheTTL overrides the key-set cache lifetime and returns the authenticator
// for chaining. A zero or negative TTL disables caching, leaving every verification to
// fetch, which is the correct behaviour if a deployment cannot tolerate a stale key set.
func (a *PrivateKeyJWTAuthenticator) WithJWKSCacheTTL(ttl time.Duration) *PrivateKeyJWTAuthenticator {
	if a.jwksCache != nil {
		a.jwksCache.ttl = ttl
	}
	return a
}

// NewPrivateKeyJWTAuthenticator builds a PrivateKeyJWTAuthenticator.
//
// tokenURL is the server's token endpoint URL (the expected aud claim).
// revCache is used for jti replay prevention (SET NX with TTL).
func NewPrivateKeyJWTAuthenticator(repo *storage.ClientRepo, revCache *cache.RevokedTokenCache, tokenURL string) *PrivateKeyJWTAuthenticator {
	return &PrivateKeyJWTAuthenticator{
		repo:       repo,
		revCache:   revCache,
		tokenURL:   tokenURL,
		httpClient: guardedClient(jwksFetchTimeout),
		jwksCache:  newJWKSCache(jwksCacheTTL),
		fetchGroup: newJWKSFetchGroup(),
	}
}

// Authenticate parses client_assertion from the form, verifies the JWT claims
// and signature, and checks jti replay.
func (a *PrivateKeyJWTAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*domain.Client, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("%w: method must be POST", ErrInvalidClient)
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: parse form: %w", ErrInvalidClient, err)
	}

	assertionType := r.Form.Get("client_assertion_type")
	assertion := r.Form.Get("client_assertion")

	const expectedType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if assertionType != expectedType {
		return nil, fmt.Errorf("%w: client_assertion_type must be %q", ErrInvalidClient, expectedType)
	}
	if assertion == "" {
		return nil, fmt.Errorf("%w: client_assertion is required", ErrInvalidClient)
	}

	// First parse without verification to get the client_id (iss/sub).
	//
	// WithVerify(false), not WithValidate(false): the latter only switches off claim
	// validation and still demands keys to check the signature, so this read of the
	// untrusted header failed for every assertion and made the method unusable. The
	// signature is verified in verifyAssertion below, which is what makes reading iss
	// from this unverified parse safe in the first place.
	tok, err := jwt.Parse([]byte(assertion), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("%w: parse assertion: %w", ErrInvalidClient, err)
	}

	clientID := tok.Issuer()
	if clientID == "" {
		clientID = tok.Subject()
	}
	if clientID == "" {
		return nil, fmt.Errorf("%w: assertion missing iss/sub", ErrInvalidClient)
	}

	client, err := a.repo.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client", ErrInvalidClient)
	}

	if client.TokenEndpointAuthMethod != domain.AuthMethodPrivateKeyJWT {
		return nil, fmt.Errorf("%w: auth method not allowed for this client", ErrInvalidClient)
	}

	// Verify the JWT properly now
	if err := a.verifyAssertion(ctx, assertion, client); err != nil {
		return nil, err
	}

	return client, nil
}

// clientVerificationKeys resolves the key set that may have signed the assertion.
//
// A jwks field holds either a bare JWK object or a JWK Set. jwk.Parse accepts only the
// bare form, so a client that published a set was refused outright. Rotating clients
// publish sets, which makes refusing them a correctness bug rather than a strictness
// choice.
//
// jwks_uri is resolved by fetch, which is why this takes ctx.
func (a *PrivateKeyJWTAuthenticator) clientVerificationKeys(ctx context.Context, client *domain.Client) (jwk.Set, error) {
	if len(client.JWKSet) > 0 {
		return parseJWKSet(client.JWKSet)
	}
	if client.JWKSURI != nil && *client.JWKSURI != "" {
		// A cached key set is a trust decision that has already been made and
		// checked, so reusing it is not a re-verification of anything. The TTL is what
		// bounds it.
		if set, ok := a.jwksCache.get(client.ClientID); ok {
			return set, nil
		}

		// Concurrent misses collapse onto one fetch rather than N.
		set, err := a.fetchGroup.do(client.ClientID, func() (jwk.Set, error) {
			body, err := a.fetchJWKS(ctx, *client.JWKSURI)
			if err != nil {
				return nil, err
			}
			return parseJWKSet(body)
		})
		if err != nil {
			return nil, err
		}
		// Only a successful fetch is cached, so a transient failure does not become a
		// TTL-long outage for the client.
		a.jwksCache.put(client.ClientID, set)
		return set, nil
	}
	return nil, fmt.Errorf("%w: client has no verification key", ErrInvalidClient)
}

// parseJWKSet accepts both encodings of a jwks value and normalises them to a set.
func parseJWKSet(raw []byte) (jwk.Set, error) {
	// The bare-JWK encoding first: it is a single object with no "keys" member, so
	// the set parse below fails on it rather than silently producing an empty set.
	if k, err := jwk.ParseKey(raw); err == nil {
		set := jwk.NewSet()
		if err := set.AddKey(k); err != nil {
			return nil, fmt.Errorf("%w: client JWKSet is unreadable: %w", ErrInvalidClient, err)
		}
		return set, nil
	}

	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse client JWKSet: %w", ErrInvalidClient, err)
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("%w: client JWKSet contains no keys", ErrInvalidClient)
	}
	return set, nil
}

// fetchJWKS retrieves a client's published key set.
//
// HTTPS only, because the response is the client's public key and an http:// jwks_uri
// lets anyone on the path substitute their own, which turns a stolen assertion into a
// stolen client. The size bound and the deadline keep one registered endpoint from
// holding a token request open.
func (a *PrivateKeyJWTAuthenticator) fetchJWKS(ctx context.Context, uri string) ([]byte, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable jwks_uri", ErrInvalidClient)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: jwks_uri must be https", ErrInvalidClient)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: jwks_uri has no host", ErrInvalidClient)
	}

	reqCtx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build jwks request", ErrInvalidClient)
	}
	req.Header.Set("Accept", "application/json")

	client := a.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch jwks_uri", ErrInvalidClient)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: jwks_uri returned %d", ErrInvalidClient, resp.StatusCode)
	}

	// LimitReader rather than ReadAll: an endpoint that streams without end is
	// bounded by the same number the server is willing to hold in memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksFetchLimit))
	if err != nil {
		return nil, fmt.Errorf("%w: read jwks_uri body", ErrInvalidClient)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: jwks_uri returned an empty body", ErrInvalidClient)
	}
	return body, nil
}

// verifyAssertion validates the JWT claims and signature.
func (a *PrivateKeyJWTAuthenticator) verifyAssertion(ctx context.Context, assertion string, client *domain.Client) error {
	keys, err := a.clientVerificationKeys(ctx, client)
	if err != nil {
		return err
	}

	// Only asymmetric algorithms. An HMAC key here would let a client authenticate with
	// a key derived from a public value, which is not authentication.
	for i := 0; i < keys.Len(); i++ {
		key, ok := keys.Key(i)
		if !ok {
			continue
		}
		alg := key.Algorithm()
		if alg != jwa.RS256 && alg != jwa.ES256 {
			return fmt.Errorf("%w: client key must be RS256 or ES256, got %s", ErrInvalidClient, alg)
		}
	}

	// The set, not a single key, is the verifier: RequireKid means the assertion names
	// the key it was signed with, so a key in the set that is not the one used cannot
	// verify it, and an assertion without a kid is refused rather than tried against
	// every key the client published.
	tok, err := jwt.Parse(
		[]byte(assertion),
		jwt.WithKeySet(keys, jws.WithRequireKid(true)),
		jwt.WithValidate(true),
	)
	if err != nil {
		return fmt.Errorf("%w: verify assertion: %w", ErrInvalidClient, err)
	}

	// Standard claims. Verified above by WithValidate, re-checked here explicitly
	// because each of these is a requirement of RFC 7523 section 3 that jwx's
	// validator does not know about: it checks that exp is present and sane, not that
	// exp is present at all.
	now := time.Now().UTC()

	// iss == sub == client_id
	iss := tok.Issuer()
	sub := tok.Subject()
	if iss != client.ClientID || sub != client.ClientID {
		return fmt.Errorf("%w: iss/sub must equal client_id", ErrInvalidClient)
	}

	// aud == token endpoint
	aud := tok.Audience()
	if len(aud) == 0 || aud[0] != a.tokenURL {
		return fmt.Errorf("%w: aud must be token endpoint", ErrInvalidClient)
	}

	// exp > now
	exp := tok.Expiration()
	if exp.IsZero() || !exp.After(now) {
		return fmt.Errorf("%w: assertion expired", ErrInvalidClient)
	}

	// jti replay check
	jti := tok.JwtID()
	if jti == "" {
		return fmt.Errorf("%w: assertion missing jti", ErrInvalidClient)
	}

	if a.revCache != nil {
		// Use revoked token cache for jti replay prevention (SET NX with TTL)
		added, err := a.revCache.AddJTI(ctx, jti, 10*time.Minute)
		if err != nil {
			return fmt.Errorf("%w: replay check failed: %w", ErrInvalidClient, err)
		}
		if !added {
			return fmt.Errorf("%w: %w", ErrInvalidClient, ErrReplayDetected)
		}
	}

	return nil
}
