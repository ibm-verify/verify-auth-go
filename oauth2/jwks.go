package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jellydator/ttlcache/v3"

	auth "github.com/ibm-verify/verify-auth-go"
)

const (
	defaultJWKSTTL       = 1 * time.Hour
	defaultJWKSClockSkew = 30 * time.Second
)

// process-level JWKS cache keyed by jwks_uri, shared across all Client instances.
var (
	jwksCacheOnce sync.Once
	jwksCache     *ttlcache.Cache[string, jose.JSONWebKeySet]
)

func getJWKSCache() *ttlcache.Cache[string, jose.JSONWebKeySet] {
	jwksCacheOnce.Do(func() {
		jwksCache = ttlcache.New[string, jose.JSONWebKeySet](
			ttlcache.WithTTL[string, jose.JSONWebKeySet](defaultJWKSTTL),
		)
		go jwksCache.Start()
	})
	return jwksCache
}

// fetchJWKSFromURI fetches the JWKS at jwksURI without consulting the cache.
func fetchJWKSFromURI(ctx context.Context, jwksURI string, httpClient *http.Client) (jose.JSONWebKeySet, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, &auth.Error{
			Code:        "jwks_fetch_failed",
			Description: "failed to create JWKS request",
			Args:        map[string]any{"jwks_uri": jwksURI},
			Cause:       err,
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, &auth.Error{
			Code:        "jwks_fetch_failed",
			Description: "failed to fetch JWKS",
			Args:        map[string]any{"jwks_uri": jwksURI},
			Cause:       err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, &auth.Error{
			Code:        "jwks_fetch_failed",
			Description: fmt.Sprintf("JWKS endpoint returned status %d", resp.StatusCode),
			Args:        map[string]any{"jwks_uri": jwksURI, "status_code": resp.StatusCode},
		}
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jose.JSONWebKeySet{}, &auth.Error{
			Code:        "jwks_decode_failed",
			Description: "failed to decode JWKS response",
			Args:        map[string]any{"jwks_uri": jwksURI},
			Cause:       err,
		}
	}

	return jwks, nil
}

// fetchJWKS returns the cached JWKS, fetching and caching it on a miss.
func fetchJWKS(ctx context.Context, jwksURI string, httpClient *http.Client) (jose.JSONWebKeySet, error) {
	cache := getJWKSCache()

	if item := cache.Get(jwksURI); item != nil {
		return item.Value(), nil
	}

	jwks, err := fetchJWKSFromURI(ctx, jwksURI, httpClient)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}

	cache.Set(jwksURI, jwks, defaultJWKSTTL)
	return jwks, nil
}

// verifyJWTSignature verifies the token signature against the JWKS and returns
// the raw payload. Claims validation is left to the caller.
// If the token's kid is absent from the cached JWKS, the cache is evicted and
// re-fetched once to handle key rotation; a present-but-failing kid is not retried.
func verifyJWTSignature(ctx context.Context, rawToken, jwksURI string, httpClient *http.Client) ([]byte, error) {
	tok, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return nil, &auth.Error{
			Code:        "token_parse_failed",
			Description: "failed to parse JWT",
			Cause:       err,
		}
	}

	var tokenKID string
	if len(tok.Signatures) > 0 {
		tokenKID = tok.Signatures[0].Protected.KeyID
	}

	jwks, err := fetchJWKS(ctx, jwksURI, httpClient)
	if err != nil {
		return nil, err
	}

	// kid absent from cache — possible rotation, re-fetch once.
	if tokenKID != "" && len(jwks.Key(tokenKID)) == 0 {
		getJWKSCache().Delete(jwksURI)
		jwks, err = fetchJWKSFromURI(ctx, jwksURI, httpClient)
		if err != nil {
			return nil, err
		}
		getJWKSCache().Set(jwksURI, jwks, defaultJWKSTTL)
	}

	keys := jwks.Key(tokenKID)
	if len(keys) == 0 {
		keys = jwks.Keys
	}

	for _, key := range keys {
		if payload, err := tok.Verify(key); err == nil {
			return payload, nil
		}
	}

	return nil, &auth.Error{
		Code:        "token_signature_invalid",
		Description: "JWT signature could not be verified against any key in the JWKS",
		Args:        map[string]any{"jwks_uri": jwksURI, "kid": tokenKID},
	}
}

// validateCommonClaims checks iss, aud, exp, and iat with clock skew tolerance.
func validateCommonClaims(iss string, aud []string, exp, iat *time.Time, expectedIssuer, expectedAudience string, now time.Time) error {
	if iss != expectedIssuer {
		return &auth.Error{
			Code:        "token_issuer_invalid",
			Description: "token issuer does not match expected issuer",
			Args:        map[string]any{"expected": expectedIssuer, "got": iss},
		}
	}

	if exp != nil && now.After(exp.Add(defaultJWKSClockSkew)) {
		return &auth.Error{
			Code:        "token_expired",
			Description: "token has expired",
			Args:        map[string]any{"exp": exp.Format(time.RFC3339)},
		}
	}

	if iat != nil && now.Before(iat.Add(-defaultJWKSClockSkew)) {
		return &auth.Error{
			Code:        "token_not_yet_valid",
			Description: "token issued in the future",
			Args:        map[string]any{"iat": iat.Format(time.RFC3339)},
		}
	}

	if expectedAudience != "" {
		found := false
		for _, a := range aud {
			if a == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return &auth.Error{
				Code:        "token_audience_invalid",
				Description: "token audience does not contain expected audience",
				Args:        map[string]any{"expected": expectedAudience, "got": aud},
			}
		}
	}

	return nil
}
