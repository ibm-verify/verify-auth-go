package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	auth "github.com/ibm-verify/verify-auth-go"
)

// isJWT reports whether token looks like a JWT by inspecting the base64url-decoded
// header for an "alg" or "typ" field. It does not fully parse the token.
func isJWT(token string) bool {
	firstDot := strings.IndexByte(token, '.')
	if firstDot == -1 {
		return false
	}
	headerPart := token[:firstDot]
	dbuf := make([]byte, base64.RawURLEncoding.DecodedLen(len(headerPart)))
	n, err := base64.RawURLEncoding.Decode(dbuf, []byte(headerPart))
	if err != nil {
		return false
	}
	headerStr := string(dbuf[:n])
	return strings.Contains(headerStr, `"alg"`) || strings.Contains(headerStr, `"typ"`)
}

// ValidateAccessToken validates a JWT or opaque access token.
//
// For JWT tokens:
//  1. Verifies the signature against the JWKS.
//  2. Validates iss, aud, exp, and iat.
//  3. If WithIntrospectionFallback is configured and the token's iat exceeds
//     the configured max age, calls IntrospectToken to confirm it has not been
//     revoked.
//
// For opaque tokens, IntrospectToken is called directly. If the introspection
// endpoint is not configured, an error is returned.
func (c *Client) ValidateAccessToken(ctx context.Context, rawToken, expectedAudience string) (*TokenClaims, error) {
	if !isJWT(rawToken) {
		return c.validateOpaqueToken(ctx, rawToken, "access_token")
	}

	payload, err := verifyJWTSignature(ctx, rawToken, c.cfg.JSONWebKeySetURI, c.httpClient())
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, &auth.Error{
			Code:        "token_claims_invalid",
			Description: "failed to decode access token claims",
			Cause:       err,
		}
	}

	now := time.Now().UTC()
	if err := validateCommonClaims(claims.Issuer, claims.Audience, claims.Expiry, claims.IssuedAt,
		c.cfg.Issuer, expectedAudience, now); err != nil {
		return nil, err
	}

	// If introspection fallback is configured and the token is older than the
	// threshold, verify it has not been revoked.
	if c.introspectionMaxAge == 0 || c.cfg.IntrospectionEndpoint == "" || claims.IssuedAt == nil || now.Sub(*claims.IssuedAt) <= c.introspectionMaxAge {
		return &claims, nil
	}

	return c.validateOpaqueToken(ctx, rawToken, "access_token")
}

// ValidateRefreshToken validates a refresh token by calling the token introspection endpoint.
// Returns an error if the introspection endpoint is not configured or the token is inactive.
func (c *Client) ValidateRefreshToken(ctx context.Context, rawToken string) (*TokenClaims, error) {
	return c.validateOpaqueToken(ctx, rawToken, "refresh_token")
}

// validateOpaqueToken calls IntrospectToken and returns the TokenClaims.
// Returns an error if the introspection endpoint is not configured or the token is inactive.
func (c *Client) validateOpaqueToken(ctx context.Context, rawToken string, tokenType string) (*TokenClaims, error) {
	if c.cfg.IntrospectionEndpoint == "" {
		return nil, &auth.Error{
			Code:        "token_validation_failed",
			Description: "Introspection endpoint is not configured",
			Args:        map[string]any{"issuer": c.cfg.Issuer},
		}
	}

	ir, err := c.IntrospectToken(ctx, rawToken, tokenType)
	if err != nil {
		return nil, err
	}

	if !ir.Active {
		return nil, &auth.Error{
			Code:        "token_revoked",
			Description: "token is not active",
		}
	}

	return &ir.TokenClaims, nil
}
