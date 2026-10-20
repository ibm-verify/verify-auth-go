package oauth2

import (
	"context"
	"encoding/json"
	"time"

	auth "github.com/ibm-verify/verify-auth-go"
)

// IDTokenClaims holds the standard OIDC ID token claims (OIDC Core §2).
type IDTokenClaims struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   *time.Time
	IssuedAt *time.Time
	Nonce    string
	Extra    map[string]any
}

func (c *IDTokenClaims) UnmarshalJSON(data []byte) error {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	c.Issuer, _ = all["iss"].(string)
	c.Subject, _ = all["sub"].(string)
	c.Nonce, _ = all["nonce"].(string)

	if raw, ok := all["aud"]; ok {
		switch v := raw.(type) {
		case string:
			c.Audience = []string{v}
		case []any:
			for _, a := range v {
				if s, ok := a.(string); ok {
					c.Audience = append(c.Audience, s)
				}
			}
		}
	}

	unixToTime := func(key string) *time.Time {
		if v, ok := all[key].(float64); ok {
			t := time.Unix(int64(v), 0).UTC()
			return &t
		}
		return nil
	}
	c.Expiry = unixToTime("exp")
	c.IssuedAt = unixToTime("iat")

	known := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nonce": true}
	for k, v := range all {
		if !known[k] {
			if c.Extra == nil {
				c.Extra = make(map[string]any)
			}
			c.Extra[k] = v
		}
	}
	return nil
}

// ValidateIDToken verifies the signature and standard claims of an OIDC ID token.
func (c *Client) ValidateIDToken(ctx context.Context, rawToken, expectedAudience string) (*IDTokenClaims, error) {
	payload, err := verifyJWTSignature(ctx, rawToken, c.cfg.JSONWebKeySetURI, c.httpClient())
	if err != nil {
		return nil, err
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, &auth.Error{
			Code:        "token_claims_invalid",
			Description: "failed to decode ID token claims",
			Cause:       err,
		}
	}

	if err := validateCommonClaims(claims.Issuer, claims.Audience, claims.Expiry, claims.IssuedAt,
		c.cfg.Issuer, expectedAudience, time.Now().UTC()); err != nil {
		return nil, err
	}

	return &claims, nil
}
