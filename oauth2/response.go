package oauth2

import (
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

type AuthorizeResponse struct {
	State string

	AuthCodeURL string

	PKCECodeVerifier string
}

type DeviceAuthResponse = oauth2.DeviceAuthResponse

// TokenResponse defines model for TokenResponse.
type TokenResponse struct {
	// AccessToken The access token that is issued by the authorization server.
	AccessToken string `json:"access_token"`

	// ExpiresIn The lifetime, in seconds, of the access token.
	ExpiresIn int64 `json:"expires_in"`

	// GrantID The grant identifier of this authorization grant.
	GrantID string `json:"grant_id"`

	// IDToken The ID token that is issued by the authorization server, when the requested scope contains 'openid'.
	IDToken string `json:"id_token,omitempty"`

	// RefreshToken The refresh token that is used to obtain new access tokens. It is only available for authorization_code grant if the refresh_token grant is enabled.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Scope A space-delimited list of scopes that are associated with this access token.
	Scope string `json:"scope,omitempty"`

	// AuthorizationDetails is a slice of authorization_detail objects granted to the token
	// that complies with [RFC9396 - Rich Authorization Request].
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`

	// TokenType The type of the access token.
	TokenType string `json:"token_type"`
}

func NewTokenResponseWithOAuth2Token(t *oauth2.Token) *TokenResponse {
	tr := &TokenResponse{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpiresIn:    t.ExpiresIn,
		TokenType:    t.TokenType,
	}

	if grantID, ok := t.Extra("grant_id").(string); ok {
		tr.GrantID = grantID
	}

	if idToken, ok := t.Extra("id_token").(string); ok {
		tr.IDToken = idToken
	}

	if scope, ok := t.Extra("scope").(string); ok {
		tr.Scope = scope
	}

	if authDetails, ok := t.Extra("authorization_details").([]any); ok && len(authDetails) > 0 {
		tr.AuthorizationDetails = make([]map[string]any, len(authDetails))
		for i, authDetail := range authDetails {
			if ad, ok := authDetail.(map[string]any); ok {
				tr.AuthorizationDetails[i] = ad
			}

			// This runs the risk of having some of the tr.AuthorizationDetails items set to nil if the
			// authorization detail objects are malformed. This is intentional to take advantage of pre-allocating
			// the slice in TokenResponse.
		}
	}

	return tr
}

// TokenClaims represents the claims in a JWT formatted access token
// or within the introspection response payload. Extra contains any
// non-standard claims.
type TokenClaims struct {
	// Scope is a space-delimited list of scopes associated with the token.
	Scope string

	// ClientID identifies the client that requested the token.
	ClientID string

	// Username is a human-readable identifier for the resource owner.
	Username string

	// TokenType is the type of the token (e.g. "Bearer").
	TokenType string

	// Expiry is the time at which the token expires.
	Expiry *time.Time

	// IssuedAt is the time at which the token was issued.
	IssuedAt *time.Time

	// NotBefore is the time before which the token must not be accepted.
	NotBefore *time.Time

	// Subject is the subject of the token.
	Subject string

	// Audience identifies the recipients that the token is intended for.
	Audience []string

	// Issuer identifies the principal that issued the token.
	Issuer string

	// JWTID is a unique identifier for the token.
	JWTID string

	// Extra contains any non-standard claims returned by the introspection
	// endpoint that are not covered by the fields above.
	Extra map[string]any
}

type IntrospectionResponse struct {
	TokenClaims

	// Active indicates whether the token is currently active.
	Active bool
}

var knownClaims = map[string]bool{
	"active": true, "scope": true, "client_id": true, "username": true,
	"token_type": true, "exp": true, "iat": true, "nbf": true,
	"sub": true, "aud": true, "iss": true, "jti": true,
}

func (c *TokenClaims) fromMap(all map[string]any) {
	c.Scope, _ = all["scope"].(string)
	c.ClientID, _ = all["client_id"].(string)
	c.Username, _ = all["username"].(string)
	c.TokenType, _ = all["token_type"].(string)
	c.Subject, _ = all["sub"].(string)
	c.Issuer, _ = all["iss"].(string)
	c.JWTID, _ = all["jti"].(string)

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
	c.NotBefore = unixToTime("nbf")

	for k, v := range all {
		if !knownClaims[k] {
			if c.Extra == nil {
				c.Extra = make(map[string]any)
			}
			c.Extra[k] = v
		}
	}
}

// UnmarshalJSON decodes standard JWT or RFC 7662 claims in a single pass, populating
// known fields and capturing everything else in Extra.
func (c *TokenClaims) UnmarshalJSON(data []byte) error {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	c.fromMap(all)
	return nil
}

// UnmarshalJSON decodes the introspection response in a single pass, populating
// known fields and capturing everything else in Extra.
func (r *IntrospectionResponse) UnmarshalJSON(data []byte) error {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	r.Active, _ = all["active"].(bool)
	r.TokenClaims.fromMap(all)
	return nil
}
