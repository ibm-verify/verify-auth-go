package oauth2

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// ClientAuth is implemented by all client authentication methods.
type ClientAuth interface {
	GetParameters() (url.Values, error)
}

// ClientSecretPost authenticates using client_id and client_secret in the POST body.
type ClientSecretPost struct {
	// ClientID contains the client_id of the application or API client.
	ClientID string

	// ClientSecret contains the client_secret. It may be left empty for public clients.
	ClientSecret string
}

func (c *ClientSecretPost) GetParameters() (url.Values, error) {
	ret := url.Values{}
	ret.Add("client_id", c.ClientID)
	if len(c.ClientSecret) > 0 {
		ret.Add("client_secret", c.ClientSecret)
	}

	return ret, nil
}

// PrivateKeyJWT authenticates using a signed JWT assertion (RFC 7523 §2.2).
type PrivateKeyJWT struct {
	// Configuration is the authorization server metadata obtained via Discover.
	// Issuer and TokenEndpoint are used to populate the aud claim.
	Configuration *Configuration

	// ClientID contains the client_id of the application or API client.
	ClientID string

	// PrivateKeyJWK contains the JSONWebKey representation of the private key.
	// The KeyID and Algorithm fields must be populated.
	PrivateKeyJWK *jose.JSONWebKey

	// Expires optionally specifies how long the assertion JWT is valid for.
	// Defaults to 30 minutes.
	Expires time.Duration
}

func (c *PrivateKeyJWT) GetParameters() (url.Values, error) {
	expires := c.Expires
	if expires == 0 {
		expires = 30 * time.Minute
	}

	claims := map[string]any{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": []string{
			c.Configuration.Issuer,
			c.Configuration.TokenEndpoint,
		},
		"exp": time.Now().UTC().Add(expires).Unix(),
		"iat": time.Now().UTC().Unix(),
		"jti": uuid.NewString(),
	}

	h := map[jose.HeaderKey]any{
		jose.HeaderKey("alg"): c.PrivateKeyJWK.Algorithm,
		jose.HeaderKey("typ"): "JWT",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(c.PrivateKeyJWK.Algorithm),
			Key:       c.PrivateKeyJWK,
		}, &jose.SignerOptions{
			ExtraHeaders: h,
		})
	if err != nil {
		return nil, err
	}

	pbytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshaling claims: %w", err)
	}

	signed, err := signer.Sign(pbytes)
	if err != nil {
		return nil, err
	}

	token, err := signed.CompactSerialize()
	if err != nil {
		return nil, err
	}

	ret := url.Values{}
	ret.Add("client_id", c.ClientID)
	ret.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	ret.Add("client_assertion", token)

	return ret, nil
}
