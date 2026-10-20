package oauth2

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenWithAPIClient performs the client credentials grant (RFC 6749 §4.4).
func (c *Client) TokenWithAPIClient(ctx context.Context, parameters url.Values) (*TokenResponse, error) {
	p, err := c.endpointParams(parameters)
	if err != nil {
		return nil, err
	}

	oauthConfig := &clientcredentials.Config{
		ClientID:       p.id,
		ClientSecret:   p.secret,
		TokenURL:       c.cfg.TokenEndpoint,
		AuthStyle:      oauth2.AuthStyleInParams,
		EndpointParams: p.params,
		Scopes:         c.Scopes,
	}

	t, err := oauthConfig.Token(c.ctx(ctx))
	if err != nil {
		return nil, wrapOAuthError(err)
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}

// TokenWithRefreshToken exchanges a refresh token for a new access token (RFC 6749 §6).
func (c *Client) TokenWithRefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	p, err := c.endpointParams()
	if err != nil {
		return nil, err
	}

	oauthConfig := &oauth2.Config{
		ClientID:     p.id,
		ClientSecret: p.secret,
		Endpoint: oauth2.Endpoint{
			TokenURL:  c.cfg.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: c.Scopes,
	}

	stale := &oauth2.Token{RefreshToken: refreshToken}
	t, err := oauthConfig.TokenSource(c.ctx(ctx), stale).Token()
	if err != nil {
		return nil, wrapOAuthError(err)
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}
