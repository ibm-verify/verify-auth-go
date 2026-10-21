package oauth2

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenWithAPIClient performs the client credentials grant (RFC 6749 §4.4).
func (c *Client) TokenWithAPIClient(ctx context.Context, parameters url.Values) (*TokenResponse, error) {
	p, err := c.endpointParams(parameters)
	if err != nil {
		return nil, err
	}
	if err := c.authorizationDetailsParam(p.params); err != nil {
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
//
// The client's scopes are sent by default. To down-scope the new token, pass a
// space-delimited "scope" in parameters; it replaces the client's scopes for this
// request. Other entries in parameters, such as "authorization_details", are sent
// as-is and take precedence over the values configured on the client.
func (c *Client) TokenWithRefreshToken(ctx context.Context, refreshToken string, parameters url.Values) (*TokenResponse, error) {
	p, err := c.endpointParams(parameters)
	if err != nil {
		return nil, err
	}
	if err := c.authorizationDetailsParam(p.params); err != nil {
		return nil, err
	}
	p.params.Set("grant_type", "refresh_token")
	p.params.Set("refresh_token", refreshToken)

	oauthConfig := &clientcredentials.Config{
		ClientID:       p.id,
		ClientSecret:   p.secret,
		TokenURL:       c.cfg.TokenEndpoint,
		AuthStyle:      oauth2.AuthStyleInParams,
		EndpointParams: p.params,
		Scopes:         c.Scopes,
	}

	// clientcredentials rejects a "scope" endpoint param when Scopes is set,
	// so move a caller-supplied scope (down-scoping, RFC 6749 §6) into Scopes.
	if s := p.params.Get("scope"); s != "" {
		oauthConfig.Scopes = strings.Fields(s)
		p.params.Del("scope")
	}

	t, err := oauthConfig.Token(c.ctx(ctx))
	if err != nil {
		return nil, wrapOAuthError(err)
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}
