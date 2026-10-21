package oauth2

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"

	auth "github.com/ibm-verify/verify-auth-go"
)

// AuthorizeWithBrowserFlow builds the authorization URL for the auth code + PKCE flow.
func (c *Client) AuthorizeWithBrowserFlow(ctx context.Context, parameters url.Values) (*AuthorizeResponse, error) {
	p, err := c.endpointParams(parameters)
	if err != nil {
		return nil, err
	}
	if err := c.authorizationDetailsParam(p.params); err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range p.params {
		opts = append(opts, oauth2.SetAuthURLParam(k, p.params.Get(k)))
	}

	verifier := oauth2.GenerateVerifier()
	opts = append(opts, oauth2.S256ChallengeOption(verifier))

	oauthConfig := &oauth2.Config{
		ClientID: p.id,
		Endpoint: oauth2.Endpoint{
			AuthURL: c.cfg.AuthorizationEndpoint,
		},
		RedirectURL: c.RedirectURL,
		Scopes:      c.Scopes,
	}

	state := generateState()

	return &AuthorizeResponse{
		State:            state,
		AuthCodeURL:      oauthConfig.AuthCodeURL(state, opts...),
		PKCECodeVerifier: verifier,
	}, nil
}

// TokenWithAuthCode exchanges an authorization code for tokens.
func (c *Client) TokenWithAuthCode(ctx context.Context, authResponse *AuthorizeResponse, callbackParams url.Values) (*TokenResponse, error) {
	if errCode := callbackParams.Get("error"); errCode != "" {
		return nil, &auth.Error{
			Code:        errCode,
			Description: callbackParams.Get("error_description"),
		}
	}

	if callbackParams.Get("state") != authResponse.State {
		return nil, &auth.Error{
			Code:        "state_mismatch",
			Description: "state parameter does not match the expected value",
			Args:        map[string]any{"expected": authResponse.State},
		}
	}

	p, err := c.endpointParams()
	if err != nil {
		return nil, err
	}

	if err := c.authorizationDetailsParam(p.params); err != nil {
		return nil, err
	}

	oauthConfig := &oauth2.Config{
		ClientID:     p.id,
		ClientSecret: p.secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.cfg.AuthorizationEndpoint,
			TokenURL: c.cfg.TokenEndpoint,
		},
		Scopes:      c.Scopes,
		RedirectURL: c.RedirectURL,
	}

	var opts []oauth2.AuthCodeOption
	for k := range p.params {
		opts = append(opts, oauth2.SetAuthURLParam(k, p.params.Get(k)))
	}
	opts = append(opts, oauth2.VerifierOption(authResponse.PKCECodeVerifier))

	t, err := oauthConfig.Exchange(c.ctx(ctx), callbackParams.Get("code"), opts...)
	if err != nil {
		return nil, wrapOAuthError(err)
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}

// AuthorizeWithDeviceFlow initiates the device authorization grant.
func (c *Client) AuthorizeWithDeviceFlow(ctx context.Context, parameters url.Values) (*DeviceAuthResponse, error) {
	p, err := c.endpointParams(parameters)
	if err != nil {
		return nil, err
	}
	if err := c.authorizationDetailsParam(p.params); err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range p.params {
		opts = append(opts, oauth2.SetAuthURLParam(k, p.params.Get(k)))
	}

	oauthConfig := &oauth2.Config{
		ClientID: p.id,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: c.cfg.DeviceAuthorizationEndpoint,
		},
		Scopes: c.Scopes,
	}

	resp, err := oauthConfig.DeviceAuth(c.ctx(ctx), opts...)
	if err != nil {
		return nil, wrapOAuthError(err)
	}
	return resp, nil
}

// TokenWithDeviceFlow polls for a token until granted, denied, or the context times out.
func (c *Client) TokenWithDeviceFlow(ctx context.Context, deviceAuthResponse *oauth2.DeviceAuthResponse) (*TokenResponse, error) {
	p, err := c.endpointParams()
	if err != nil {
		return nil, err
	}
	if err := c.authorizationDetailsParam(p.params); err != nil {
		return nil, err
	}

	oauthConfig := &oauth2.Config{
		ClientID:     p.id,
		ClientSecret: p.secret,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: c.cfg.DeviceAuthorizationEndpoint,
			TokenURL:      c.cfg.TokenEndpoint,
		},
		Scopes: c.Scopes,
	}

	var opts []oauth2.AuthCodeOption
	for k := range p.params {
		opts = append(opts, oauth2.SetAuthURLParam(k, p.params.Get(k)))
	}

	t, err := oauthConfig.DeviceAccessToken(c.ctx(ctx), deviceAuthResponse, opts...)
	if err != nil {
		return nil, wrapOAuthError(err)
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}
