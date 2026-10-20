package oauth2

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	auth "github.com/ibm-verify/verify-auth-go"
)

var (
	randFunc   = rand.Reader
	alphaLower = []rune("abcdefghijklmnopqrstuvwxyz")
)

type DeviceAuthTokenCallback func() (*oauth2.Token, error)

// Client represents an OAuth 2.0 / OIDC client.
type Client struct {
	cfg                 *Configuration
	ClientAuth          ClientAuth
	RedirectURL         string
	Scopes              []string
	// HTTPClient is used for all requests. Defaults to http.DefaultClient if nil.
	HTTPClient          *http.Client
	introspectionMaxAge time.Duration
}

// ClientOption configures optional fields on a Client.
type ClientOption func(*Client)

func WithRedirectURL(u string) ClientOption {
	return func(c *Client) { c.RedirectURL = u }
}

func WithScopes(scopes ...string) ClientOption {
	return func(c *Client) { c.Scopes = scopes }
}

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.HTTPClient = hc }
}

// WithIntrospectionFallback enables revocation checking for JWT access tokens
// whose iat exceeds maxAge. When ValidateAccessToken encounters a token older
// than maxAge, it calls IntrospectToken to confirm it has not been revoked.
func WithIntrospectionFallback(maxAge time.Duration) ClientOption {
	return func(c *Client) { c.introspectionMaxAge = maxAge }
}

// NewClient creates a Client from the provided Configuration.
// Use Discover to obtain cfg, or construct it manually for testing.
func NewClient(clientAuth ClientAuth, cfg *Configuration, opts ...ClientOption) (*Client, error) {
	if cfg == nil {
		return nil, &auth.Error{
			Code:        "invalid_configuration",
			Description: "cfg is required; use Discover to obtain it",
		}
	}
	if cfg.Issuer == "" {
		return nil, &auth.Error{
			Code:        "invalid_configuration",
			Description: "cfg.Issuer must not be empty",
		}
	}

	c := &Client{
		cfg:        cfg,
		ClientAuth: clientAuth,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) ctx(parent context.Context) context.Context {
	return context.WithValue(parent, oauth2.HTTPClient, c.httpClient())
}

type endpointResult struct {
	id     string
	secret string
	params url.Values
}

// endpointParams extracts client credentials from ClientAuth and merges any
// extra caller-supplied parameters. Caller values take precedence.
func (c *Client) endpointParams(extra ...url.Values) (endpointResult, error) {
	raw, err := c.ClientAuth.GetParameters()
	if err != nil {
		return endpointResult{}, err
	}

	res := endpointResult{
		id:     raw.Get("client_id"),
		secret: raw.Get("client_secret"),
	}
	raw.Del("client_id")
	raw.Del("client_secret")

	for _, vals := range extra {
		for k, vs := range vals {
			raw[k] = vs
		}
	}
	res.params = raw
	return res, nil
}

// wrapOAuthError converts golang.org/x/oauth2 errors into *auth.Error.
func wrapOAuthError(err error) error {
	if err == nil {
		return nil
	}
	var ae *auth.Error
	if errors.As(err, &ae) {
		return ae
	}
	// golang.org/x/oauth2 surfaces AS errors as *oauth2.RetrieveError.
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		code := re.ErrorCode
		if code == "" {
			code = "token_request_failed"
		}
		return &auth.Error{
			Code:        code,
			Description: re.ErrorDescription,
			Args:        map[string]any{"status_code": re.Response.StatusCode},
			Cause:       err,
		}
	}
	return &auth.Error{
		Code:        "token_request_failed",
		Description: err.Error(),
		Cause:       err,
	}
}

// generateRandomString returns a cryptographically random string of length l.
func generateRandomString(l int, allowedRunes []rune) (string, error) {
	c := big.NewInt(int64(len(allowedRunes)))
	seq := make([]rune, l)

	for i := range l {
		r, err := rand.Int(randFunc, c)
		if err != nil {
			return "", err
		}
		seq[i] = allowedRunes[r.Uint64()]
	}

	return string(seq), nil
}

// generateState returns a random state value, falling back to a UUID.
func generateState() string {
	s, err := generateRandomString(24, alphaLower)
	if err != nil {
		return uuid.NewString()
	}
	return s
}
