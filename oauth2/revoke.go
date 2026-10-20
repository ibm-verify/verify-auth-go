package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	auth "github.com/ibm-verify/verify-auth-go"
)

// RevokeToken calls the token revocation endpoint (RFC 7009).
func (c *Client) RevokeToken(ctx context.Context, token, tokenTypeHint string) error {
	if c.cfg.RevocationEndpoint == "" {
		return &auth.Error{
			Code:        "revocation_not_supported",
			Description: "the authorization server does not advertise a revocation endpoint",
			Args:        map[string]any{"issuer": c.cfg.Issuer},
		}
	}

	p, err := c.endpointParams()
	if err != nil {
		return err
	}

	body := url.Values{}
	body.Set("token", token)
	if tokenTypeHint != "" {
		body.Set("token_type_hint", tokenTypeHint)
	}
	body.Set("client_id", p.id)
	if p.secret != "" {
		body.Set("client_secret", p.secret)
	}
	for k := range p.params {
		body.Set(k, p.params.Get(k))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.RevocationEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return &auth.Error{
			Code:        "revocation_request_failed",
			Description: "failed to create revocation request",
			Cause:       err,
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return &auth.Error{
			Code:        "revocation_request_failed",
			Description: "failed to call revocation endpoint",
			Cause:       err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return &auth.Error{
			Code:        "revocation_request_failed",
			Description: fmt.Sprintf("revocation endpoint returned status %d", resp.StatusCode),
			Args:        map[string]any{"status_code": resp.StatusCode, "body": string(raw)},
		}
	}

	return nil
}
