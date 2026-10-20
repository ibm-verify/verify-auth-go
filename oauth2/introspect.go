package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	auth "github.com/ibm-verify/verify-auth-go"
)

// IntrospectToken calls the token introspection endpoint (RFC 7662).
func (c *Client) IntrospectToken(ctx context.Context, token, tokenTypeHint string) (*IntrospectionResponse, error) {
	if c.cfg.IntrospectionEndpoint == "" {
		return nil, &auth.Error{
			Code:        "introspection_not_supported",
			Description: "the authorization server does not advertise an introspection endpoint",
			Args:        map[string]any{"issuer": c.cfg.Issuer},
		}
	}

	p, err := c.endpointParams()
	if err != nil {
		return nil, err
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.IntrospectionEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, &auth.Error{
			Code:        "introspection_request_failed",
			Description: "failed to create introspection request",
			Cause:       err,
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, &auth.Error{
			Code:        "introspection_request_failed",
			Description: "failed to call introspection endpoint",
			Cause:       err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, &auth.Error{
			Code:        "introspection_request_failed",
			Description: fmt.Sprintf("introspection endpoint returned status %d", resp.StatusCode),
			Args:        map[string]any{"status_code": resp.StatusCode, "body": string(raw)},
		}
	}

	var ir IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, &auth.Error{
			Code:        "introspection_decode_failed",
			Description: "failed to decode introspection response",
			Cause:       err,
		}
	}

	return &ir, nil
}
