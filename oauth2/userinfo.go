package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	auth "github.com/ibm-verify/verify-auth-go"
)

// UserInfoResponse holds the claims returned by the userinfo endpoint
// (OIDC Core §5.1). Extra captures any non-standard claims.
type UserInfoResponse struct {
	Subject           string         `json:"sub"`
	Name              string         `json:"name,omitempty"`
	GivenName         string         `json:"given_name,omitempty"`
	FamilyName        string         `json:"family_name,omitempty"`
	MiddleName        string         `json:"middle_name,omitempty"`
	Nickname          string         `json:"nickname,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Profile           string         `json:"profile,omitempty"`
	Picture           string         `json:"picture,omitempty"`
	Website           string         `json:"website,omitempty"`
	Email             string         `json:"email,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Gender            string         `json:"gender,omitempty"`
	Birthdate         string         `json:"birthdate,omitempty"`
	ZoneInfo          string         `json:"zoneinfo,omitempty"`
	Locale            string         `json:"locale,omitempty"`
	PhoneNumber       string         `json:"phone_number,omitempty"`
	PhoneVerified     bool           `json:"phone_number_verified,omitempty"`
	UpdatedAt         int64          `json:"updated_at,omitempty"`
	Extra             map[string]any `json:"-"`
}

var knownUserInfoClaims = map[string]bool{
	"sub": true, "name": true, "given_name": true, "family_name": true,
	"middle_name": true, "nickname": true, "preferred_username": true,
	"profile": true, "picture": true, "website": true, "email": true,
	"email_verified": true, "gender": true, "birthdate": true,
	"zoneinfo": true, "locale": true, "phone_number": true,
	"phone_number_verified": true, "updated_at": true,
}

// UserInfo calls the userinfo endpoint using the provided access token and
// returns the claims for the authenticated user (OIDC Core §5.3).
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	if c.cfg.UserinfoEndpoint == "" {
		return nil, &auth.Error{
			Code:        "userinfo_not_supported",
			Description: "the authorization server does not advertise a userinfo endpoint",
			Args:        map[string]any{"issuer": c.cfg.Issuer},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, &auth.Error{
			Code:        "userinfo_request_failed",
			Description: "failed to create userinfo request",
			Cause:       err,
		}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, &auth.Error{
			Code:        "userinfo_request_failed",
			Description: "failed to call userinfo endpoint",
			Args:        map[string]any{"issuer": c.cfg.Issuer},
			Cause:       err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, &auth.Error{
			Code:        "userinfo_request_failed",
			Description: fmt.Sprintf("userinfo endpoint returned status %d", resp.StatusCode),
			Args:        map[string]any{"status_code": resp.StatusCode, "body": string(raw)},
		}
	}

	// Decode into a raw map first so we can split known vs extra claims.
	var all map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		return nil, &auth.Error{
			Code:        "userinfo_decode_failed",
			Description: "failed to decode userinfo response",
			Cause:       err,
		}
	}

	// Marshal back to JSON and decode into the typed struct for known fields.
	b, _ := json.Marshal(all)
	var ui UserInfoResponse
	if err := json.Unmarshal(b, &ui); err != nil {
		return nil, &auth.Error{
			Code:        "userinfo_decode_failed",
			Description: "failed to decode userinfo claims",
			Cause:       err,
		}
	}

	for k, v := range all {
		if !knownUserInfoClaims[k] {
			if ui.Extra == nil {
				ui.Extra = make(map[string]any)
			}
			ui.Extra[k] = v
		}
	}

	return &ui, nil
}
