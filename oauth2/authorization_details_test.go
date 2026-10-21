package oauth2_test

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	oauth2pkg "github.com/ibm-verify/verify-auth-go/oauth2"
)

var testAuthorizationDetails = []map[string]any{
	{"type": "payment_initiation", "actions": []any{"initiate"}},
}

const testAuthorizationDetailsJSON = `[{"actions":["initiate"],"type":"payment_initiation"}]`

func newTestClientWithDetails(t *testing.T, s *stubServer) *oauth2pkg.Client {
	t.Helper()
	auth := &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"}
	c, err := oauth2pkg.NewClient(auth, s.cfg,
		oauth2pkg.WithHTTPClient(s.Client()),
		oauth2pkg.WithScopes("openid", "profile"),
		oauth2pkg.WithAuthorizationDetails(testAuthorizationDetails),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func assertForm(t *testing.T, form url.Values, key, want string) {
	t.Helper()
	if got := form.Get(key); got != want {
		t.Errorf("%s: got %q, want %q", key, got, want)
	}
}

func TestAuthorizationDetails_AuthorizeURL(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}
	u, err := url.Parse(ar.AuthCodeURL)
	if err != nil {
		t.Fatalf("parse AuthCodeURL: %v", err)
	}
	assertForm(t, u.Query(), "authorization_details", testAuthorizationDetailsJSON)
}

func TestAuthorizationDetails_NotSetWhenEmpty(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClient(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}
	u, _ := url.Parse(ar.AuthCodeURL)
	if u.Query().Has("authorization_details") {
		t.Error("authorization_details must be absent when not configured")
	}

	if _, err := c.TokenWithAPIClient(context.Background(), nil); err != nil {
		t.Fatalf("TokenWithAPIClient: %v", err)
	}
	if s.lastForm("/oauth2/token").Has("authorization_details") {
		t.Error("authorization_details must be absent from token request when not configured")
	}
}

func TestAuthorizationDetails_AuthorizationCodeToken(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}
	cb := url.Values{"code": {"stub-auth-code"}, "state": {ar.State}}
	if _, err := c.TokenWithAuthCode(context.Background(), ar, cb); err != nil {
		t.Fatalf("TokenWithAuthCode: %v", err)
	}

	form := s.lastForm("/oauth2/token")
	assertForm(t, form, "grant_type", "authorization_code")
	assertForm(t, form, "authorization_details", testAuthorizationDetailsJSON)
}

func TestAuthorizationDetails_ClientCredentials(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	if _, err := c.TokenWithAPIClient(context.Background(), nil); err != nil {
		t.Fatalf("TokenWithAPIClient: %v", err)
	}
	form := s.lastForm("/oauth2/token")
	assertForm(t, form, "grant_type", "client_credentials")
	assertForm(t, form, "authorization_details", testAuthorizationDetailsJSON)
}

func TestAuthorizationDetails_DeviceAuthorization(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	if _, err := c.AuthorizeWithDeviceFlow(context.Background(), nil); err != nil {
		t.Fatalf("AuthorizeWithDeviceFlow: %v", err)
	}
	assertForm(t, s.lastForm("/oauth2/device_authorization"), "authorization_details", testAuthorizationDetailsJSON)
}

func TestAuthorizationDetails_CallerValueWins(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	override := `[{"type":"account_information"}]`
	params := url.Values{"authorization_details": {override}}
	if _, err := c.TokenWithAPIClient(context.Background(), params); err != nil {
		t.Fatalf("TokenWithAPIClient: %v", err)
	}
	assertForm(t, s.lastForm("/oauth2/token"), "authorization_details", override)
}

func TestAuthorizationDetails_NotSentToIntrospectOrRevoke(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	if _, err := c.IntrospectToken(context.Background(), "stub-access-token", "access_token"); err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if s.lastForm("/oauth2/introspect").Has("authorization_details") {
		t.Error("authorization_details must not be sent to the introspection endpoint")
	}

	if err := c.RevokeToken(context.Background(), "stub-access-token", "access_token"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if s.lastForm("/oauth2/revoke").Has("authorization_details") {
		t.Error("authorization_details must not be sent to the revocation endpoint")
	}
}

func TestAuthorizationDetails_MarshalError(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	auth := &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"}
	c, err := oauth2pkg.NewClient(auth, s.cfg,
		oauth2pkg.WithHTTPClient(s.Client()),
		oauth2pkg.WithAuthorizationDetails([]map[string]any{{"bad": make(chan int)}}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.TokenWithAPIClient(context.Background(), nil); err == nil {
		t.Fatal("expected marshal error, got nil")
	}
}

// ----------------------------------------------------------------------------
// Refresh token: scope / authorization_details
// ----------------------------------------------------------------------------

func TestTokenWithRefreshToken_RequestForm(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	if _, err := c.TokenWithRefreshToken(context.Background(), "my-refresh-token", nil); err != nil {
		t.Fatalf("TokenWithRefreshToken: %v", err)
	}

	form := s.lastForm("/oauth2/token")
	assertForm(t, form, "grant_type", "refresh_token")
	assertForm(t, form, "refresh_token", "my-refresh-token")
	assertForm(t, form, "client_id", "test-client")
	// Default behaviour re-sends the client's scopes.
	assertForm(t, form, "scope", "openid profile")
	assertForm(t, form, "authorization_details", testAuthorizationDetailsJSON)
}

func TestTokenWithRefreshToken_DownScope(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClient(t, s)

	params := url.Values{"scope": {"openid  email"}}
	if _, err := c.TokenWithRefreshToken(context.Background(), "my-refresh-token", params); err != nil {
		t.Fatalf("TokenWithRefreshToken: %v", err)
	}

	form := s.lastForm("/oauth2/token")
	assertForm(t, form, "grant_type", "refresh_token")
	assertForm(t, form, "scope", "openid email")
	if got := len(form["scope"]); got != 1 {
		t.Errorf("scope sent %d times, want 1", got)
	}
	if form.Has("authorization_details") {
		t.Error("authorization_details must be absent when not configured")
	}
}

func TestTokenWithRefreshToken_DownScopeAuthorizationDetails(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClientWithDetails(t, s)

	narrow := []map[string]any{{"type": "payment_initiation", "actions": []any{"read"}}}
	buf, _ := json.Marshal(narrow)
	params := url.Values{"authorization_details": {string(buf)}, "scope": {"openid"}}

	if _, err := c.TokenWithRefreshToken(context.Background(), "my-refresh-token", params); err != nil {
		t.Fatalf("TokenWithRefreshToken: %v", err)
	}

	form := s.lastForm("/oauth2/token")
	assertForm(t, form, "scope", "openid")

	var got []map[string]any
	if err := json.Unmarshal([]byte(form.Get("authorization_details")), &got); err != nil {
		t.Fatalf("authorization_details is not valid JSON: %v", err)
	}
	if !reflect.DeepEqual(got, narrow) {
		t.Errorf("authorization_details: got %v, want %v", got, narrow)
	}
}

func TestTokenWithRefreshToken_DoesNotMutateParameters(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClient(t, s)

	params := url.Values{"scope": {"openid"}}
	if _, err := c.TokenWithRefreshToken(context.Background(), "my-refresh-token", params); err != nil {
		t.Fatalf("TokenWithRefreshToken: %v", err)
	}
	if params.Get("scope") != "openid" || len(params) != 1 {
		t.Errorf("caller's parameters were mutated: %v", params)
	}
}
