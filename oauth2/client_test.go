package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/ibm-verify/verify-auth-go"
	oauth2pkg "github.com/ibm-verify/verify-auth-go/oauth2"
)

// stubTokenResponse is the JSON the stub server returns from the token endpoint.
var stubTokenResponse = map[string]any{
	"access_token":  "stub-access-token",
	"token_type":    "Bearer",
	"expires_in":    3600,
	"refresh_token": "stub-refresh-token",
	"scope":         "openid profile",
	"id_token":      "stub-id-token",
	"grant_id":      "stub-grant-id",
}

// stubServer stands up a minimal OAuth 2.0 / OIDC server using httptest.
// It exposes the discovery, token, device authorization, introspection, and
// revocation endpoints. The returned *httptest.Server must be closed by the caller.
type stubServer struct {
	*httptest.Server
	cfg *oauth2pkg.Configuration

	mu    sync.Mutex
	forms map[string]url.Values // last form received, keyed by request path
}

func (s *stubServer) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forms == nil {
		s.forms = map[string]url.Values{}
	}
	s.forms[r.URL.Path] = r.PostForm
}

// lastForm returns the last form body received at the given path.
func (s *stubServer) lastForm(path string) url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forms[path]
}

func newStubServer(t *testing.T) *stubServer {
	t.Helper()

	mux := http.NewServeMux()
	s := httptest.NewServer(mux)
	stub := &stubServer{Server: s}

	issuer := s.URL + "/oauth2"

	cfg := &oauth2pkg.Configuration{
		Issuer:                      issuer,
		AuthorizationEndpoint:       issuer + "/authorize",
		TokenEndpoint:               issuer + "/token",
		DeviceAuthorizationEndpoint: issuer + "/device_authorization",
		IntrospectionEndpoint:       issuer + "/introspect",
		RevocationEndpoint:          issuer + "/revoke",
	}

	// Discovery endpoint
	mux.HandleFunc("/oauth2/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	// Token endpoint — handles authorization_code, client_credentials, refresh_token
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		stub.record(r)

		// Verify client credentials are present
		if r.FormValue("client_id") == "" {
			writeOAuthError(w, "invalid_client", "missing client_id")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stubTokenResponse)
	})

	// Device authorization endpoint
	mux.HandleFunc("/oauth2/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		stub.record(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "stub-device-code",
			"user_code":        "STUB-1234",
			"verification_uri": issuer + "/device",
			"expires_in":       600,
			"interval":         1,
		})
	})

	// Introspection endpoint
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		stub.record(r)
		token := r.FormValue("token")
		active := token == "stub-access-token"
		now := time.Now().UTC()
		exp := now.Add(time.Hour)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":     active,
			"sub":        "user-123",
			"client_id":  r.FormValue("client_id"),
			"token_type": "Bearer",
			"scope":      "openid profile",
			"iss":        issuer,
			"iat":        now.Unix(),
			"exp":        exp.Unix(),
			// non-standard claim to exercise Extra
			"custom_claim": "custom_value",
		})
	})

	// Revocation endpoint
	mux.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		stub.record(r)
		w.WriteHeader(http.StatusOK)
	})

	stub.cfg = cfg
	return stub
}

func writeOAuthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func newTestClient(t *testing.T, s *stubServer) *oauth2pkg.Client {
	t.Helper()
	auth := &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"}
	c, err := oauth2pkg.NewClient(auth, s.cfg,
		oauth2pkg.WithHTTPClient(s.Client()),
		oauth2pkg.WithScopes("openid", "profile"),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// ----------------------------------------------------------------------------
// Discover
// ----------------------------------------------------------------------------

func TestDiscover(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	cfg, err := oauth2pkg.Discover(context.Background(), s.cfg.Issuer, s.Client())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if cfg.Issuer != s.cfg.Issuer {
		t.Errorf("Issuer: got %q, want %q", cfg.Issuer, s.cfg.Issuer)
	}
	if cfg.TokenEndpoint != s.cfg.TokenEndpoint {
		t.Errorf("TokenEndpoint: got %q, want %q", cfg.TokenEndpoint, s.cfg.TokenEndpoint)
	}
}

func TestDiscover_NotFound(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()

	_, err := oauth2pkg.Discover(context.Background(), s.URL+"/oauth2", s.Client())
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

// ----------------------------------------------------------------------------
// NewClient validation
// ----------------------------------------------------------------------------

func TestNewClient_NilConfig(t *testing.T) {
	_, err := oauth2pkg.NewClient(&oauth2pkg.ClientSecretPost{ClientID: "x"}, nil)
	if err == nil {
		t.Fatal("expected error for nil cfg")
	}
}

func TestNewClient_EmptyIssuer(t *testing.T) {
	_, err := oauth2pkg.NewClient(&oauth2pkg.ClientSecretPost{ClientID: "x"}, &oauth2pkg.Configuration{})
	if err == nil {
		t.Fatal("expected error for empty issuer")
	}
}

// ----------------------------------------------------------------------------
// Client credentials (TokenWithAPIClient)
// ----------------------------------------------------------------------------

func TestTokenWithAPIClient(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	tr, err := c.TokenWithAPIClient(context.Background(), nil)
	if err != nil {
		t.Fatalf("TokenWithAPIClient: %v", err)
	}

	if tr.AccessToken != "stub-access-token" {
		t.Errorf("AccessToken: got %q, want %q", tr.AccessToken, "stub-access-token")
	}
	if tr.GrantID != "stub-grant-id" {
		t.Errorf("GrantID: got %q, want %q", tr.GrantID, "stub-grant-id")
	}
}

func TestTokenWithAPIClient_ExtraParams(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	// Verify caller-supplied params are forwarded and don't break the flow.
	c := newTestClient(t, s)
	params := url.Values{"custom_param": {"custom_value"}}

	tr, err := c.TokenWithAPIClient(context.Background(), params)
	if err != nil {
		t.Fatalf("TokenWithAPIClient with extra params: %v", err)
	}
	if tr.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
}

// ----------------------------------------------------------------------------
// Authorization code flow (AuthorizeWithBrowserFlow + TokenWithAuthCode)
// ----------------------------------------------------------------------------

func TestAuthorizeWithBrowserFlow(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}

	if ar.State == "" {
		t.Error("expected non-empty state")
	}
	if ar.PKCECodeVerifier == "" {
		t.Error("expected non-empty PKCE verifier")
	}
	if !strings.Contains(ar.AuthCodeURL, s.cfg.AuthorizationEndpoint) {
		t.Errorf("AuthCodeURL %q does not contain authorization endpoint %q", ar.AuthCodeURL, s.cfg.AuthorizationEndpoint)
	}
	if !strings.Contains(ar.AuthCodeURL, "code_challenge=") {
		t.Error("AuthCodeURL missing code_challenge (PKCE)")
	}
}

func TestTokenWithAuthCode(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}

	callback := url.Values{
		"code":  {"stub-auth-code"},
		"state": {ar.State},
	}

	tr, err := c.TokenWithAuthCode(context.Background(), ar, callback)
	if err != nil {
		t.Fatalf("TokenWithAuthCode: %v", err)
	}
	if tr.AccessToken != "stub-access-token" {
		t.Errorf("AccessToken: got %q, want %q", tr.AccessToken, "stub-access-token")
	}
	if tr.IDToken != "stub-id-token" {
		t.Errorf("IDToken: got %q, want %q", tr.IDToken, "stub-id-token")
	}
}

func TestTokenWithAuthCode_StateMismatch(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	ar, _ := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	callback := url.Values{
		"code":  {"stub-auth-code"},
		"state": {"wrong-state"},
	}

	_, err := c.TokenWithAuthCode(context.Background(), ar, callback)
	if err == nil {
		t.Fatal("expected state mismatch error")
	}
	var authErr *auth.Error
	if !errors.As(err, &authErr) || authErr.Code != "state_mismatch" {
		t.Errorf("expected auth.Error with code state_mismatch, got: %v", err)
	}
}

func TestTokenWithAuthCode_ErrorCallback(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)
	ar, _ := c.AuthorizeWithBrowserFlow(context.Background(), nil)

	callback := url.Values{
		"error":             {"access_denied"},
		"error_description": {"user denied"},
		"state":             {ar.State},
	}

	_, err := c.TokenWithAuthCode(context.Background(), ar, callback)
	if err == nil {
		t.Fatal("expected error for error callback")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Device authorization flow
// ----------------------------------------------------------------------------

func TestAuthorizeWithDeviceFlow(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	dar, err := c.AuthorizeWithDeviceFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithDeviceFlow: %v", err)
	}

	if dar.DeviceCode == "" {
		t.Error("expected non-empty device code")
	}
	if dar.UserCode == "" {
		t.Error("expected non-empty user code")
	}
}

func TestTokenWithDeviceFlow(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	dar, err := c.AuthorizeWithDeviceFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithDeviceFlow: %v", err)
	}

	// golang.org/x/oauth2 enforces a minimum 5s poll interval internally.
	// Use a context with enough headroom for one poll cycle.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr, err := c.TokenWithDeviceFlow(ctx, dar)
	if err != nil {
		t.Fatalf("TokenWithDeviceFlow: %v", err)
	}
	if tr.AccessToken != "stub-access-token" {
		t.Errorf("AccessToken: got %q, want %q", tr.AccessToken, "stub-access-token")
	}
}

// ----------------------------------------------------------------------------
// Refresh token
// ----------------------------------------------------------------------------

func TestTokenWithRefreshToken(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	tr, err := c.TokenWithRefreshToken(context.Background(), "stub-refresh-token", nil)
	if err != nil {
		t.Fatalf("TokenWithRefreshToken: %v", err)
	}
	if tr.AccessToken != "stub-access-token" {
		t.Errorf("AccessToken: got %q, want %q", tr.AccessToken, "stub-access-token")
	}
}

// ----------------------------------------------------------------------------
// Introspection
// ----------------------------------------------------------------------------

func TestIntrospectToken_Active(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	ir, err := c.IntrospectToken(context.Background(), "stub-access-token", "access_token")
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}

	if !ir.Active {
		t.Error("expected token to be active")
	}
	if ir.Subject != "user-123" {
		t.Errorf("Subject: got %q, want %q", ir.Subject, "user-123")
	}
	if ir.Expiry == nil {
		t.Error("expected non-nil Expiry")
	}
	if ir.IssuedAt == nil {
		t.Error("expected non-nil IssuedAt")
	}
	if v, ok := ir.Extra["custom_claim"]; !ok || v != "custom_value" {
		t.Errorf("Extra[custom_claim]: got %v, want %q", v, "custom_value")
	}
}

func TestIntrospectToken_Inactive(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	ir, err := c.IntrospectToken(context.Background(), "expired-token", "access_token")
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if ir.Active {
		t.Error("expected token to be inactive")
	}
}

// ----------------------------------------------------------------------------
// Revocation
// ----------------------------------------------------------------------------

func TestRevokeToken(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	c := newTestClient(t, s)

	if err := c.RevokeToken(context.Background(), "stub-access-token", "access_token"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

func TestRevokeToken_ServerError(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	// Override the revocation endpoint to return an error.
	errorMux := http.NewServeMux()
	errorMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	errServer := httptest.NewServer(errorMux)
	defer errServer.Close()

	cfg := *s.cfg
	cfg.RevocationEndpoint = errServer.URL + "/"

	auth := &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"}
	c, err := oauth2pkg.NewClient(auth, &cfg, oauth2pkg.WithHTTPClient(errServer.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.RevokeToken(context.Background(), "some-token", ""); err == nil {
		t.Fatal("expected error for server 500")
	}
}

// ----------------------------------------------------------------------------
// IntrospectionResponse.UnmarshalJSON
// ----------------------------------------------------------------------------

func TestIntrospectionResponse_UnmarshalJSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := fmt.Sprintf(`{
		"active": true,
		"sub": "alice",
		"iss": "https://example.com",
		"aud": ["client-a", "client-b"],
		"scope": "openid",
		"client_id": "client-a",
		"username": "alice@example.com",
		"token_type": "Bearer",
		"exp": %d,
		"iat": %d,
		"nbf": %d,
		"jti": "abc123",
		"vendor_claim": 42
	}`, now.Add(time.Hour).Unix(), now.Unix(), now.Unix())

	var ir oauth2pkg.IntrospectionResponse
	if err := json.Unmarshal([]byte(payload), &ir); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if !ir.Active {
		t.Error("Active: want true")
	}
	if ir.Subject != "alice" {
		t.Errorf("Subject: got %q", ir.Subject)
	}
	if ir.Issuer != "https://example.com" {
		t.Errorf("Issuer: got %q", ir.Issuer)
	}
	if len(ir.Audience) != 2 {
		t.Errorf("Audience len: got %d, want 2", len(ir.Audience))
	}
	if ir.JWTID != "abc123" {
		t.Errorf("JWTID: got %q", ir.JWTID)
	}
	if ir.Expiry == nil || !ir.Expiry.Equal(now.Add(time.Hour)) {
		t.Errorf("Expiry: got %v, want %v", ir.Expiry, now.Add(time.Hour))
	}
	if v, ok := ir.Extra["vendor_claim"]; !ok {
		t.Error("Extra missing vendor_claim")
	} else if v.(float64) != 42 {
		t.Errorf("Extra[vendor_claim]: got %v, want 42", v)
	}
	// Known fields must not appear in Extra.
	for _, known := range []string{"active", "sub", "iss", "aud", "exp", "iat", "nbf", "jti"} {
		if _, ok := ir.Extra[known]; ok {
			t.Errorf("Extra should not contain known field %q", known)
		}
	}
}

func TestIntrospectionResponse_AudienceString(t *testing.T) {
	payload := `{"active":true,"aud":"single-client"}`
	var ir oauth2pkg.IntrospectionResponse
	if err := json.Unmarshal([]byte(payload), &ir); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(ir.Audience) != 1 || ir.Audience[0] != "single-client" {
		t.Errorf("Audience: got %v, want [single-client]", ir.Audience)
	}
}
