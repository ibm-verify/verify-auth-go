package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4"

	oauth2pkg "github.com/ibm-verify/verify-auth-go/oauth2"
)

func newPrivateKeyJWTAuth(t *testing.T, cfg *oauth2pkg.Configuration) *oauth2pkg.PrivateKeyJWT {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &oauth2pkg.PrivateKeyJWT{
		Configuration: cfg,
		ClientID:      "test-client",
		PrivateKeyJWK: &jose.JSONWebKey{Key: key, KeyID: "k1", Algorithm: string(jose.RS256)},
	}
}

func TestAuthorizeWithBrowserFlow_OmitsClientCredentials(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()

	tests := map[string]oauth2pkg.ClientAuth{
		"private_key_jwt": newPrivateKeyJWTAuth(t, s.cfg),
		"client_secret":   &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"},
	}

	for name, clientAuth := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := oauth2pkg.NewClient(clientAuth, s.cfg, oauth2pkg.WithHTTPClient(s.Client()))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
			if err != nil {
				t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
			}

			u, err := url.Parse(ar.AuthCodeURL)
			if err != nil {
				t.Fatalf("parse AuthCodeURL: %v", err)
			}
			q := u.Query()
			assertForm(t, q, "client_id", "test-client")
			for _, k := range []string{"client_assertion", "client_assertion_type", "client_secret"} {
				if q.Has(k) {
					t.Errorf("%s must not be sent on the authorization request", k)
				}
			}
		})
	}
}

// tokenCapture is the request received by the token endpoint of a tokenServer.
type tokenCapture struct {
	authorization string
	form          url.Values
}

// tokenServer returns an OP whose token endpoint records the request and replies
// with the supplied body.
func tokenServer(t *testing.T, reply map[string]any) (*oauth2pkg.Configuration, *http.Client, *tokenCapture, func()) {
	t.Helper()

	got := &tokenCapture{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.authorization = r.Header.Get("Authorization")
		got.form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	})

	cfg := &oauth2pkg.Configuration{
		Issuer:                srv.URL,
		AuthorizationEndpoint: srv.URL + "/authorize",
		TokenEndpoint:         srv.URL + "/token",
	}
	return cfg, srv.Client(), got, srv.Close
}

func TestTokenWithAuthCode_CredentialsInBody(t *testing.T) {
	cfg, hc, got, closeFn := tokenServer(t, map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 60,
	})
	defer closeFn()

	tests := map[string]struct {
		clientAuth oauth2pkg.ClientAuth
		wantKeys   []string
	}{
		"public client": {
			clientAuth: &oauth2pkg.ClientSecretPost{ClientID: "test-client"},
			wantKeys:   []string{"client_id"},
		},
		"client_secret_post": {
			clientAuth: &oauth2pkg.ClientSecretPost{ClientID: "test-client", ClientSecret: "test-secret"},
			wantKeys:   []string{"client_id", "client_secret"},
		},
		"private_key_jwt": {
			clientAuth: newPrivateKeyJWTAuth(t, cfg),
			wantKeys:   []string{"client_id", "client_assertion", "client_assertion_type"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := oauth2pkg.NewClient(tc.clientAuth, cfg,
				oauth2pkg.WithHTTPClient(hc),
				oauth2pkg.WithRedirectURL("https://tools.example/oidc/callback"),
			)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
			if err != nil {
				t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
			}

			cb := url.Values{"code": {"abc"}, "state": {ar.State}}
			if _, err := c.TokenWithAuthCode(context.Background(), ar, cb); err != nil {
				t.Fatalf("TokenWithAuthCode: %v", err)
			}

			if got.authorization != "" {
				t.Errorf("Authorization header must not be set, got %q", got.authorization)
			}
			for _, k := range tc.wantKeys {
				if !got.form.Has(k) {
					t.Errorf("token request is missing %s", k)
				}
			}
			assertForm(t, got.form, "code_verifier", ar.PKCECodeVerifier)
		})
	}
}

func TestTokenWithAuthCode_AuthorizationDetailsInResponse(t *testing.T) {
	cfg, hc, _, closeFn := tokenServer(t, map[string]any{
		"access_token": "at",
		"token_type":   "Bearer",
		"expires_in":   60,
		"authorization_details": []any{
			map[string]any{"type": "payment_initiation", "actions": []any{"initiate"}},
		},
	})
	defer closeFn()

	c, err := oauth2pkg.NewClient(&oauth2pkg.ClientSecretPost{ClientID: "test-client"}, cfg,
		oauth2pkg.WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}

	tr, err := c.TokenWithAuthCode(context.Background(), ar, url.Values{"code": {"abc"}, "state": {ar.State}})
	if err != nil {
		t.Fatalf("TokenWithAuthCode: %v", err)
	}

	want := []map[string]any{{"type": "payment_initiation", "actions": []any{"initiate"}}}
	if !reflect.DeepEqual(tr.AuthorizationDetails, want) {
		t.Errorf("AuthorizationDetails: got %v, want %v", tr.AuthorizationDetails, want)
	}
}

func TestTokenWithAuthCode_NoAuthorizationDetailsInResponse(t *testing.T) {
	s := newStubServer(t)
	defer s.Close()
	c := newTestClient(t, s)

	ar, err := c.AuthorizeWithBrowserFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuthorizeWithBrowserFlow: %v", err)
	}
	tr, err := c.TokenWithAuthCode(context.Background(), ar, url.Values{"code": {"abc"}, "state": {ar.State}})
	if err != nil {
		t.Fatalf("TokenWithAuthCode: %v", err)
	}
	if tr.AuthorizationDetails != nil {
		t.Errorf("AuthorizationDetails: got %v, want nil", tr.AuthorizationDetails)
	}
}
