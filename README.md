# IBM Verify Auth SDK for Go

`verify-auth-go` provides OAuth 2.0 and OpenID Connect (OIDC) capabilities for authenticating with IBM Verify or standard OIDC Providers.

## Installation

```bash
go get github.com/ibm-verify/verify-auth-go
```

## Quick Start

Working with the SDK follows a 3-step workflow:

1. **Discover configuration** from the authorization server's well-known endpoint.
2. **Configure client authentication** (`ClientSecretPost` or `PrivateKeyJWT`).
3. **Instantiate the `Client`**.

```go
package main

import (
	"context"
	"log"

	"github.com/ibm-verify/verify-auth-go/oauth2"
)

func main() {
	ctx := context.Background()

	// 1. Discover server metadata
	cfg, err := oauth2.Discover(ctx, "https://tenant.verify.ibm.com/oauth2", nil)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}

	// 2. Configure client authentication
	auth := &oauth2.ClientSecretPost{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
	}

	// 3. Create the client
	client, err := oauth2.NewClient(auth, cfg,
		oauth2.WithScopes("openid"),
		oauth2.WithRedirectURL("https://example.com/callback"),
	)
	if err != nil {
		log.Fatalf("client creation failed: %v", err)
	}

	// client is ready to use
	_ = client
}
```

## Common Workflows

Once initialized, `*oauth2.Client` handles token acquisition, validation, and lifecycle operations:

### 1. Acquiring Tokens
* **Client Credentials / API Client**: Request access tokens using machine-to-machine client credentials (`TokenWithAPIClient`).
* **Browser / Authorization Code Flow**: Generate authorization URLs with PKCE support (`AuthorizeWithBrowserFlow`) and exchange authorization codes for tokens (`TokenWithAuthCode`).
* **Device Authorization Grant**: Request device codes for headless devices (`AuthorizeWithDeviceFlow`) and poll for the token (`TokenWithDeviceFlow`).
* **Refresh Token**: Refresh expired access tokens (`TokenWithRefreshToken`).

### 2. Validating Tokens
* **Access Tokens**: Validate JWT signatures against JWKS, verify standard claims (`iss`, `aud`, `exp`), or automatically introspect opaque tokens (`ValidateAccessToken`).
* **ID Tokens**: Verify signatures and OIDC claims against the issuer JWKS (`ValidateIDToken`).
* **Refresh Tokens**: Verify active status via server introspection (`ValidateRefreshToken`).

### 3. Token Lifecycle & User Info
* **Introspection**: Inspect token status and custom claims (`IntrospectToken`).
* **Revocation**: Revoke access or refresh tokens (`RevokeToken`).
* **UserInfo**: Fetch claims for authenticated users from the OIDC UserInfo endpoint (`UserInfo`).

## Client Options

Configure optional client behavior using functional options passed to `oauth2.NewClient`:

* `WithScopes(...)`: Sets default scopes for token requests.
* `WithRedirectURL(...)`: Sets the OAuth 2.0 redirect URI.
* `WithHTTPClient(...)`: Provides a custom `*http.Client` for requests.
* `WithIntrospectionFallback(maxAge)`: Enables automatic revocation checks via introspection when validating JWTs older than `maxAge`.
