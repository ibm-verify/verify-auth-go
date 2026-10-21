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

## Documentation

- [API reference](https://pkg.go.dev/github.com/ibm-verify/verify-auth-go/oauth2): the methods on `oauth2.Client` and the available client options.
- [Supported grant types and client authentication methods](oauth2/README.md).
