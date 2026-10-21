// Package oauth2 provides an OAuth 2.0 and OpenID Connect client for IBM Verify
// and other standards-compliant authorization servers.
//
// Retrieve the server metadata with [Discover], choose a [ClientAuth] such as
// [ClientSecretPost] or [PrivateKeyJWT], and create a [Client] with [NewClient].
// The methods on [Client] cover token acquisition, validation and lifecycle
// operations.
package oauth2
