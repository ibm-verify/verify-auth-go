package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// DiscoveryEndpoint is the well-known path appended to an issuer URL.
const DiscoveryEndpoint = "/.well-known/openid-configuration"

// Discover fetches the authorization server metadata from issuer+DiscoveryEndpoint.
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (*Configuration, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+DiscoveryEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("configuration endpoint returned status %d", resp.StatusCode)
	}

	var cfg Configuration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}

	return &cfg, nil
}

// Configuration holds OAuth 2.0 / OIDC authorization server metadata (RFC 8414).
type Configuration struct {
	// Issuer is the identifier of the authorization server.
	Issuer string `json:"issuer,omitempty"`

	// AuthorizationEndpoint is the URL of the OAuth 2.0 Authorization Endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`

	// TokenEndpoint is the URL of the OAuth 2.0 Token Endpoint.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// IntrospectionEndpoint is the URL of the OAuth 2.0 Introspection Endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// UserinfoEndpoint is the URL where an access token can be used to retrieve user info.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// RevocationEndpoint is the URL of the OAuth 2.0 Revocation Endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// EndSessionEndpoint is the URL for RP-initiated logout.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	// DeviceAuthorizationEndpoint is the URL of the Device Authorization Endpoint (RFC 8628).
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// UserAuthorizationEndpoint is the IBM Verify user authorization endpoint.
	UserAuthorizationEndpoint string `json:"user_authorization_endpoint,omitempty"`

	// JSONWebKeySetURI is the URL of the JSON Web Key Set.
	JSONWebKeySetURI string `json:"jwks_uri,omitempty"`

	// PushedAuthorizationRequestEndpoint is the URL of the PAR endpoint (RFC 9126).
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	// MTLSEndpointAliases contains mTLS-specific endpoint aliases (RFC 8705).
	MTLSEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`

	// RegistrationEndpoint is the URL for Dynamic Client Registration.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported lists the supported scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported lists the supported response_type values.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// ResponseModesSupported lists the supported response_mode values.
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported lists the supported grant_type values.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// ACRValuesSupported lists the supported ACR values.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// SubjectTypesSupported lists the supported subject identifier types.
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`

	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported,omitempty"`
	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported,omitempty"`
	AuthorizationSigningAlgValuesSupported    []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// IDTokenSigningAlgValuesSupported lists the supported JWS algorithms for ID tokens.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported lists the supported JWE alg values for ID tokens.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// IDTokenEncryptionEncValuesSupported lists the supported JWE enc values for ID tokens.
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserinfoSigningAlgValuesSupported lists the supported JWS algorithms for UserInfo.
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// UserinfoEncryptionAlgValuesSupported lists the supported JWE alg values for UserInfo.
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserinfoEncryptionEncValuesSupported lists the supported JWE enc values for UserInfo.
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// RequestObjectSigningAlgValuesSupported lists the supported JWS algorithms for Request Objects.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RequestObjectEncryptionAlgValuesSupported lists the supported JWE alg values for Request Objects.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// RequestObjectEncryptionEncValuesSupported lists the supported JWE enc values for Request Objects.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists the supported client authentication methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// TokenEndpointAuthSigningAlgValuesSupported lists the supported JWS algorithms for token endpoint auth.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// RevocationEndpointAuthMethodsSupported lists the supported client authentication methods for revocation.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// RevocationEndpointAuthSigningAlgValuesSupported lists the supported JWS algorithms for revocation auth.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// IntrospectionEndpointAuthMethodsSupported lists the supported client authentication methods for introspection.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// IntrospectionEndpointAuthSigningAlgValuesSupported lists the supported JWS algorithms for introspection auth.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// ClaimTypesSupported lists the supported claim types.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// ClaimsSupported lists the claim names the server may supply.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// ClaimsParameterSupported specifies whether the claims parameter is supported.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// CodeChallengeMethodsSupported lists the supported PKCE code challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// ClaimsLocalesSupported lists the supported BCP47 language tags for claims.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// UILocalesSupported lists the supported BCP47 language tags for the UI.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// RequestParameterSupported specifies whether the request parameter is supported.
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// RequestURIParameterSupported specifies whether the request_uri parameter is supported.
	// Defaults to true per spec, so no omitempty.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`

	// RequireRequestURIRegistration specifies whether request_uri pre-registration is required.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	// DPoPSigningAlgValuesSupported lists the supported DPoP signing algorithms (RFC 9449).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// TLSClientCertificateBoundAccessTokens indicates support for certificate-bound tokens (RFC 8705).
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// BackChannelLogoutSupported indicates support for back-channel logout.
	BackChannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`

	// BackChannelLogoutSessionSupported indicates support for sid claim in logout tokens.
	BackChannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// Extra contains properties present in the metadata document not covered by
	// the well-known fields above.
	Extra map[string]any `json:"-"`
}

// MTLSEndpointAliases contains mTLS-specific endpoint aliases (RFC 8705).
type MTLSEndpointAliases struct {
	// TokenEndpoint is the mTLS alias for the token endpoint.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// IntrospectionEndpoint is the mTLS alias for the introspection endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// RevocationEndpoint is the mTLS alias for the revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// PushedAuthorizationRequestEndpoint is the mTLS alias for the PAR endpoint.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}
