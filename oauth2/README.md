# Authentication

The authentication modules support various OAuth 2.0 and OpenID Connect flows to obtain tokens.

Supported grant types:

- [Authorization Code with PKCE](https://oauth.net/2/pkce/)
- [Device Authorization Flow](https://oauth.net/2/device-flow/)
- [Client Credentials](https://oauth.net/2/grant-types/client-credentials/)
- [Refresh Token](https://datatracker.ietf.org/doc/html/rfc6749#section-6)

Rich Authorization Requests ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)) are supported through `authorization_details` on the authorization, device authorization and token requests.

Supported client authentication methods:

- Client Secret Post: Send the `client_id` and `client_secret` in the POST body when invoking the Token endpoint.
- [Private Key JWT](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2): Use a `client_assertion` parameter with a signed JSON Web Token (JWT) value.
