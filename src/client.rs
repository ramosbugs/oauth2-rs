use crate::{
    AccessToken, AuthType, AuthUrl, AuthorizationCode, AuthorizationRequest,
    ClientCredentialsTokenRequest, ClientId, ClientSecret, CodeTokenRequest, ConfigurationError,
    CsrfToken, DeviceAccessTokenRequest, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
    DeviceAuthorizationUrl, ErrorResponse, ExtraDeviceAuthorizationFields, IntrospectionRequest,
    IntrospectionUrl, PasswordTokenRequest, RedirectUrl, RefreshToken, RefreshTokenRequest,
    ResourceOwnerPassword, ResourceOwnerUsername, RevocableToken, RevocationRequest, RevocationUrl,
    TokenIntrospectionResponse, TokenResponse, TokenType, TokenUrl,
};

use chrono::Utc;

use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;

/// Stores the configuration for an OAuth2 client.
///
/// This type implements the
/// [Builder Pattern](https://doc.rust-lang.org/1.0.0/style/ownership/builders.html) together with
/// [typestates](https://cliffle.com/blog/rust-typestate/#what-are-typestates) to encode whether
/// certain fields have been set that are prerequisites to certain authentication flows. For
/// example, the authorization endpoint must be set via [`Client::set_auth_url`] before
/// [`Client::authorize_url`] can be called. Each endpoint has a corresponding const generic
/// parameter (e.g., `HAS_AUTH_URL`) used to statically enforce these dependencies. These generics
/// are set automatically by the corresponding setter functions, and in most cases user code should
/// not need to deal with them directly.
///
/// # Error Types
///
/// To enable compile time verification that only the correct and complete set of errors for the `Client` function being
/// invoked are exposed to the caller, the `Client` type is specialized on multiple implementations of the
/// [`ErrorResponse`] trait. The exact [`ErrorResponse`] implementation returned varies by the RFC that the invoked
/// `Client` function implements:
///
///   - Generic type `TE` (aka Token Error) for errors defined by [RFC 6749 OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).
///   - Generic type `TRE` (aka Token Revocation Error) for errors defined by [RFC 7009 OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009).
///
/// For example when revoking a token, error code `unsupported_token_type` (from RFC 7009) may be returned:
/// ```rust
/// # use thiserror::Error;
/// # use http::status::StatusCode;
/// # use http::header::{HeaderValue, CONTENT_TYPE};
/// # use oauth2::{*, basic::*};
/// # let client = BasicClient::new(ClientId::new("aaa".to_string()))
/// #     .set_client_secret(ClientSecret::new("bbb".to_string()))
/// #     .set_auth_url(AuthUrl::new("https://example.com/auth".to_string()).unwrap())
/// #     .set_token_url(TokenUrl::new("https://example.com/token".to_string()).unwrap())
/// #     .set_revocation_uri(RevocationUrl::new("https://revocation/url".to_string()).unwrap());
/// #
/// # #[derive(Debug, Error)]
/// # enum FakeError {
/// #     #[error("error")]
/// #     Err,
/// # }
/// #
/// # let http_client = |_| -> Result<HttpResponse, FakeError> {
/// #     Ok(HttpResponse {
/// #         status_code: StatusCode::BAD_REQUEST,
/// #         headers: vec![(
/// #             CONTENT_TYPE,
/// #             HeaderValue::from_str("application/json").unwrap(),
/// #         )]
/// #         .into_iter()
/// #         .collect(),
/// #         body: "{\"error\": \"unsupported_token_type\", \"error_description\": \"stuff happened\", \
/// #                \"error_uri\": \"https://errors\"}"
/// #             .to_string()
/// #             .into_bytes(),
/// #     })
/// # };
/// #
/// let res = client
///     .revoke_token(AccessToken::new("some token".to_string()).into())
///     .unwrap()
///     .request(http_client);
///
/// assert!(matches!(res, Err(
///     RequestTokenError::ServerResponse(err)) if matches!(err.error(),
///         RevocationErrorResponseType::UnsupportedTokenType)));
/// ```
///
/// # Examples
///
/// See the [crate] root documentation for usage examples.
#[derive(Clone, Debug)]
pub struct Client<
    TE,
    TR,
    TT,
    TIR,
    RT,
    TRE,
    const HAS_AUTH_URL: bool = false,
    const HAS_DEVICE_AUTH_URL: bool = false,
    const HAS_INTROSPECTION_URL: bool = false,
    const HAS_REVOCATION_URL: bool = false,
    const HAS_TOKEN_URL: bool = false,
> where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse,
{
    pub(crate) client_id: ClientId,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) auth_url: Option<AuthUrl>,
    pub(crate) auth_type: AuthType,
    pub(crate) token_url: Option<TokenUrl>,
    pub(crate) redirect_url: Option<RedirectUrl>,
    pub(crate) introspection_url: Option<IntrospectionUrl>,
    pub(crate) revocation_url: Option<RevocationUrl>,
    pub(crate) device_authorization_url: Option<DeviceAuthorizationUrl>,
    pub(crate) phantom: PhantomData<(TE, TR, TT, TIR, RT, TRE)>,
}
impl<TE, TR, TT, TIR, RT, TRE> Client<TE, TR, TT, TIR, RT, TRE, false, false, false, false, false>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Initializes an OAuth2 client with the specified client ID.
    pub fn new(client_id: ClientId) -> Self {
        Self {
            client_id,
            client_secret: None,
            auth_url: None,
            auth_type: AuthType::BasicAuth,
            token_url: None,
            redirect_url: None,
            introspection_url: None,
            revocation_url: None,
            device_authorization_url: None,
            phantom: PhantomData,
        }
    }
}
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_AUTH_URL: bool,
        const HAS_DEVICE_AUTH_URL: bool,
        const HAS_INTROSPECTION_URL: bool,
        const HAS_REVOCATION_URL: bool,
        const HAS_TOKEN_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1). Note that
    /// if a client secret is omitted (i.e., `client_secret` is set to `None` when calling
    /// [`Client::new`]), [`AuthType::RequestBody`] is used regardless of the `auth_type` passed to
    /// this function.
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = auth_type;

        self
    }

    /// Sets the authorization endpoint.
    ///
    /// The client uses the authorization endpoint to obtain authorization from the resource owner
    /// via user-agent redirection. This URL is used in all standard OAuth2 flows except the
    /// [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
    /// and the [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4).
    pub fn set_auth_url(
        self,
        auth_url: AuthUrl,
    ) -> Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        true,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    > {
        Client {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: Some(auth_url),
            auth_type: self.auth_type,
            token_url: self.token_url,
            redirect_url: self.redirect_url,
            introspection_url: self.introspection_url,
            revocation_url: self.revocation_url,
            device_authorization_url: self.device_authorization_url,
            phantom: self.phantom,
        }
    }

    /// Sets the client secret.
    ///
    /// A client secret is generally used for confidential (i.e., server-side) OAuth2 clients and
    /// omitted from public (browser or native app) OAuth2 clients (see
    /// [RFC 8252](https://tools.ietf.org/html/rfc8252)).
    pub fn set_client_secret(mut self, client_secret: ClientSecret) -> Self {
        self.client_secret = Some(client_secret);

        self
    }

    /// Sets the device authorization URL used by the device authorization endpoint.
    /// Used for Device Code Flow, as per [RFC 8628](https://tools.ietf.org/html/rfc8628).
    pub fn set_device_authorization_url(
        self,
        device_authorization_url: DeviceAuthorizationUrl,
    ) -> Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        true,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    > {
        Client {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: self.auth_url,
            auth_type: self.auth_type,
            token_url: self.token_url,
            redirect_url: self.redirect_url,
            introspection_url: self.introspection_url,
            revocation_url: self.revocation_url,
            device_authorization_url: Some(device_authorization_url),
            phantom: self.phantom,
        }
    }

    /// Sets the introspection URL for contacting the ([RFC 7662](https://tools.ietf.org/html/rfc7662))
    /// introspection endpoint.
    pub fn set_introspection_uri(
        self,
        introspection_url: IntrospectionUrl,
    ) -> Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_TOKEN_URL,
        HAS_DEVICE_AUTH_URL,
        true,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    > {
        Client {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: self.auth_url,
            auth_type: self.auth_type,
            token_url: self.token_url,
            redirect_url: self.redirect_url,
            introspection_url: Some(introspection_url),
            revocation_url: self.revocation_url,
            device_authorization_url: self.device_authorization_url,
            phantom: self.phantom,
        }
    }

    /// Sets the redirect URL used by the authorization endpoint.
    pub fn set_redirect_uri(mut self, redirect_url: RedirectUrl) -> Self {
        self.redirect_url = Some(redirect_url);

        self
    }

    /// Sets the revocation URL for contacting the revocation endpoint ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
    ///
    /// See: [`revoke_token()`](Self::revoke_token())
    pub fn set_revocation_uri(
        self,
        revocation_url: RevocationUrl,
    ) -> Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_TOKEN_URL,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        true,
        HAS_TOKEN_URL,
    > {
        Client {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: self.auth_url,
            auth_type: self.auth_type,
            token_url: self.token_url,
            redirect_url: self.redirect_url,
            introspection_url: self.introspection_url,
            revocation_url: Some(revocation_url),
            device_authorization_url: self.device_authorization_url,
            phantom: self.phantom,
        }
    }

    /// Sets the token endpoint.
    ///
    /// The client uses the token endpoint to exchange an authorization code for an access token,
    /// typically with client authentication. This URL is used in
    /// all standard OAuth2 flows except the
    /// [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2).
    pub fn set_token_url(
        self,
        token_url: TokenUrl,
    ) -> Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        true,
    > {
        Client {
            client_id: self.client_id,
            client_secret: self.client_secret,
            auth_url: self.auth_url,
            auth_type: self.auth_type,
            token_url: Some(token_url),
            redirect_url: self.redirect_url,
            introspection_url: self.introspection_url,
            revocation_url: self.revocation_url,
            device_authorization_url: self.device_authorization_url,
            phantom: self.phantom,
        }
    }

    /// Returns the Client ID.
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the type of client authentication used for communicating with the authorization
    /// server.
    pub fn auth_type(&self) -> &AuthType {
        &self.auth_type
    }

    /// Returns the redirect URL used by the authorization endpoint.
    pub fn redirect_url(&self) -> Option<&RedirectUrl> {
        self.redirect_url.as_ref()
    }
}

// Methods requiring an authorization endpoint.
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_DEVICE_AUTH_URL: bool,
        const HAS_INTROSPECTION_URL: bool,
        const HAS_REVOCATION_URL: bool,
        const HAS_TOKEN_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        true,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Returns the authorization endpoint.
    pub fn auth_url(&self) -> &AuthUrl {
        // This is enforced statically via the HAS_AUTH_URL const generic.
        self.auth_url.as_ref().expect("should have auth_url")
    }

    /// Generates an authorization URL for a new authorization request.
    ///
    /// # Arguments
    ///
    /// * `state_fn` - A function that returns an opaque value used by the client to maintain state
    ///   between the request and callback. The authorization server includes this value when
    ///   redirecting the user-agent back to the client.
    ///
    /// # Security Warning
    ///
    /// Callers should use a fresh, unpredictable `state` for each authorization request and verify
    /// that this value matches the `state` parameter passed by the authorization server to the
    /// redirect URI. Doing so mitigates
    /// [Cross-Site Request Forgery](https://tools.ietf.org/html/rfc6749#section-10.12)
    ///  attacks. To disable CSRF protections (NOT recommended), use `insecure::authorize_url`
    ///  instead.
    pub fn authorize_url<S>(&self, state_fn: S) -> AuthorizationRequest
    where
        S: FnOnce() -> CsrfToken,
    {
        AuthorizationRequest {
            // This is enforced statically via the HAS_AUTH_URL const generic.
            auth_url: self.auth_url(),
            client_id: &self.client_id,
            extra_params: Vec::new(),
            pkce_challenge: None,
            redirect_url: self.redirect_url.as_ref().map(Cow::Borrowed),
            response_type: "code".into(),
            scopes: Vec::new(),
            state: state_fn(),
        }
    }
}

// Methods requiring a token endpoint.
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_AUTH_URL: bool,
        const HAS_DEVICE_AUTH_URL: bool,
        const HAS_INTROSPECTION_URL: bool,
        const HAS_REVOCATION_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        true,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Requests an access token for the *client credentials* grant type.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.4.2>.
    pub fn exchange_client_credentials(&self) -> ClientCredentialsTokenRequest<TE, TR, TT> {
        ClientCredentialsTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            scopes: Vec::new(),
            // This is enforced statically via the HAS_TOKEN_URL const generic.
            token_url: self.token_url.as_ref().expect("should have token_url"),
            _phantom: PhantomData,
        }
    }

    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// Acquires ownership of the `code` because authorization codes may only be used once to
    /// retrieve an access token from the authorization server.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.1.3>.
    pub fn exchange_code(&self, code: AuthorizationCode) -> CodeTokenRequest<TE, TR, TT> {
        CodeTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            code,
            extra_params: Vec::new(),
            pkce_verifier: None,
            // This is enforced statically via the HAS_TOKEN_URL const generic.
            token_url: self.token_url.as_ref().expect("should have token_url"),
            redirect_url: self.redirect_url.as_ref().map(Cow::Borrowed),
            _phantom: PhantomData,
        }
    }

    /// Perform a device access token request as per
    /// <https://tools.ietf.org/html/rfc8628#section-3.4>.
    pub fn exchange_device_access_token<'a, 'b, 'c, EF>(
        &'a self,
        auth_response: &'b DeviceAuthorizationResponse<EF>,
    ) -> DeviceAccessTokenRequest<'b, 'c, TR, TT, EF>
    where
        'a: 'b,
        EF: ExtraDeviceAuthorizationFields,
    {
        DeviceAccessTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            // This is enforced statically via the HAS_TOKEN_URL const generic.
            token_url: self.token_url.as_ref().expect("should have token_url"),
            dev_auth_resp: auth_response,
            time_fn: Arc::new(Utc::now),
            max_backoff_interval: None,
            _phantom: PhantomData,
        }
    }

    /// Requests an access token for the *password* grant type.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.3.2>.
    pub fn exchange_password<'a, 'b>(
        &'a self,
        username: &'b ResourceOwnerUsername,
        password: &'b ResourceOwnerPassword,
    ) -> PasswordTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        PasswordTokenRequest::<'b> {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            username,
            password,
            extra_params: Vec::new(),
            scopes: Vec::new(),
            // This is enforced statically via the HAS_TOKEN_URL const generic.
            token_url: self.token_url.as_ref().expect("should have token_url"),
            _phantom: PhantomData,
        }
    }

    /// Exchanges a refresh token for an access token
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-6>.
    pub fn exchange_refresh_token<'a, 'b>(
        &'a self,
        refresh_token: &'b RefreshToken,
    ) -> RefreshTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        RefreshTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            refresh_token,
            scopes: Vec::new(),
            // This is enforced statically via the HAS_TOKEN_URL const generic.
            token_url: self.token_url.as_ref().expect("should have token_url"),
            _phantom: PhantomData,
        }
    }

    /// Returns the token endpoint.
    pub fn token_url(&self) -> &TokenUrl {
        // This is enforced statically via the HAS_TOKEN_URL const generic.
        self.token_url.as_ref().expect("should have token_url")
    }
}

// Methods requiring a device authorization endpoint.
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_AUTH_URL: bool,
        const HAS_INTROSPECTION_URL: bool,
        const HAS_REVOCATION_URL: bool,
        const HAS_TOKEN_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        true,
        HAS_INTROSPECTION_URL,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Perform a device authorization request as per
    /// <https://tools.ietf.org/html/rfc8628#section-3.1>.
    pub fn exchange_device_code(&self) -> DeviceAuthorizationRequest<TE> {
        DeviceAuthorizationRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            scopes: Vec::new(),
            // This is enforced statically via the HAS_DEVICE_AUTH_URL const generic.
            device_authorization_url: self
                .device_authorization_url
                .as_ref()
                .expect("should have device_authorization_url"),
            _phantom: PhantomData,
        }
    }

    /// Returns the device authorization URL used by the device authorization endpoint.
    pub fn device_authorization_url(&self) -> &DeviceAuthorizationUrl {
        // This is enforced statically via the HAS_DEVICE_AUTH_URL const generic.
        self.device_authorization_url
            .as_ref()
            .expect("should have device_authorization_url")
    }
}

// Methods requiring an introspection endpoint.
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_AUTH_URL: bool,
        const HAS_DEVICE_AUTH_URL: bool,
        const HAS_REVOCATION_URL: bool,
        const HAS_TOKEN_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        HAS_DEVICE_AUTH_URL,
        true,
        HAS_REVOCATION_URL,
        HAS_TOKEN_URL,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Query the authorization server [`RFC 7662 compatible`](https://tools.ietf.org/html/rfc7662) introspection
    /// endpoint to determine the set of metadata for a previously received token.
    ///
    /// Requires [`set_introspection_uri()`](Self::set_introspection_uri) to have been previously
    /// called to set the introspection endpoint URL.
    pub fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
    ) -> Result<IntrospectionRequest<'a, TE, TIR, TT>, ConfigurationError> {
        Ok(IntrospectionRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            // This is enforced statically via the HAS_INTROSPECTION_URL const generic.
            introspection_url: self
                .introspection_url
                .as_ref()
                .expect("should have introspection_url"),
            token,
            token_type_hint: None,
            _phantom: PhantomData,
        })
    }

    /// Returns the introspection URL for contacting the ([RFC 7662](https://tools.ietf.org/html/rfc7662))
    /// introspection endpoint.
    pub fn introspection_url(&self) -> &IntrospectionUrl {
        // This is enforced statically via the HAS_INTROSPECTION_URL const generic.
        self.introspection_url
            .as_ref()
            .expect("should have introspection_url")
    }
}

// Methods requiring a revocation endpoint.
impl<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        const HAS_AUTH_URL: bool,
        const HAS_DEVICE_AUTH_URL: bool,
        const HAS_INTROSPECTION_URL: bool,
        const HAS_TOKEN_URL: bool,
    >
    Client<
        TE,
        TR,
        TT,
        TIR,
        RT,
        TRE,
        HAS_AUTH_URL,
        HAS_DEVICE_AUTH_URL,
        HAS_INTROSPECTION_URL,
        true,
        HAS_TOKEN_URL,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
    TIR: TokenIntrospectionResponse<TT>,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    /// Attempts to revoke the given previously received token using an
    /// [RFC 7009 OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009) compatible
    /// endpoint.
    ///
    /// Requires [`set_revocation_uri()`](Self::set_revocation_uri) to have been previously
    /// called to set the revocation endpoint URL.
    pub fn revoke_token(
        &self,
        token: RT,
    ) -> Result<RevocationRequest<RT, TRE>, ConfigurationError> {
        // https://tools.ietf.org/html/rfc7009#section-2 states:
        //   "The client requests the revocation of a particular token by making an
        //    HTTP POST request to the token revocation endpoint URL.  This URL
        //    MUST conform to the rules given in [RFC6749], Section 3.1.  Clients
        //    MUST verify that the URL is an HTTPS URL."

        // This is enforced statically via the HAS_REVOCATION_URL const generic.
        let revocation_url = self
            .revocation_url
            .as_ref()
            .expect("should have revocation_url");

        if revocation_url.url().scheme() != "https" {
            return Err(ConfigurationError::InsecureUrl("revocation"));
        }

        Ok(RevocationRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            revocation_url,
            token,
            _phantom: PhantomData,
        })
    }

    /// Returns the revocation URL for contacting the revocation endpoint
    /// ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
    ///
    /// See: [`revoke_token()`](Self::revoke_token())
    pub fn revocation_url(&self) -> &RevocationUrl {
        // This is enforced statically via the HAS_REVOCATION_URL const generic.
        self.revocation_url
            .as_ref()
            .expect("should have revocation_url")
    }
}
