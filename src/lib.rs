#![warn(missing_docs)]
//!
//! An extensible, strongly-typed implementation of OAuth2
//! ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
//!
//! # Contents
//! * [Importing `oauth2`: selecting an HTTP client interface](#importing-oauth2-selecting-an-http-client-interface)
//! * [Getting started: Authorization Code Grant w/ PKCE](#getting-started-authorization-code-grant-w-pkce)
//!   * [Example: Synchronous (blocking) API](#example-synchronous-blocking-api)
//!   * [Example: Async/Await API](#example-asyncawait-api)
//! * [Implicit Grant](#implicit-grant)
//! * [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
//! * [Client Credentials Grant](#client-credentials-grant)
//! * [Other examples](#other-examples)
//!   * [Contributed Examples](#contributed-examples)
//!
//! # Importing `oauth2`: selecting an HTTP client interface
//!
//! This library offers a flexible HTTP client interface with two modes:
//!  * **Synchronous (blocking)**
//!
//!    The synchronous interface is available for any combination of feature flags.
//!
//!    Example import in `Cargo.toml`:
//!    ```toml
//!    oauth2 = "3.0"
//!    ```
//!
//! For the HTTP client modes described above, the following HTTP client implementations can be
//! used:
//!  * **[`reqwest`]**
//!
//!    The `reqwest` HTTP client supports both modes. By default, `reqwest` 0.10 is enabled,
//!    which supports the synchronous and asynchronous `futures` 0.3 APIs.
//!
//!    Synchronous client: [`reqwest::http_client`]
//!
//!    Async/await `futures` 0.3 client: [`reqwest::async_http_client`]
//!
//!  * **[`curl`]**
//!
//!    The `curl` HTTP client only supports the synchronous HTTP client mode and can be enabled in
//!    `Cargo.toml` via the `curl` feature flag.
//!
//!    Synchronous client: [`curl::http_client`]
//!
//!  * **Custom**
//!
//!    In addition to the clients above, users may define their own HTTP clients, which must accept
//!    an [`HttpRequest`] and return an [`HttpResponse`] or error. Users writing their own clients
//!    may wish to disable the default `reqwest` 0.10 dependency by specifying
//!    `default-features = false` in `Cargo.toml`:
//!    ```toml
//!    oauth2 = { version = "3.0", default-features = false }
//!    ```
//!
//!    Synchronous HTTP clients should implement the following trait:
//!    ```ignore
//!    FnOnce(HttpRequest) -> Result<HttpResponse, RE>
//!    where RE: std::error::Error + Send + Sync + 'static
//!
//!    Async/await HTTP clients should implement the following trait:
//!    ```ignore
//!    FnOnce(HttpRequest) -> F
//!    where
//!      F: Future<Output = Result<HttpResponse, RE>>,
//!      RE: std::error::Error + Send + Sync + 'static
//!    ```
//!
//! # Getting started: Authorization Code Grant w/ PKCE
//!
//! This is the most common OAuth2 flow. PKCE is recommended whenever the OAuth2 client has no
//! client secret or has a client secret that cannot remain confidential (e.g., native, mobile, or
//! client-side web applications).
//!
//! ## Example: Synchronous (blocking) API
//!
//! This example works with `oauth2`'s default feature flags, which include `reqwest` 0.10.
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_url(RedirectUrl::new("http://redirect".to_string())?);
//!
//! // Generate a PKCE challenge.
//! let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     // Set the desired scopes.
//!     .add_scope(Scope::new("read".to_string()))
//!     .add_scope(Scope::new("write".to_string()))
//!     // Set the PKCE code challenge.
//!     .set_pkce_challenge(pkce_challenge)
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//!
//! // Now you can trade it for an access token.
//! let token_result =
//!     client
//!         .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//!         // Set the PKCE code verifier.
//!         .set_pkce_verifier(pkce_verifier)
//!         .request(http_client)?;
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: Async/Await API
//!
//! One can use async/await as follows:
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! # #[cfg(feature = "reqwest-010")]
//! use oauth2::reqwest::async_http_client;
//! use url::Url;
//!
//! # #[cfg(feature = "reqwest-010")]
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_url(RedirectUrl::new("http://redirect".to_string())?);
//!
//! // Generate a PKCE challenge.
//! let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     // Set the desired scopes.
//!     .add_scope(Scope::new("read".to_string()))
//!     .add_scope(Scope::new("write".to_string()))
//!     // Set the PKCE code challenge.
//!     .set_pkce_challenge(pkce_challenge)
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//!
//! // Now you can trade it for an access token.
//! let token_result = client
//!     .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//!     // Set the PKCE code verifier.
//!     .set_pkce_verifier(pkce_verifier)
//!     .request_async(async_http_client)
//!     .await?;
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//! # Ok(())
//! # }
//! ```
//!
//! # Implicit Grant
//!
//! This flow fetches an access token directly from the authorization endpoint. Be sure to
//! understand the security implications of this flow before using it. In most cases, the
//! Authorization Code Grant flow is preferable to the Implicit Grant flow.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     RedirectUrl,
//!     Scope
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         None
//!     );
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     .use_implicit_flow()
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have the access code.
//! // For security reasons, your code should verify that the `state` parameter returned by the
//! // server matches `csrf_state`.
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Resource Owner Password Credentials Grant
//!
//! You can ask for a *password* access token by calling the `Client::exchange_password` method,
//! while including the username and password.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     ResourceOwnerPassword,
//!     ResourceOwnerUsername,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     );
//!
//! let token_result =
//!     client
//!         .exchange_password(
//!             &ResourceOwnerUsername::new("user".to_string()),
//!             &ResourceOwnerPassword::new("pass".to_string())
//!         )
//!         .add_scope(Scope::new("read".to_string()))
//!         .request(http_client)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Client Credentials Grant
//!
//! You can ask for a *client credentials* access token by calling the
//! `Client::exchange_client_credentials` method.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?),
//!     );
//!
//! let token_result = client
//!     .exchange_client_credentials()
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Google](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/google.rs)
//! - [Github](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/github.rs)
//! - [Microsoft Graph](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/msgraph.rs)
//! - [Wunderlist](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/wunderlist.rs)
//!
//! ## Contributed Examples
//!
//! - [`actix-web-oauth2`](https://github.com/pka/actix-web-oauth2) (version 2.x of this crate)
//!
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

use http::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::status::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::{form_urlencoded, Url};

///
/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
///
pub mod basic;

///
/// HTTP client backed by the [curl](https://crates.io/crates/curl) crate.
/// Requires "curl" feature.
///
#[cfg(feature = "curl")]
pub mod curl;

///
/// Helper methods used by OAuth2 implementations/extensions.
///
pub mod helpers;

///
/// HTTP client backed by the [reqwest](https://crates.io/crates/reqwest) crate.
/// Requires "reqwest-010" feature.
///
#[cfg(feature = "reqwest-010")]
pub mod reqwest;

#[cfg(test)]
mod tests;

mod types;

///
/// Public re-exports of types used for HTTP client interfaces.
///
pub use http;
pub use url;

pub use types::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeChallengeMethod, PkceCodeVerifier, RedirectUrl, RefreshToken, ResourceOwnerPassword,
    ResourceOwnerUsername, ResponseType, Scope, TokenUrl,
};

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

///
/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *BasicAuth*, following the recommendation of
/// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
///
#[derive(Clone, Debug)]
pub enum AuthType {
    /// The client_id and client_secret will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}

///
/// Stores the configuration for an OAuth2 client.
///
#[derive(Clone, Debug)]
pub struct Client<TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_url: AuthUrl,
    auth_type: AuthType,
    token_url: Option<TokenUrl>,
    redirect_url: Option<RedirectUrl>,
    phantom_te: PhantomData<TE>,
    phantom_tr: PhantomData<TR>,
    phantom_tt: PhantomData<TT>,
}

impl<TE, TR, TT> Client<TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Initializes an OAuth2 client with the fields common to most OAuth2 flows.
    ///
    /// # Arguments
    ///
    /// * `client_id` -  Client ID
    /// * `client_secret` -  Optional client secret. A client secret is generally used for private
    ///   (server-side) OAuth2 clients and omitted from public (client-side or native app) OAuth2
    ///   clients (see [RFC 8252](https://tools.ietf.org/html/rfc8252)).
    /// * `auth_url` -  Authorization endpoint: used by the client to obtain authorization from
    ///   the resource owner via user-agent redirection. This URL is used in all standard OAuth2
    ///   flows except the [Resource Owner Password Credentials
    ///   Grant](https://tools.ietf.org/html/rfc6749#section-4.3) and the
    ///   [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4).
    /// * `token_url` - Token endpoint: used by the client to exchange an authorization grant
    ///   (code) for an access token, typically with client authentication. This URL is used in
    ///   all standard OAuth2 flows except the
    ///   [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2). If this value is set
    ///   to `None`, the `exchange_*` methods will return `Err(RequestTokenError::Other(_))`.
    ///
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
    ) -> Self {
        Client {
            client_id,
            client_secret,
            auth_url,
            auth_type: AuthType::BasicAuth,
            token_url,
            redirect_url: None,
            phantom_te: PhantomData,
            phantom_tr: PhantomData,
            phantom_tt: PhantomData,
        }
    }

    ///
    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
    ///
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = auth_type;

        self
    }

    ///
    /// Sets the the redirect URL used by the authorization endpoint.
    ///
    pub fn set_redirect_url(mut self, redirect_url: RedirectUrl) -> Self {
        self.redirect_url = Some(redirect_url);

        self
    }

    ///
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
    ///
    pub fn authorize_url<S>(&self, state_fn: S) -> AuthorizationRequest
    where
        S: FnOnce() -> CsrfToken,
    {
        AuthorizationRequest {
            auth_url: &self.auth_url,
            client_id: &self.client_id,
            extra_params: Vec::new(),
            pkce_challenge: None,
            redirect_url: self.redirect_url.as_ref().map(Cow::Borrowed),
            response_type: "code".into(),
            scopes: Vec::new(),
            state: state_fn(),
        }
    }

    ///
    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// Acquires ownership of the `code` because authorization codes may only be used once to
    /// retrieve an access token from the authorization server.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.1.3
    ///
    pub fn exchange_code(&self, code: AuthorizationCode) -> CodeTokenRequest<TE, TR, TT> {
        CodeTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            code,
            extra_params: Vec::new(),
            pkce_verifier: None,
            token_url: self.token_url.as_ref(),
            redirect_url: self.redirect_url.as_ref(),
            _phantom: PhantomData,
        }
    }

    ///
    /// Requests an access token for the *password* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.3.2
    ///
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
            token_url: self.token_url.as_ref(),
            _phantom: PhantomData,
        }
    }

    ///
    /// Requests an access token for the *client credentials* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.4.2
    ///
    pub fn exchange_client_credentials(&self) -> ClientCredentialsTokenRequest<TE, TR, TT> {
        ClientCredentialsTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            scopes: Vec::new(),
            token_url: self.token_url.as_ref(),
            _phantom: PhantomData,
        }
    }

    ///
    /// Exchanges a refresh token for an access token
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-6
    ///
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
            token_url: self.token_url.as_ref(),
            _phantom: PhantomData,
        }
    }
}

///
/// A request to the authorization endpoint
///
#[derive(Debug)]
pub struct AuthorizationRequest<'a> {
    auth_url: &'a AuthUrl,
    client_id: &'a ClientId,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pkce_challenge: Option<PkceCodeChallenge>,
    redirect_url: Option<Cow<'a, RedirectUrl>>,
    response_type: Cow<'a, str>,
    scopes: Vec<Cow<'a, Scope>>,
    state: CsrfToken,
}
impl<'a> AuthorizationRequest<'a> {
    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Appends an extra param to the authorization URL.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Enables the [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2) flow.
    ///
    pub fn use_implicit_flow(mut self) -> Self {
        self.response_type = "token".into();
        self
    }

    ///
    /// Enables custom flows other than the `code` and `token` (implicit flow) grant.
    ///
    pub fn set_response_type(mut self, response_type: &ResponseType) -> Self {
        self.response_type = (&**response_type).to_owned().into();
        self
    }

    ///
    /// Enables the use of [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)
    /// (PKCE).
    ///
    /// PKCE is *highly recommended* for all public clients (i.e., those for which there
    /// is no client secret or for which the client secret is distributed with the client,
    /// such as in a native, mobile app, or browser app).
    ///
    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.pkce_challenge = Some(pkce_code_challenge);
        self
    }

    ///
    /// Overrides the `redirect_url` to the one specified.
    ///
    pub fn set_redirect_url(mut self, redirect_url: Cow<'a, RedirectUrl>) -> Self {
        self.redirect_url = Some(redirect_url);
        self
    }

    ///
    /// Returns the full authorization URL and CSRF state for this authorization
    /// request.
    ///
    pub fn url(self) -> (Url, CsrfToken) {
        let scopes = self
            .scopes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let url = {
            let mut pairs: Vec<(&str, &str)> = vec![
                ("response_type", self.response_type.as_ref()),
                ("client_id", &self.client_id),
                ("state", self.state.secret()),
            ];

            if let Some(ref pkce_challenge) = self.pkce_challenge {
                pairs.push(("code_challenge", &pkce_challenge.as_str()));
                pairs.push(("code_challenge_method", &pkce_challenge.method().as_str()));
            }

            if let Some(ref redirect_url) = self.redirect_url {
                pairs.push(("redirect_uri", redirect_url.as_str()));
            }

            if !scopes.is_empty() {
                pairs.push(("scope", &scopes));
            }

            let mut url: Url = self.auth_url.url().to_owned();

            url.query_pairs_mut()
                .extend_pairs(pairs.iter().map(|&(k, v)| (k, &v[..])));

            url.query_pairs_mut()
                .extend_pairs(self.extra_params.iter().cloned());
            url
        };

        (url, self.state)
    }
}

///
/// An HTTP request.
///
#[derive(Clone, Debug)]
pub struct HttpRequest {
    // These are all owned values so that the request can safely be passed between
    // threads.
    /// URL to which the HTTP request is being made.
    pub url: Url,
    /// HTTP request method for this request.
    pub method: http::method::Method,
    /// HTTP request headers to send.
    pub headers: HeaderMap,
    /// HTTP request body (typically for POST requests only).
    pub body: Vec<u8>,
}

///
/// An HTTP response.
///
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code returned by the server.
    pub status_code: http::status::StatusCode,
    /// HTTP response headers returned by the server.
    pub headers: HeaderMap,
    /// HTTP response body returned by the server.
    pub body: Vec<u8>,
}

///
/// A request to exchange an authorization code for an access token.
///
/// See https://tools.ietf.org/html/rfc6749#section-4.1.3.
///
#[derive(Debug)]
pub struct CodeTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    code: AuthorizationCode,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pkce_verifier: Option<PkceCodeVerifier>,
    token_url: Option<&'a TokenUrl>,
    redirect_url: Option<&'a RedirectUrl>,
    _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> CodeTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Completes the [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)
    /// (PKCE) protocol flow.
    ///
    /// This method must be called if `set_pkce_challenge` was used during the authorization
    /// request.
    ///
    pub fn set_pkce_verifier(mut self, pkce_verifier: PkceCodeVerifier) -> Self {
        self.pkce_verifier = Some(pkce_verifier);
        self
    }

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + Send + Sync + 'static,
    {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", self.code.secret()),
        ];
        if let Some(ref pkce_verifier) = self.pkce_verifier {
            params.push(("code_verifier", pkce_verifier.secret()));
        }

        Ok(token_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            self.redirect_url,
            None,
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?,
            params,
        ))
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + Send + Sync + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(token_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

///
/// A request to exchange a refresh token for an access token.
///
/// See https://tools.ietf.org/html/rfc6749#section-6.
///
#[derive(Debug)]
pub struct RefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    refresh_token: &'a RefreshToken,
    scopes: Vec<Cow<'a, Scope>>,
    token_url: Option<&'a TokenUrl>,
    _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> RefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Appends a new scope to the token request.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + Send + Sync + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(token_response)
    }
    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }

    fn prepare_request<RE>(&self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + Send + Sync + 'static,
    {
        Ok(token_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            Some(&self.scopes),
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?,
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", self.refresh_token.secret()),
            ],
        ))
    }
}

///
/// A request to exchange resource owner credentials for an access token.
///
/// See https://tools.ietf.org/html/rfc6749#section-4.3.
///
#[derive(Debug)]
pub struct PasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    username: &'a ResourceOwnerUsername,
    password: &'a ResourceOwnerPassword,
    scopes: Vec<Cow<'a, Scope>>,
    token_url: Option<&'a TokenUrl>,
    _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> PasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Appends a new scope to the token request.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + Send + Sync + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(token_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }

    fn prepare_request<RE>(&self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + Send + Sync + 'static,
    {
        Ok(token_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            Some(&self.scopes),
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?,
            vec![
                ("grant_type", "password"),
                ("username", self.username),
                ("password", self.password.secret()),
            ],
        ))
    }
}

///
/// A request to exchange client credentials for an access token.
///
/// See https://tools.ietf.org/html/rfc6749#section-4.4.
///
#[derive(Debug)]
pub struct ClientCredentialsTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    scopes: Vec<Cow<'a, Scope>>,
    token_url: Option<&'a TokenUrl>,
    _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> ClientCredentialsTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Appends a new scope to the token request.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, RE>(self, http_client: F) -> Result<TR, RequestTokenError<RE, TE>>
    where
        F: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: Error + Send + Sync + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(token_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }

    fn prepare_request<RE>(&self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + Send + Sync + 'static,
    {
        Ok(token_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            Some(&self.scopes),
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?,
            vec![("grant_type", "client_credentials")],
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn token_request<'a>(
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: &'a [(Cow<'a, str>, Cow<'a, str>)],
    redirect_url: Option<&'a RedirectUrl>,
    scopes: Option<&'a Vec<Cow<'a, Scope>>>,
    token_url: &'a TokenUrl,
    params: Vec<(&'a str, &'a str)>,
) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_FORMENCODED),
    );

    let scopes_opt = scopes.and_then(|scopes| {
        if !scopes.is_empty() {
            Some(
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            None
        }
    });

    let mut params: Vec<(&str, &str)> = params;
    if let Some(ref scopes) = scopes_opt {
        params.push(("scope", scopes));
    }

    // FIXME: add support for auth extensions? e.g., client_secret_jwt and private_key_jwt
    match auth_type {
        AuthType::RequestBody => {
            params.push(("client_id", client_id));
            if let Some(ref client_secret) = client_secret {
                params.push(("client_secret", client_secret.secret()));
            }
        }
        AuthType::BasicAuth => {
            // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
            // before using them as HTTP Basic auth username and password. Note that this is
            // not standard for ordinary Basic auth, so curl won't do it for us.
            let urlencoded_id: String =
                form_urlencoded::byte_serialize(&client_id.as_bytes()).collect();

            let urlencoded_secret = client_secret.map(|secret| {
                form_urlencoded::byte_serialize(secret.secret().as_bytes()).collect::<String>()
            });
            let b64_credential = base64::encode(&format!(
                "{}:{}",
                &urlencoded_id,
                urlencoded_secret
                    .as_ref()
                    .map(|secret| secret.as_str())
                    .unwrap_or("")
            ));
            headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
            );
        }
    }

    if let Some(ref redirect_url) = redirect_url {
        params.push(("redirect_uri", redirect_url.as_ref()));
    }

    params.extend_from_slice(
        extra_params
            .iter()
            .map(|&(ref k, ref v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    HttpRequest {
        url: token_url.url().to_owned(),
        method: http::method::Method::POST,
        headers,
        body,
    }
}

fn token_response<RE, TE, TR, TT>(
    http_response: HttpResponse,
) -> Result<TR, RequestTokenError<RE, TE>>
where
    RE: Error + Send + Sync + 'static,
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    if http_response.status_code != StatusCode::OK {
        let reason = http_response.body.as_slice();
        if reason.is_empty() {
            return Err(RequestTokenError::Other(
                "Server returned empty error response".to_string(),
            ));
        } else {
            let error = match serde_json::from_slice::<TE>(reason) {
                Ok(error) => RequestTokenError::ServerResponse(error),
                Err(error) => RequestTokenError::Parse(error, reason.to_vec()),
            };
            return Err(error);
        }
    }

    // Validate that the response Content-Type is JSON.
    http_response
        .headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if content_type.to_str().ok().filter(|ct| ct.to_lowercase().starts_with(CONTENT_TYPE_JSON)).is_none() {
                Err(
                    RequestTokenError::Other(
                        format!(
                            "Unexpected response Content-Type: {:?}, should be `{}`",
                            content_type,
                            CONTENT_TYPE_JSON
                        )
                    )
                )
            } else {
                Ok(())
            }
        )?;

    if http_response.body.is_empty() {
        Err(RequestTokenError::Other(
            "Server returned empty response body".to_string(),
        ))
    } else {
        let response_body = http_response.body.as_slice();
        serde_json::from_slice(response_body)
            .map_err(|e| RequestTokenError::Parse(e, response_body.to_vec()))
    }
}

///
/// Trait for OAuth2 access tokens.
///
pub trait TokenType: Clone + DeserializeOwned + Debug + PartialEq + Serialize {}

///
/// Trait for adding extra fields to the `TokenResponse`.
///
pub trait ExtraTokenFields: DeserializeOwned + Debug + Serialize {}

///
/// Empty (default) extra token fields.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmptyExtraTokenFields {}
impl ExtraTokenFields for EmptyExtraTokenFields {}

///
/// Common methods shared by all OAuth2 token implementations.
///
/// The methods in this trait are defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1). This trait exists
/// separately from the `StandardTokenResponse` struct to support customization by clients,
/// such as supporting interoperability with non-standards-complaint OAuth2 providers.
///
pub trait TokenResponse<TT>: Debug + DeserializeOwned + Serialize
where
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken;
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT;
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration>;
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken>;
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scipe of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>>;
}

///
/// Standard OAuth2 token response.
///
/// This struct includes the fields defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1), as well as
/// extensions defined by the `EF` type parameter.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}
impl<EF, TT> StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// Instantiate a new OAuth2 token response.
    ///
    pub fn new(access_token: AccessToken, token_type: TT, extra_fields: EF) -> Self {
        Self {
            access_token,
            token_type,
            expires_in: None,
            refresh_token: None,
            scopes: None,
            extra_fields,
        }
    }

    ///
    /// Set the `access_token` field.
    ///
    pub fn set_access_token(&mut self, access_token: AccessToken) {
        self.access_token = access_token;
    }

    ///
    /// Set the `token_type` field.
    ///
    pub fn set_token_type(&mut self, token_type: TT) {
        self.token_type = token_type;
    }

    ///
    /// Set the `expires_in` field.
    ///
    pub fn set_expires_in(&mut self, expires_in: Option<&Duration>) {
        self.expires_in = expires_in.map(Duration::as_secs);
    }

    ///
    /// Set the `refresh_token` field.
    ///
    pub fn set_refresh_token(&mut self, refresh_token: Option<RefreshToken>) {
        self.refresh_token = refresh_token;
    }

    ///
    /// Set the `scopes` field.
    ///
    pub fn set_scopes(&mut self, scopes: Option<Vec<Scope>>) {
        self.scopes = scopes;
    }

    ///
    /// Extra fields defined by the client application.
    ///
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }

    ///
    /// Set the extra fields defined by the client application.
    ///
    pub fn set_extra_fields(&mut self, extra_fields: EF) {
        self.extra_fields = extra_fields;
    }
}
impl<EF, TT> TokenResponse<TT> for StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT {
        &self.token_type
    }
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scipe of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

///
/// Server Error Response
///
/// This trait exists separately from the `StandardErrorResponse` struct
/// to support customization by clients, such as supporting interoperability with
/// non-standards-complaint OAuth2 providers
///
pub trait ErrorResponse: Debug + DeserializeOwned + Send + Serialize + Sync {}

///
/// Error types enum.
///
/// NOTE: The serialization must return the `snake_case` representation of
/// this error type. This value must match the error type from the relevant OAuth 2.0 standards
/// (RFC 6749 or an extension).
///
pub trait ErrorResponseType: Debug + DeserializeOwned + Send + Serialize + Sync {}

///
/// Error response returned by server after requesting an access token.
///
/// The fields in this structure are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2). This
/// trait is parameterized by a `ErrorResponseType` to support error types specific to future OAuth2
/// authentication schemes and extensions.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StandardErrorResponse<T: ErrorResponseType> {
    #[serde(bound = "T: ErrorResponseType")]
    error: T,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

impl<T: ErrorResponseType> StandardErrorResponse<T> {
    ///
    /// Instantiate a new `ErrorResponse`.
    ///
    /// # Arguments
    ///
    /// * `error` - REQUIRED. A single ASCII error code deserialized to the generic parameter.
    ///   `ErrorResponseType`.
    /// * `error_description` - OPTIONAL. Human-readable ASCII text providing additional
    ///   information, used to assist the client developer in understanding the error that
    ///   occurred. Values for this parameter MUST NOT include characters outside the set
    ///   `%x20-21 / %x23-5B / %x5D-7E`.
    /// * `error_uri` - OPTIONAL. A URI identifying a human-readable web page with information
    ///   about the error used to provide the client developer with additional information about
    ///   the error. Values for the "error_uri" parameter MUST conform to the URI-reference
    ///   syntax and thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    pub fn new(error: T, error_description: Option<String>, error_uri: Option<String>) -> Self {
        Self {
            error,
            error_description,
            error_uri,
        }
    }

    ///
    /// REQUIRED. A single ASCII error code deserialized to the generic parameter
    /// `ErrorResponseType`.
    ///
    pub fn error(&self) -> &T {
        &self.error
    }
    ///
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred. Values for this
    /// parameter MUST NOT include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
    ///
    pub fn error_description(&self) -> Option<&String> {
        self.error_description.as_ref()
    }
    ///
    /// OPTIONAL. URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and
    /// thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    pub fn error_uri(&self) -> Option<&String> {
        self.error_uri.as_ref()
    }
}

impl<T> ErrorResponse for StandardErrorResponse<T> where T: ErrorResponseType + 'static {}

impl<TE> Display for StandardErrorResponse<TE>
where
    TE: ErrorResponseType + Display,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let mut formatted = self.error().to_string();

        if let Some(error_description) = self.error_description() {
            formatted.push_str(": ");
            formatted.push_str(error_description);
        }

        if let Some(error_uri) = self.error_uri() {
            formatted.push_str(" / See ");
            formatted.push_str(error_uri);
        }

        write!(f, "{}", formatted)
    }
}

///
/// Error encountered while requesting access token.
///
#[derive(Debug, thiserror::Error)]
pub enum RequestTokenError<RE, T>
where
    RE: Error + Send + Sync + 'static,
    T: ErrorResponse + 'static,
{
    ///
    /// Error response returned by authorization server. Contains the parsed `ErrorResponse`
    /// returned by the server.
    ///
    #[error("Server returned error response")]
    ServerResponse(T),
    ///
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity Errored).
    ///
    #[error("Request Errored")]
    Request(#[source] RE),
    ///
    /// Errored to parse server response. Parse errors may occur while parsing either successful
    /// or error responses.
    ///
    #[error("Failed to parse server response")]
    Parse(#[source] serde_json::error::Error, Vec<u8>),
    ///
    /// Some other type of error occurred (e.g., an unexpected server response).
    ///
    #[error("Other error: {}", _0)]
    Other(String),
}
