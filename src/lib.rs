#![warn(missing_docs)]
//!
//! An extensible, strongly-typed implementation of OAuth2
//! ([RFC 6749](https://tools.ietf.org/html/rfc6749)) including token introspection ([RFC 7662](https://tools.ietf.org/html/rfc7662))
//! and token revocation ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
//!
//! # Contents
//! * [Importing `oauth2`: selecting an HTTP client interface](#importing-oauth2-selecting-an-http-client-interface)
//! * [Getting started: Authorization Code Grant w/ PKCE](#getting-started-authorization-code-grant-w-pkce)
//!   * [Example: Synchronous (blocking) API](#example-synchronous-blocking-api)
//!   * [Example: Asynchronous API](#example-asynchronous-api)
//! * [Implicit Grant](#implicit-grant)
//! * [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
//! * [Client Credentials Grant](#client-credentials-grant)
//! * [Device Code Flow](#device-code-flow)
//! * [Other examples](#other-examples)
//!   * [Contributed Examples](#contributed-examples)
//!
//! # Importing `oauth2`: selecting an HTTP client interface
//!
//! This library offers a flexible HTTP client interface with two modes:
//!  * **Synchronous (blocking)**
//!  * **Asynchronous**
//!
//! For the HTTP client modes described above, the following HTTP client implementations can be
//! used:
//!  * **[`reqwest`]**
//!
//!    The `reqwest` HTTP client supports both the synchronous and asynchronous modes and is enabled
//!    by default.
//!
//!    Synchronous client: [`reqwest::http_client`]
//!
//!    Asynchronous client: [`reqwest::async_http_client`]
//!
//!  * **[`curl`]**
//!
//!    The `curl` HTTP client only supports the synchronous HTTP client mode and can be enabled in
//!    `Cargo.toml` via the `curl` feature flag.
//!
//!    Synchronous client: [`curl::http_client`]
//!
//! * **[`ureq`]**
//!
//!    The `ureq` HTTP client is a simple HTTP client with minimal dependencies. It only supports
//!    the synchronous HTTP client mode and can be enabled in `Cargo.toml` via the `ureq` feature
//!     flag.
//!
//!  * **Custom**
//!
//!    In addition to the clients above, users may define their own HTTP clients, which must accept
//!    an [`HttpRequest`] and return an [`HttpResponse`] or error. Users writing their own clients
//!    may wish to disable the default `reqwest` dependency by specifying
//!    `default-features = false` in `Cargo.toml` (replacing `...` with the desired version of this
//!    crate):
//!    ```toml
//!    oauth2 = { version = "...", default-features = false }
//!    ```
//!
//!    Synchronous HTTP clients should implement the following trait:
//!    ```rust,ignore
//!    FnOnce(HttpRequest) -> Result<HttpResponse, RE>
//!    where RE: std::error::Error + 'static
//!    ```
//!
//!    Asynchronous HTTP clients should implement the following trait:
//!    ```rust,ignore
//!    FnOnce(HttpRequest) -> F
//!    where
//!      F: Future<Output = Result<HttpResponse, RE>>,
//!      RE: std::error::Error + 'static
//!    ```
//!
//! # Comparing secrets securely
//!
//! OAuth flows require comparing secrets received from the provider servers. To do so securely
//! while avoiding [timing side-channels](https://en.wikipedia.org/wiki/Timing_attack), the
//! comparison must be done in constant time, either using a constant-time crate such as
//! [`constant_time_eq`](https://crates.io/crates/constant_time_eq) (which could break if a future
//! compiler version decides to be overly smart
//! about its optimizations), or by first computing a cryptographically-secure hash (e.g., SHA-256)
//! of both values and then comparing the hashes using `==`.
//!
//! The `timing-resistant-secret-traits` feature flag adds a safe (but comparatively expensive)
//! [`PartialEq`] implementation to the secret types. Timing side-channels are why [`PartialEq`] is
//! not auto-derived for this crate's secret types, and the lack of [`PartialEq`] is intended to
//! prompt users to think more carefully about these comparisons.
//!
//! # Getting started: Authorization Code Grant w/ PKCE
//!
//! This is the most common OAuth2 flow. PKCE is recommended whenever the OAuth2 client has no
//! client secret or has a client secret that cannot remain confidential (e.g., native, mobile, or
//! client-side web applications).
//!
//! ## Example: Synchronous (blocking) API
//!
//! This example works with `oauth2`'s default feature flags, which include `reqwest`.
//!
//! ```rust,no_run
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
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?)
//!     .set_token_uri(TokenUrl::new("http://token".to_string())?)
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
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
//! // parameter returned by the server matches `csrf_token`.
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
//! ## Example: Asynchronous API
//!
//! The example below uses async/await:
//!
//! ```rust,no_run
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
//! # #[cfg(feature = "reqwest")]
//! use oauth2::reqwest::async_http_client;
//! use url::Url;
//!
//! # #[cfg(feature = "reqwest")]
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?)
//!     .set_token_uri(TokenUrl::new("http://token".to_string())?)
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
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
//! // parameter returned by the server matches `csrf_token`.
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
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?);
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
//! // server matches `csrf_token`.
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
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?)
//!     .set_token_uri(TokenUrl::new("http://token".to_string())?);
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
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?)
//!     .set_token_uri(TokenUrl::new("http://token".to_string())?);
//!
//! let token_result = client
//!     .exchange_client_credentials()
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Device Code Flow
//!
//! Device Code Flow allows users to sign in on browserless or input-constrained
//! devices.  This is a two-stage process; first a user-code and verification
//! URL are obtained by using the `Client::exchange_client_credentials`
//! method. Those are displayed to the user, then are used in a second client
//! to poll the token endpoint for a token.
//!
//! ## Example
//!
//! ```rust,no_run
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     DeviceAuthorizationUrl,
//!     Scope,
//!     StandardDeviceAuthorizationResponse,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::reqwest::http_client;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let device_auth_url = DeviceAuthorizationUrl::new("http://deviceauth".to_string())?;
//! let client = BasicClient::new(ClientId::new("client_id".to_string()))
//!     .set_client_secret(ClientSecret::new("client_secret".to_string()))
//!     .set_auth_uri(AuthUrl::new("http://authorize".to_string())?)
//!     .set_token_uri(TokenUrl::new("http://token".to_string())?)
//!     .set_device_authorization_url(device_auth_url);
//!
//! let details: StandardDeviceAuthorizationResponse = client
//!     .exchange_device_code()
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client)?;
//!
//! println!(
//!     "Open this URL in your browser:\n{}\nand enter the code: {}",
//!     details.verification_uri().to_string(),
//!     details.user_code().secret().to_string()
//! );
//!
//! let token_result =
//!     client
//!     .exchange_device_access_token(&details)
//!     .request(http_client, std::thread::sleep, None)?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Google](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/google.rs) (includes token revocation)
//! - [Github](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/github.rs)
//! - [Microsoft Device Code Flow (async)](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/microsoft_devicecode.rs)
//! - [Microsoft Graph](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/msgraph.rs)
//! - [Wunderlist](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/wunderlist.rs)
//!
//! ## Contributed Examples
//!
//! - [`actix-web-oauth2`](https://github.com/pka/actix-web-oauth2) (version 2.x of this crate)
//!

/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
pub mod basic;

mod client;

mod code;

/// HTTP client backed by the [curl](https://crates.io/crates/curl) crate.
/// Requires "curl" feature.
#[cfg(all(feature = "curl", not(target_arch = "wasm32")))]
pub mod curl;

#[cfg(all(feature = "curl", target_arch = "wasm32"))]
compile_error!("wasm32 is not supported with the `curl` feature. Use the `reqwest` backend or a custom backend for wasm32 support");

/// Device Code Flow OAuth2 implementation
/// ([RFC 8628](https://tools.ietf.org/html/rfc8628)).
mod devicecode;

mod endpoint;

mod error;

/// Helper methods used by OAuth2 implementations/extensions.
pub mod helpers;

mod introspection;

/// HTTP client backed by the [reqwest](https://crates.io/crates/reqwest) crate.
/// Requires "reqwest" feature.
#[cfg(any(feature = "reqwest", feature = "reqwest-blocking"))]
pub mod reqwest;

/// OAuth 2.0 Token Revocation implementation
/// ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
mod revocation;

#[cfg(test)]
mod tests;

mod token;

mod types;

/// HTTP client backed by the [ureq](https://crates.io/crates/ureq) crate.
/// Requires "ureq" feature.
#[cfg(feature = "ureq")]
pub mod ureq;

pub use crate::client::Client;
pub use crate::code::AuthorizationRequest;
pub use crate::devicecode::{
    DeviceAccessTokenRequest, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
    DeviceCodeErrorResponse, DeviceCodeErrorResponseType, EmptyExtraDeviceAuthorizationFields,
    ExtraDeviceAuthorizationFields, StandardDeviceAuthorizationResponse,
};
pub use crate::endpoint::{HttpRequest, HttpResponse};
pub use crate::error::{
    ErrorResponse, ErrorResponseType, RequestTokenError, StandardErrorResponse,
};
pub use crate::introspection::{
    IntrospectionRequest, StandardTokenIntrospectionResponse, TokenIntrospectionResponse,
};
pub use crate::revocation::{
    RevocableToken, RevocationErrorResponseType, RevocationRequest, StandardRevocableToken,
};
pub use crate::token::{
    ClientCredentialsTokenRequest, CodeTokenRequest, EmptyExtraTokenFields, ExtraTokenFields,
    PasswordTokenRequest, RefreshTokenRequest, StandardTokenResponse, TokenResponse, TokenType,
};
pub use crate::types::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    DeviceAuthorizationUrl, DeviceCode, EndUserVerificationUrl, IntrospectionUrl,
    PkceCodeChallenge, PkceCodeChallengeMethod, PkceCodeVerifier, RedirectUrl, RefreshToken,
    ResourceOwnerPassword, ResourceOwnerUsername, ResponseType, RevocationUrl, Scope, TokenUrl,
    UserCode, VerificationUriComplete,
};

/// Public re-exports of types used for HTTP client interfaces.
pub use http;
pub use url;

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

/// There was a problem configuring the request.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    /// The endpoint URL to be contacted MUST be HTTPS.
    #[error("Scheme for {0} endpoint URL must be HTTPS")]
    InsecureUrl(&'static str),
}

/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *BasicAuth*, following the recommendation of
/// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AuthType {
    /// The client_id and client_secret (if set) will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}
