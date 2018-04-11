#![warn(missing_docs)]
//!
//! A simple implementation of the OAuth2 flow, trying to adhere as much as possible to
//! [RFC 6749](https://tools.ietf.org/html/rfc6749).
//!
//! # Getting started: Authorization Code Grant
//!
//! This is the most common OAuth2 flow.
//!
//! ## Example
//!
//! ```
//! extern crate base64;
//! extern crate oauth2;
//! extern crate rand;
//! extern crate url;
//!
//! use oauth2::prelude::*;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     RedirectUrl,
//!     Scope,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), Box<std::error::Error>> {
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new(Url::parse("http://authorize")?),
//!         TokenUrl::new(Url::parse("http://token")?)
//!     )
//!         // Set the desired scopes.
//!         .add_scope(Scope::new("read".to_string()))
//!         .add_scope(Scope::new("write".to_string()))
//!
//!         // Set the URL the user will be redirected to after the authorization process.
//!         .set_redirect_url(RedirectUrl::new(Url::parse("http://redirect")?));
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random);
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
//!     client.exchange_code(AuthorizationCode::new("some authorization code".to_string()));
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//! # Ok(())
//! # }
//! # fn main() {}
//! ```
//!
//! # Implicit Grant
//!
//! This flow fetches an access token directly from the authorization endpoint. Be sure to
//! understand the security implications of this flow before using it. In most cases, the
//! Authorization Code Grant flow is preferable to the Implicit Grant flow.
//!
//! ## Example: 
//!
//! ```
//! extern crate base64;
//! extern crate oauth2;
//! extern crate rand;
//! extern crate url;
//!
//! use oauth2::prelude::*;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     RedirectUrl,
//!     Scope,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), Box<std::error::Error>> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new(Url::parse("http://authorize")?),
//!         TokenUrl::new(Url::parse("http://token")?)
//!     );
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client.authorize_url_implicit(CsrfToken::new_random);
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
//! # fn main() {}
//! ```
//!
//! # Resource Owner Password Credentials Grant
//!
//! You can ask for a *password* access token by calling the `Client::exchange_password` method,
//! while including the username and password.
//!
//! ## Example
//!
//! ```
//! extern crate base64;
//! extern crate oauth2;
//! extern crate rand;
//! extern crate url;
//!
//! use oauth2::prelude::*;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     ResourceOwnerPassword,
//!     ResourceOwnerUsername,
//!     Scope,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), Box<std::error::Error>> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new(Url::parse("http://authorize")?),
//!         TokenUrl::new(Url::parse("http://token")?)
//!     )
//!         .add_scope(Scope::new("read".to_string()));
//!
//! let token_result =
//!     client.exchange_password(
//!         &ResourceOwnerUsername::new("user".to_string()),
//!         &ResourceOwnerPassword::new("pass".to_string())
//!     );
//! # Ok(())
//! # }
//! # fn main() {}
//! ```
//!
//! # Client Credentials Grant
//!
//! You can ask for a *client credentials* access token by calling the
//! `Client::exchange_client_credentials` method.
//!
//! ## Example: 
//!
//! ```
//! extern crate oauth2;
//! extern crate url;
//!
//! use oauth2::prelude::*;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     Scope,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use url::Url;
//!
//! # fn err_wrapper() -> Result<(), Box<std::error::Error>> {
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new(Url::parse("http://authorize")?),
//!         TokenUrl::new(Url::parse("http://token")?)
//!     )
//!         .add_scope(Scope::new("read".to_string()));
//!
//! let token_result = client.exchange_client_credentials();
//! # Ok(())
//! # }
//! # fn main() {}
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Google](https://github.com/alexcrichton/oauth2-rs/blob/master/examples/google.rs)
//! - [Github](https://github.com/alexcrichton/oauth2-rs/blob/master/examples/github.rs)
//!

extern crate base64;
extern crate curl;
extern crate failure;
#[macro_use] extern crate failure_derive;
extern crate rand;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate url;

use std::io::Read;
use std::fmt::{Debug, Display, Formatter};
use std::fmt::Error as FormatterError;
use std::marker::PhantomData;
use std::ops::Deref;
use std::time::Duration;

use curl::easy::Easy;
use rand::{thread_rng, Rng};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use prelude::*;

const CONTENT_TYPE_JSON: &str = "application/json";

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
/// Crate prelude that should be wildcard-imported by crate users.
///
pub mod prelude {
    use std::fmt::Debug;
    use std::ops::Deref;

    ///
    /// New type to wrap a more primitive type in a more typesafe manner.
    ///
    pub trait NewType<T> : Clone + Debug + Deref + PartialEq {
        ///
        /// Create a new instance to wrap the given `val`.
        ///
        fn new(val: T) -> Self;
    }

    ///
    /// New type representing a secret value to wrap a more primitive type in a more typesafe
    /// manner.
    ///
    pub trait SecretNewType<T> : Debug {
        ///
        /// Create a new instance to wrap the given `val`.
        ///
        fn new(val: T) -> Self where Self: Sized;
        ///
        /// Get the secret contained within this type.
        ///
        /// # Security Warning
        ///
        /// Leaking this value may compromise the security of the OAuth2 flow.
        ///
        fn secret(&self) -> &T;
    }
}

#[macro_export] macro_rules! new_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
        impl {
            $($item:tt)*
        }
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type $(#[$attr:meta])*,
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        ),
        $new_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(
            $(#[$type_attr])*
            $type
        );
        impl $name {
            $($item)*
        }
        impl NewType<$type> for $name {
            #[doc = $new_doc]
            fn new(s: $type) -> Self {
                $name(s)
            }
        }
        impl Deref for $name {
            type Target = $type;
            fn deref(&self) -> &$type {
                &self.0
            }
        }
    }
}

#[macro_export] macro_rules! new_secret_type {
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
    ) => {
        new_secret_type![
            $(#[$attr])*
            $name($type)
            impl {}
        ];
    };
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
        impl {
            $($item:tt)*
        }
    ) => {
        new_secret_type![
            $(#[$attr])*,
            $name($type),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            concat!("Get the secret contained within this `", stringify!($name), "`."),
            impl {
                $($item)*
            }
        ];
    };
    (
        $(#[$attr:meta])*,
        $name:ident($type:ty),
        $new_doc:expr,
        $secret_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(
            #[$attr]
        )*
        #[derive(Clone, PartialEq)]
        pub struct $name($type);
        impl $name {
            $($item)*
        }
        impl SecretNewType<$type> for $name {
            #[doc = $new_doc]
            fn new(s: $type) -> Self {
                $name(s)
            }
            ///
            #[doc = $secret_doc]
            ///
            /// # Security Warning
            ///
            /// Leaking this value may compromise the security of the OAuth2 flow.
            ///
            fn secret(&self) -> &$type { &self.0 }
        }
        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
                write!(f, concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

new_type![
    ///
    /// Client identifier issued to the client during the registration process described by
    /// [Section 2.2](https://tools.ietf.org/html/rfc6749#section-2.2).
    ///
    #[derive(Deserialize, Serialize)]
    ClientId(String)
];

new_type![
    #[derive(Deserialize, Serialize)]
    ///
    /// URL of the authorization server's authorization endpoint.
    ///
    AuthUrl(
        #[serde(
            deserialize_with = "helpers::deserialize_url",
            serialize_with = "helpers::serialize_url"
        )]
        Url
    )
];
new_type![
    #[derive(Deserialize, Serialize)]
    ///
    /// URL of the authorization server's token endpoint.
    ///
    TokenUrl(
        #[serde(
            deserialize_with = "helpers::deserialize_url",
            serialize_with = "helpers::serialize_url"
        )]
        Url
    )
];
new_type![
    #[derive(Deserialize, Serialize)]
    ///
    /// URL of the client's redirection endpoint.
    ///
    RedirectUrl(
        #[serde(
            deserialize_with = "helpers::deserialize_url",
            serialize_with = "helpers::serialize_url"
        )]
        Url
    )
];
new_type![
    ///
    /// Authorization endpoint response (grant) type defined in
    /// [Section 3.1.1](https://tools.ietf.org/html/rfc6749#section-3.1.1).
    ///
    #[derive(Deserialize, Serialize)]
    ResponseType(String)
];
new_type![
    ///
    /// Resource owner's username used directly as an authorization grant to obtain an access
    /// token.
    ///
    ResourceOwnerUsername(String)
];

new_type![
    ///
    /// Access token scope, as defined by the authorization server.
    ///
    #[derive(Deserialize, Serialize)]
    Scope(String)
];
impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str { self }
}

new_secret_type![
    ///
    /// Client password issued to the client during the registration process described by
    /// [Section 2.2](https://tools.ietf.org/html/rfc6749#section-2.2).
    ///
    ClientSecret(String)
];
new_secret_type![
    ///
    /// Value used for [CSRF]((https://tools.ietf.org/html/rfc6749#section-10.12)) protection
    /// via the `state` parameter.
    ///
    #[must_use]
    CsrfToken(String)
    impl {
        ///
        /// Generate a new random, base64-encoded 128-bit CSRF token.
        ///
        pub fn new_random() -> Self {
            CsrfToken::new_random_len(16)
        }
        ///
        /// Generate a new random, base64-encoded CSRF token of the specified length.
        ///
        /// # Arguments
        ///
        /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
        ///
        pub fn new_random_len(num_bytes: u32) -> Self {
            let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
            CsrfToken::new(base64::encode(&random_bytes))
        }
    }
];
new_secret_type![
    ///
    /// Authorization code returned from the authorization endpoint.
    ///
    AuthorizationCode(String)
];
new_secret_type![
    ///
    /// Refresh token used to obtain a new access token (if supported by the authorization server).
    ///
    #[derive(Deserialize, Serialize)]
    RefreshToken(String)
];
new_secret_type![
    ///
    /// Access token returned by the token endpoint and used to access protected resources.
    ///
    #[derive(Deserialize, Serialize)]
    AccessToken(String)
];
new_secret_type![
    ///
    /// Resource owner's password used directly as an authorization grant to obtain an access
    /// token.
    ///
    ResourceOwnerPassword(String)
];


///
/// Stores the configuration for an OAuth2 client.
///
#[derive(Clone, Debug)]
pub struct Client<TT: TokenType, T: Token<TT>, TE: ErrorResponseType> {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_url: AuthUrl,
    auth_type: AuthType,
    token_url: TokenUrl,
    scopes: Vec<Scope>,
    redirect_url: Option<RedirectUrl>,
    phantom_tt: PhantomData<TT>,
    phantom_t: PhantomData<T>,
    phantom_te: PhantomData<TE>,
}

impl<TT: TokenType, T: Token<TT>, TE: ErrorResponseType> Client<TT, T, TE> {
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
    ///   [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2).
    ///
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: TokenUrl
    ) -> Self {
        Client {
            client_id,
            client_secret,
            auth_url,
            auth_type: AuthType::BasicAuth,
            token_url,
            scopes: Vec::new(),
            redirect_url: None,
            phantom_tt: PhantomData,
            phantom_t: PhantomData,
            phantom_te: PhantomData,
        }
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(scope);

        self
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
    /// Produces the full authorization URL used by the
    /// [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1) flow, which
    /// is the most common OAuth2 flow.
    ///
    /// # Arguments
    ///
    /// * `state` - An opaque value used by the client to maintain state between the request and
    ///   callback. The authorization server includes this value when redirecting the user-agent
    ///   back to the client.
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
    pub fn authorize_url<F>(&self, state_fn: F) -> (Url, CsrfToken)
    where F: Fn() -> CsrfToken {
        let state = state_fn();
        (self.authorize_url_impl("code", Some(&state), None), state)
    }

    ///
    /// Produces the full authorization URL used by the
    /// [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2) flow.
    ///
    /// # Arguments
    ///
    /// * `state` - An opaque value used by the client to maintain state between the request and
    ///   callback. The authorization server includes this value when redirecting the user-agent
    ///   back to the client.
    ///
    /// # Security Warning
    ///
    /// Callers should use a fresh, unpredictable `state` for each authorization request and verify
    /// that this value matches the `state` parameter passed by the authorization server to the
    /// redirect URI. Doing so mitigates
    /// [Cross-Site Request Forgery](https://tools.ietf.org/html/rfc6749#section-10.12)
    ///  attacks. To disable CSRF protections (NOT recommended), use
    /// `insecure::authorize_url_implicit` instead.
    ///
    pub fn authorize_url_implicit<F>(&self, state_fn: F) -> (Url, CsrfToken)
    where F: Fn() -> CsrfToken {
        let state = state_fn();
        (self.authorize_url_impl("token", Some(&state), None), state)
    }

    ///
    /// Produces the full authorization URL used by an OAuth2
    /// [extension](https://tools.ietf.org/html/rfc6749#section-8.4).
    ///
    /// # Arguments
    ///
    /// * `response_type` - The response type this client expects from the authorization endpoint.
    ///   For `"code"` or `"token"` response types, instead use the `authorize_url` or
    ///   `authorize_url_implicit` functions, respectively.
    /// * `extra_params` - Additional parameters as required by the applicable OAuth2 extension(s).
    ///   Callers should NOT specify any of the following parameters: `response_type`, `client_id`,
    ///   `redirect_uri`, or `scope`.
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    pub fn authorize_url_extension(
        &self,
        response_type: &ResponseType,
        extra_params: &[(&str, &str)]
    ) -> Url {
        self.authorize_url_impl(response_type, None, Some(extra_params))
    }

    fn authorize_url_impl(
        &self,
        response_type: &str,
        state_opt: Option<&CsrfToken>,
        extra_params_opt: Option<&[(&str, &str)]>
    ) -> Url {
        let scopes = self.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(" ");

        let mut pairs: Vec<(&str, &str) > = vec![
            ("response_type", response_type),
            ("client_id", &self.client_id),
        ];

        if let Some(ref redirect_url) = self.redirect_url {
            pairs.push(("redirect_uri", redirect_url.as_str()));
        }

        if !scopes.is_empty() {
            pairs.push(("scope", &scopes));
        }

        if let Some(state) = state_opt {
            pairs.push(("state", state.secret()));
        }

        let mut url: Url = (*self.auth_url).clone();

        url.query_pairs_mut().extend_pairs(
            pairs.iter().map(|&(k, v)| { (k, &v[..]) })
        );

        if let Some(extra_params) = extra_params_opt {
            url.query_pairs_mut().extend_pairs(
                extra_params.iter().cloned()
            );
        }

        url
    }

    ///
    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// Acquires ownership of the `code` because authorization codes may only be used to retrieve
    /// an access token from the authorization server.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.1.3
    ///
    pub fn exchange_code(&self, code: AuthorizationCode) -> Result<T, RequestTokenError<TE>> {
        // Make Clippy happy since we're intentionally taking ownership.
        let code_owned = code;
        let params = vec![
            ("grant_type", "authorization_code"),
            ("code", code_owned.secret())
        ];

        self.request_token(params)
    }

    ///
    /// Requests an access token for the *password* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.3.2
    ///
    pub fn exchange_password(
        &self,
        username: &ResourceOwnerUsername,
        password: &ResourceOwnerPassword
    ) -> Result<T, RequestTokenError<TE>> {
        let params = vec![
            ("grant_type", "password"),
            ("username", username),
            ("password", password.secret()),
        ];

        self.request_token(params)
    }

    ///
    /// Requests an access token for the *client credentials* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.4.2
    ///
    pub fn exchange_client_credentials(&self) -> Result<T, RequestTokenError<TE>> {
        // Generate the space-delimited scopes String before initializing params so that it has
        // a long enough lifetime.
        let scopes_opt =
            if !self.scopes.is_empty() {
                Some(self.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(" "))
            } else {
                None
            };

        let mut params: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];

        if let Some(ref scopes) = scopes_opt {
            params.push(("scope", scopes));
        }
        self.request_token(params)
    }

    ///
    /// Exchanges a refresh token for an access token
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-6
    ///
    pub fn exchange_refresh_token(
        &self, refresh_token: &RefreshToken
    ) -> Result<T, RequestTokenError<TE>> {
        let params: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.secret()),
        ];

        self.request_token(params)
    }

    fn post_request_token<'a, 'b: 'a>(
        &'b self,
        mut params: Vec<(&'b str, &'a str)>
    ) -> Result<RequestTokenResponse, curl::Error> {
        let mut easy = Easy::new();

        match self.auth_type {
            AuthType::RequestBody => {
                params.push(("client_id", &self.client_id));
                if let Some(ref client_secret) = self.client_secret {
                    params.push(("client_secret", client_secret.secret()));
                }
            }
            AuthType::BasicAuth => {
                easy.username(&self.client_id)?;
                if let Some(ref client_secret) = self.client_secret {
                    easy.password(client_secret.secret())?;
                }
            }
        }

        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.as_str()));
        }

        let form =
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish()
                .into_bytes();
        let mut form_slice = &form[..];

        easy.url(&self.token_url.to_string()[..])?;

        // Section 5.1 of RFC 6749 (https://tools.ietf.org/html/rfc6749#section-5.1) only permits
        // JSON responses for this request. Some providers such as GitHub have off-spec behavior
        // and not only support different response formats, but have non-JSON defaults. Explicitly
        // request JSON here.
        let mut headers = curl::easy::List::new();
        let accept_header = format!("Accept: {}", CONTENT_TYPE_JSON);
        headers.append(&accept_header)?;
        easy.http_headers(headers)?;

        easy.post(true)?;
        easy.post_field_size(form.len() as u64)?;

        let mut data = Vec::new();
        {
            let mut transfer = easy.transfer();

            transfer.read_function(|buf| {
                Ok(form_slice.read(buf).unwrap_or(0))
            })?;

            transfer.write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })?;

            transfer.perform()?;
        }

        let http_status = easy.response_code()?;
        let content_type = easy.content_type()?;

        Ok(RequestTokenResponse{
            http_status,
            content_type: content_type.map(|s| s.to_string()),
            response_body: data,
        })
    }

    fn request_token(&self, params: Vec<(&str, &str)>) -> Result<T, RequestTokenError<TE>> {
        let token_response = self.post_request_token(params).map_err(RequestTokenError::Request)?;
        if token_response.http_status != 200 {
            let reason = String::from_utf8_lossy(token_response.response_body.as_slice());
            if reason.is_empty() {
                return Err(
                    RequestTokenError::Other("Server returned empty error response".to_string())
                );
            } else {
                let error = match serde_json::from_str::<ErrorResponse<TE>>(&reason) {
                    Ok(error) => RequestTokenError::ServerResponse(error),
                    Err(error) => RequestTokenError::Parse(error),
                };
                return Err(error);
            }
        }

        // Validate that the response Content-Type is JSON.
        token_response
            .content_type
            .map_or(Ok(()), |content_type|
                // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
                // may be followed by optional whitespace and/or a parameter (e.g., charset).
                // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
                if !content_type.to_lowercase().starts_with(CONTENT_TYPE_JSON) {
                    Err(
                        RequestTokenError::Other(
                            format!(
                                "Unexpected response Content-Type: `{}`, should be `{}`",
                                content_type,
                                CONTENT_TYPE_JSON
                            )
                        )
                    )
                } else {
                    Ok(())
                }
            )?;

        if token_response.response_body.is_empty() {
            Err(RequestTokenError::Other("Server returned empty response body".to_string()))
        } else {
            let response_body =
                String::from_utf8(token_response.response_body)
                    .map_err(|parse_error|
                        RequestTokenError::Other(
                            format!("Couldn't parse response as UTF-8: {}", parse_error)
                        )
                    )?;

            T::from_json(&response_body).map_err(RequestTokenError::Parse)
        }
    }
}

///
/// Private struct returned by `post_request_token`.
///
struct RequestTokenResponse {
    http_status: u32,
    content_type: Option<String>,
    response_body: Vec<u8>,
}

///
/// Trait for OAuth2 access tokens.
///
pub trait TokenType : DeserializeOwned + Debug + PartialEq + Serialize {}

///
/// Common methods shared by all OAuth2 token implementations.
///
/// The getters in this trait are defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1). This trait is
/// parameterized by a `TokenType` to support future OAuth2 authentication schemes.
///
pub trait Token<T: TokenType> : Debug + DeserializeOwned + PartialEq + Serialize {
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken;
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &T;
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

    ///
    /// Factory method to deserialize a `Token` from a JSON response.
    ///
    /// # Failures
    /// If parsing fails, returns a `serde_json::error::Error` describing the parse error.
    fn from_json(data: &str) -> Result<Self, serde_json::error::Error>;
}


///
/// Error types enum.
///
/// NOTE: The implementation of the `Display` trait must return the `snake_case` representation of
/// this error type. This value must match the error type from the relevant OAuth 2.0 standards
/// (RFC 6749 or an extension).
///
pub trait ErrorResponseType : Debug + DeserializeOwned + Display + PartialEq + Serialize {}

///
/// Error response returned by server after requesting an access token.
///
/// The fields in this structure are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2). This
/// trait is parameterized by a `ErrorResponseType` to support error types specific to future OAuth2
/// authentication schemes and extensions.
///
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct ErrorResponse<T: ErrorResponseType> {
    #[serde(rename = "error")]
    #[serde(bound(deserialize = "T: ErrorResponseType"))]
    _error: T,
    #[serde(rename = "error_description")]
    #[serde(default)]
    _error_description: Option<String>,
    #[serde(rename = "error_uri")]
    #[serde(default)]
    _error_uri: Option<String>,
}

impl<T: ErrorResponseType> ErrorResponse<T> {
    ///
    /// REQUIRED. A single ASCII error code deserialized to the generic parameter
    /// `ErrorResponseType`.
    ///
    pub fn error(&self) -> &T { &self._error }
    ///
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred.
    ///
    pub fn error_description(&self) -> Option<&String> { self._error_description.as_ref() }
    ///
    /// OPTIONAL. A URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    ///
    pub fn error_uri(&self) -> Option<&String> { self._error_uri.as_ref() }
}

impl<TE: ErrorResponseType> Display for ErrorResponse<TE> {
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
#[derive(Debug, Fail)]
pub enum RequestTokenError<T: ErrorResponseType> {
    ///
    /// Error response returned by authorization server. Contains the parsed `ErrorResponse`
    /// returned by the server.
    ///
    #[fail(display = "Server response: {}", _0)]
    ServerResponse(ErrorResponse<T>),
    ///
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity failed).
    ///
    #[fail(display = "Request error: {}", _0)]
    Request(#[cause] curl::Error),
    ///
    /// Failed to parse server response. Parse errors may occur while parsing either successful
    /// or error responses.
    ///
    #[fail(display = "Parse error: {}", _0)]
    Parse(#[cause] serde_json::error::Error),
    ///
    /// Some other type of error occurred (e.g., an unexpected server response).
    ///
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

///
/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
/// 
pub mod basic {
    extern crate serde_json;

    use std::fmt::Error as FormatterError;
    use std::fmt::{Debug, Display, Formatter};
    use std::time::Duration;

    use serde::de::DeserializeOwned;

    use super::{
        AccessToken,
        Client,
        ErrorResponse,
        ErrorResponseType,
        RefreshToken,
        RequestTokenError,
        Scope,
        Token,
        TokenType,
    };
    use super::helpers;

    ///
    /// Basic OAuth2 client specialization, suitable for most applications.
    ///
    pub type BasicClient =
        Client<BasicTokenType, BasicToken<BasicTokenType>, BasicErrorResponseType>;

    ///
    /// Basic OAuth2 authorization token types.
    ///
    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum BasicTokenType {
        ///
        /// Bearer token
        /// ([OAuth 2.0 Bearer Tokens - RFC 6750](https://tools.ietf.org/html/rfc6750)).
        ///
        Bearer,
        ///
        /// MAC ([OAuth 2.0 Message Authentication Code (MAC)
        /// Tokens](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05)).
        ///
        Mac,
    }
    impl TokenType for BasicTokenType {}

    ///
    /// Basic OAuth2 authorization token.
    ///
    /// The fields in this struct are defined in
    /// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1). The fields
    /// are private and should be accessed via the getters from the `super::Token` trait.
    ///
    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    pub struct BasicToken<T: TokenType = BasicTokenType> {
        #[serde(rename = "access_token")]
        _access_token: AccessToken,
        #[serde(bound(deserialize = "T: DeserializeOwned"))]
        #[serde(rename = "token_type")]
        #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
        _token_type: T,
        #[serde(rename = "expires_in")]
        _expires_in: Option<u64>,
        #[serde(rename = "refresh_token")]
        _refresh_token: Option<RefreshToken>,
        #[serde(rename = "scope")]
        #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
        #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
        #[serde(default)]
        _scopes: Option<Vec<Scope>>,
    }

    impl<T: TokenType> Token<T> for BasicToken<T> {
        fn access_token(&self) -> &AccessToken { &self._access_token }
        fn token_type(&self) -> &T { &self._token_type }
        fn expires_in(&self) -> Option<Duration> { self._expires_in.map(Duration::from_secs) }
        fn refresh_token(&self) -> Option<&RefreshToken> { self._refresh_token.as_ref() }
        fn scopes(&self) -> Option<&Vec<Scope>> { self._scopes.as_ref() }

        fn from_json(data: &str) -> Result<Self, serde_json::error::Error> {
            serde_json::from_str(data)
        }
    }

    ///
    /// Basic access token error types.
    ///
    /// These error types are defined in
    /// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2).
    ///
    #[derive(Deserialize, PartialEq, Serialize)]
    #[serde(rename_all="snake_case")]
    pub enum BasicErrorResponseType {
        ///
        /// The request is missing a required parameter, includes an unsupported parameter value
        /// (other than grant type), repeats a parameter, includes multiple credentials, utilizes
        /// more than one mechanism for authenticating the client, or is otherwise malformed.
        ///
        InvalidRequest,
        ///
        /// Client authentication failed (e.g., unknown client, no client authentication included,
        /// or unsupported authentication method).
        ///
        InvalidClient,
        ///
        /// The provided authorization grant (e.g., authorization code, resource owner credentials)
        /// or refresh token is invalid, expired, revoked, does not match the redirection URI used
        /// in the authorization request, or was issued to another client.
        ///
        InvalidGrant,
        ///
        /// The authenticated client is not authorized to use this authorization grant type.
        ///
        UnauthorizedClient,
        ///
        /// The authorization grant type is not supported by the authorization server.
        ///
        UnsupportedGrantType,
        ///
        /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
        /// resource owner.
        ///
        InvalidScope,
    }

    impl ErrorResponseType for BasicErrorResponseType {}

    impl Debug for BasicErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            Display::fmt(self, f)
        }
    }

    impl Display for BasicErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            write!(f, "{}", helpers::variant_name(&self))
        }
    }

    ///
    /// Error response specialization for basic OAuth2 implementation.
    ///
    pub type BasicErrorResponse = ErrorResponse<BasicErrorResponseType>;

    ///
    /// Token error specialization for basic OAuth2 implementation.
    ///
    pub type BasicRequestTokenError = RequestTokenError<BasicErrorResponseType>;
}

///
/// Insecure methods -- not recommended for most applications.
///
pub mod insecure {
    use url::Url;

    use super::{
        Client,
        ErrorResponseType,
        Token,
        TokenType,
    };

    ///
    /// Produces the full authorization URL used by the
    /// [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1) flow, which
    /// is the most common OAuth2 flow.
    ///
    /// # Security Warning
    ///
    /// The URL produced by this function is vulnerable to
    /// [Cross-Site Request Forgery](https://tools.ietf.org/html/rfc6749#section-10.12) attacks.
    /// It is highly recommended to use the `Client::authorize_url` function instead.
    ///
    pub fn authorize_url<TT, T, TE>(client: &Client<TT, T, TE>) -> Url
    where TT: TokenType, T: Token<TT>, TE: ErrorResponseType {
        client.authorize_url_impl("code", None, None)
    }

    ///
    /// Produces the full authorization URL used by the
    /// [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2) flow.
    ///
    /// # Security Warning
    ///
    /// The URL produced by this function is vulnerable to
    /// [Cross-Site Request Forgery](https://tools.ietf.org/html/rfc6749#section-10.12) attacks.
    /// It is highly recommended to use the `Client::authorize_url_implicit` function instead.
    ///
    pub fn authorize_url_implicit<TT, T, TE>(client: &Client<TT, T, TE>) -> Url
    where TT: TokenType, T: Token<TT>, TE: ErrorResponseType {
        client.authorize_url_impl("token", None, None)
    }
}

///
/// Helper methods used by OAuth2 implementations/extensions.
///
pub mod helpers {
    use std;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::ser;
    use serde::ser::{Impossible, SerializeStructVariant, SerializeTupleVariant};
    use url::Url;

    ///
    /// Serde case-insensitive deserializer for an untagged `enum`.
    ///
    /// This function converts values to lowercase before deserializing as the `enum`. Requires the
    /// `#[serde(rename_all = "lowercase")]` attribute to be set on the `enum`.
    ///
    /// # Example
    ///
    /// In example below, the following JSON values all deserialize to
    /// `GroceryBasket { fruit_item: Fruit::Banana }`:
    ///
    ///  * `{"fruit_item": "banana"}`
    ///  * `{"fruit_item": "BANANA"}`
    ///  * `{"fruit_item": "Banana"}`
    ///
    /// Note: this example does not compile automatically due to
    /// [Rust issue #29286](https://github.com/rust-lang/rust/issues/29286).
    ///
    /// ```
    /// # /*
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// #[serde(rename_all = "lowercase")]
    /// enum Fruit {
    ///     Apple,
    ///     Banana,
    ///     Orange,
    /// }
    ///
    /// #[derive(Deserialize)]
    /// struct GroceryBasket {
    ///     #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
    ///     fruit_item: Fruit,
    /// }
    /// # */
    /// ```
    ///
    pub fn deserialize_untagged_enum_case_insensitive<'de, T, D>(
        deserializer: D
    ) -> Result<T, D::Error>
    where T: Deserialize<'de>, D: Deserializer<'de> {
        use serde::de::Error;
        use serde_json::Value;
        T::deserialize(Value::String(String::deserialize(deserializer)?.to_lowercase()))
            .map_err(Error::custom)
    }

    ///
    /// Serde space-delimited string deserializer for a `Vec<String>`.
    ///
    /// This function splits a JSON string at each space character into a `Vec<String>` .
    ///
    /// # Example
    ///
    /// In example below, the JSON value `{"items": "foo bar baz"}` would deserialize to:
    ///
    /// ```
    /// # struct GroceryBasket {
    /// #     items: Vec<String>,
    /// # }
    /// # fn main() {
    /// GroceryBasket {
    ///     items: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
    /// };
    /// # }
    /// ```
    ///
    /// Note: this example does not compile automatically due to
    /// [Rust issue #29286](https://github.com/rust-lang/rust/issues/29286).
    ///
    /// ```
    /// # /*
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct GroceryBasket {
    ///     #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    ///     items: Vec<String>,
    /// }
    /// # */
    /// ```
    ///
    pub fn deserialize_space_delimited_vec<'de, T, D>(
        deserializer: D
    ) -> Result<T, D::Error>
    where T: Default + Deserialize<'de>, D: Deserializer<'de> {
        use serde::de::Error;
        use serde_json::Value;
        if let Some(space_delimited) = Option::<String>::deserialize(deserializer)? {
            let entries =
                space_delimited
                    .split(' ')
                    .map(|s| Value::String(s.to_string()))
                    .collect();
            T::deserialize(Value::Array(entries))
                .map_err(Error::custom)
        } else {
            // If the JSON value is null, use the default value.
            Ok(T::default())
        }
    }

    ///
    /// Serde space-delimited string serializer for an `Option<Vec<String>>`.
    ///
    /// This function serializes a string vector into a single space-delimited string.
    /// If `string_vec_opt` is `None`, the function serializes it as `None` (e.g., `null`
    /// in the case of JSON serialization).
    ///
    pub fn serialize_space_delimited_vec<T, S>(
        vec_opt: &Option<Vec<T>>,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where T: AsRef<str>, S: Serializer {
        if let Some(ref vec) = *vec_opt {
            let space_delimited = vec.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(" ");

            serializer.serialize_str(&space_delimited)
        } else {
            serializer.serialize_none()
        }
    }

    ///
    /// Serde string deserializer for a `Url`.
    ///
    pub fn deserialize_url<'de, D>(
        deserializer: D
    ) -> Result<Url, D::Error>
    where D: Deserializer<'de> {
        use serde::de::Error;
        let url_str = String::deserialize(deserializer)?;
        Url::parse(url_str.as_ref()).map_err(Error::custom)
    }

    ///
    /// Serde string serializer for a `Url`.
    ///
    pub fn serialize_url<S>(
        url: &Url,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(url.as_str())
    }

    ///
    /// Serde string serializer for an enum.
    ///
    /// Source:
    /// [https://github.com/serde-rs/serde/issues/553](https://github.com/serde-rs/serde/issues/553)
    ///
    pub fn variant_name<T: Serialize>(t: &T) -> &'static str {
        #[derive(Debug)]
        struct NotEnum;
        type Result<T> = std::result::Result<T, NotEnum>;
        impl std::error::Error for NotEnum {
            fn description(&self) -> &str { "not struct" }
        }
        impl std::fmt::Display for NotEnum {
            fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result { unimplemented!() }
        }
        impl ser::Error for NotEnum {
            fn custom<T: std::fmt::Display>(_msg: T) -> Self { NotEnum }
        }

        struct VariantName;
        impl Serializer for VariantName {
            type Ok = &'static str;
            type Error = NotEnum;
            type SerializeSeq = Impossible<Self::Ok, Self::Error>;
            type SerializeTuple = Impossible<Self::Ok, Self::Error>;
            type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
            type SerializeTupleVariant = Enum;
            type SerializeMap = Impossible<Self::Ok, Self::Error>;
            type SerializeStruct = Impossible<Self::Ok, Self::Error>;
            type SerializeStructVariant = Enum;
            fn serialize_bool(self, _v: bool) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_i8(self, _v: i8) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_i16(self, _v: i16) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_i32(self, _v: i32) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_i64(self, _v: i64) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_u8(self, _v: u8) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_u16(self, _v: u16) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_u32(self, _v: u32) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_u64(self, _v: u64) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_f32(self, _v: f32) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_f64(self, _v: f64) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_char(self, _v: char) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_str(self, _v: &str) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_none(self) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok> {
                Err(NotEnum)
            }
            fn serialize_unit(self) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> { Err(NotEnum) }
            fn serialize_unit_variant(
                self,
                _name: &'static str,
                _variant_index: u32,
                variant: &'static str
            ) -> Result<Self::Ok> {
                Ok(variant)
            }
            fn serialize_newtype_struct<T: ?Sized + Serialize>(
                self,
                _name: &'static str,
                _value: &T
            ) -> Result<Self::Ok> {
                Err(NotEnum)
            }
            fn serialize_newtype_variant<T: ?Sized + Serialize>(
                self,
                _name: &'static str,
                _variant_index: u32,
                variant: &'static str,
                _value: &T
            ) -> Result<Self::Ok> {
                Ok(variant)
            }
            fn serialize_seq(
                self,
                _len: Option<usize>
            ) -> Result<Self::SerializeSeq> {
                Err(NotEnum)
            }
            fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> { Err(NotEnum) }
            fn serialize_tuple_struct(
                self,
                _name: &'static str,
                _len: usize
            ) -> Result<Self::SerializeTupleStruct> {
                Err(NotEnum)
            }
            fn serialize_tuple_variant(
                self,
                _name: &'static str,
                _variant_index: u32,
                variant: &'static str,
                _len: usize
            ) -> Result<Self::SerializeTupleVariant> {
                Ok(Enum(variant))
            }
            fn serialize_map(
                self,
                _len: Option<usize>
            ) -> Result<Self::SerializeMap> {
                Err(NotEnum)
            }
            fn serialize_struct(
                self,
                _name: &'static str,
                _len: usize
            ) -> Result<Self::SerializeStruct> {
                Err(NotEnum)
            }
            fn serialize_struct_variant(
                self,
                _name: &'static str,
                _variant_index: u32,
                variant: &'static str,
                _len: usize
            ) -> Result<Self::SerializeStructVariant> {
                Ok(Enum(variant))
            }
        }

        struct Enum(&'static str);
        impl SerializeStructVariant for Enum {
            type Ok = &'static str;
            type Error = NotEnum;
            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                _key: &'static str,
                _value: &T
            ) -> Result<()> {
                Ok(())
            }
            fn end(self) -> Result<Self::Ok> {
                Ok(self.0)
            }
        }
        impl SerializeTupleVariant for Enum {
            type Ok = &'static str;
            type Error = NotEnum;
            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                _value: &T
            ) -> Result<()> {
                Ok(())
            }
            fn end(self) -> Result<Self::Ok> {
                Ok(self.0)
            }
        }

        t.serialize(VariantName).unwrap()
    }
}
