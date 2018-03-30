#![warn(missing_docs)]
//!
//! A simple implementation of the OAuth2 flow, trying to adhere as much as possible to the [RFC](https://tools.ietf.org/html/rfc6749).
//!
//! # Getting started
//!
//! ## Example
//!
//! ```
//! use oauth2::Config;
//!
//! // Create an OAuth2 config by specifying the client ID, client secret, authorization URL and token URL.
//! let mut config = Config::new("client_id", "client_secret", "http://authorize", "http://token");
//!
//! // Set the desired scopes.
//! config = config.add_scope("read");
//! config = config.add_scope("write");
//!
//! // Set the URL the user will be redirected to after the authorization process.
//! config = config.set_redirect_url("http://redirect");
//!
//! // Set a state parameter (optional, but recommended).
//! // Please upgrade to 2.0, this is deprecated because it reuses the same state for every request
//! #[allow(deprecated)]
//! let config = config.set_state("1234");
//!
//! // Generate the full authorization URL.
//! // This is the URL you should redirect the user to, in order to trigger the authorization process.
//! println!("Browse to: {}", config.authorize_url());
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the authorization code.
//! // Now you can trade it for an access token.
//! let token_result = config.exchange_code("some authorization code");
//!
//! // Unwrapping token_result will either produce a Token or a TokenError.
//! ```
//!
//! # The client credentials grant type
//!
//! You can ask for a *client credentials* access token by calling the `Config::exchange_client_credentials` method.
//!
//! ## Example
//!
//! ```
//! use oauth2::Config;
//!
//! let mut config = Config::new("client_id", "client_secret", "http://authorize", "http://token");
//! config = config.add_scope("read");
//! config = config.set_redirect_url("http://redirect");
//!
//! let token_result = config.exchange_client_credentials();
//! ```
//!
//! # The password grant type
//!
//! You can ask for a *password* access token by calling the `Config::exchange_password` method, while including
//! the username and password.
//!
//! ## Example
//!
//! ```
//! use oauth2::Config;
//!
//! let mut config = Config::new("client_id", "client_secret", "http://authorize", "http://token");
//! config = config.add_scope("read");
//! config = config.set_redirect_url("http://redirect");
//!
//! let token_result = config.exchange_password("user", "pass");
//! ```
//!
//! # Setting a different response type
//!
//! The [RFC](https://tools.ietf.org/html/rfc6749#section-3.1.1) specifies various response types.
//!
//! The crate **defaults to the code response type**, but you can configure it to other values as well, by
//! calling the `Config::set_response_type` method.
//!
//! ## Example
//!
//! ```
//! use oauth2::{Config, ResponseType};
//!
//! let mut config = Config::new("client_id", "client_secret", "http://authorize", "http://token");
//! config = config.set_response_type(ResponseType::Token);
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Google](https://github.com/alexcrichton/oauth2-rs/blob/master/examples/google.rs)
//! - [Github](https://github.com/alexcrichton/oauth2-rs/blob/master/examples/github.rs)
//!

extern crate url;
extern crate curl;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate log;

use std::io::Read;
use std::convert::{From, Into, AsRef};
use std::fmt::{Display, Formatter};
use std::fmt::Error as FormatterError;
use std::error::Error;
use url::Url;
use curl::easy::Easy;

///
/// Stores the configuration for an OAuth2 client.
///
#[derive(Clone)]
pub struct Config {
    client_id: String,
    client_secret: String,
    auth_url: Url,
    auth_type: AuthType,
    token_url: Url,
    scopes: Vec<String>,
    response_type: ResponseType,
    redirect_url: Option<String>,
    state: Option<String>,
}

///
/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *RequestBody*.
///
#[derive(Clone)]
pub enum AuthType {
    /// The client_id and client_secret will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}

impl Config {
    ///
    /// Initializes the OAuth2 client with the client ID, client secret, the base authorization URL and the URL
    /// ment for requesting the access token.
    ///
    pub fn new<I, S, A, T>(client_id: I, client_secret: S, auth_url: A, token_url: T) -> Self
    where I: Into<String>, S: Into<String>, A: AsRef<str>, T: AsRef<str> {
        Config {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: Url::parse(auth_url.as_ref()).unwrap(),
            auth_type: AuthType::RequestBody,
            token_url: Url::parse(token_url.as_ref()).unwrap(),
            scopes: Vec::new(),
            response_type: ResponseType::Code,
            redirect_url: None,
            state: None,
        }
    }

    ///
    /// Appends a new scope to the authorization URL.
    ///
    pub fn add_scope<S>(mut self, scope: S) -> Self
    where S: Into<String> {
        self.scopes.push(scope.into());

        self
    }

    ///
    /// Allows setting a particular response type. Both `&str` and `ResponseType` work here.
    ///
    /// The default response type is *code*.
    ///
    pub fn set_response_type<R>(mut self, response_type: R) -> Self
    where R: Into<ResponseType> {
        self.response_type = response_type.into();

        self
    }

    ///
    /// Allows configuring whether basic auth is used to communicate with the authorization server.
    ///
    /// The default auth type is to place the client_id and client_secret inside the request body.
    ///
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = auth_type;

        self
    }

    ///
    /// Allows setting the redirect URL.
    ///
    pub fn set_redirect_url<R>(mut self, redirect_url: R) -> Self
    where R: Into<String> {
        self.redirect_url = Some(redirect_url.into());

        self
    }

    ///
    /// Allows setting a state parameter inside the authorization URL, which we'll be returned
    /// by the server after the authorization is over.
    ///
    /// *CSRF Protection*
    ///
    /// For proper CSRF protection you should set a per-request random state and verify that
    /// the state matches in the callback.  This API will reuse the same state for every request,
    /// therefore it is highly recommended that you upgrade to 2.0 and provide a random state
    /// to the authorize_url() method.
    ///
    #[deprecated(since="1.3.1", note="Please upgrade to 2.0 and pass a random per-request state to authorize_url()")]
    pub fn set_state<S>(mut self, state: S) -> Self
    where S: Into<String> {
        self.state = Some(state.into());

        self
    }

    ///
    /// Produces the full authorization URL.
    ///
    pub fn authorize_url(&self) -> Url {
        let scopes = self.scopes.join(" ");
        let response_type = self.response_type.to_string();

        let mut pairs = vec![
            ("client_id", &self.client_id),
            ("scope", &scopes),
            ("response_type", &response_type),
        ];

        if let Some(ref redirect_url) = self.redirect_url {
            pairs.push(("redirect_uri", redirect_url));
        }

        if let Some(ref state) = self.state {
            pairs.push(("state", state));
        }

        let mut url = self.auth_url.clone();

        url.query_pairs_mut().extend_pairs(
            pairs.iter().map(|&(k, v)| { (k, &v[..]) })
        );

        url
    }

    ///
    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.1.3
    ///
    #[deprecated(since="1.0.0", note="please use `exchange_code` instead")]
    pub fn exchange<C>(&self, code: C) -> Result<Token, TokenError>
    where C: Into<String> {
        let params = vec![
            ("code", code.into())
        ];

        self.request_token(params)
    }

    ///
    /// Exchanges a code produced by a successful authorization process with an access token.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.1.3
    ///
    pub fn exchange_code<C>(&self, code: C) -> Result<Token, TokenError>
    where C: Into<String> {
        let params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.into())
        ];

        self.request_token(params)
    }

    ///
    /// Requests an access token for the *client credentials* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.4.2
    ///
    pub fn exchange_client_credentials(&self) -> Result<Token, TokenError> {
        let scopes = self.scopes.join(" ");
        let params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("scope", scopes),
        ];

        self.request_token(params)
    }

    ///
    /// Requests an access token for the *password* grant type.
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-4.3.2
    ///
    pub fn exchange_password<U, P>(&self, username: U, password: P) -> Result<Token, TokenError>
    where U: Into<String>, P: Into<String> {
        let params = vec![
            ("grant_type", "password".to_string()),
            ("username", username.into()),
            ("password", password.into())
        ];

        self.request_token(params)
    }

    ///
    /// Exchanges a refresh token for an access token
    ///
    /// See https://tools.ietf.org/html/rfc6749#section-6
    ///
    pub fn exchange_refresh_token<T>(&self, token: T) -> Result<Token, TokenError>
    where T: Into<String> {
        let params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", token.into()),
        ];

        self.request_token(params)
    }

    fn request_token(&self, mut params: Vec<(&str, String)>) -> Result<Token, TokenError> {
        let mut easy = Easy::new();

        match self.auth_type {
            AuthType::RequestBody => {
                params.push(("client_id", self.client_id.clone()));
                params.push(("client_secret", self.client_secret.clone()));
            }
            AuthType::BasicAuth => {
                easy.username(&self.client_id).unwrap();
                easy.password(&self.client_secret).unwrap();
            }
        }

        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.to_string()));
        }

        let form = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
        let form = form.into_bytes();
        let mut form = &form[..];

        easy.url(&self.token_url.to_string()[..]).unwrap();
        easy.post(true).unwrap();
        easy.post_field_size(form.len() as u64).unwrap();

        let mut data = Vec::new();
        {
            let mut transfer = easy.transfer();

            transfer.read_function(|buf| {
                Ok(form.read(buf).unwrap_or(0))
            }).unwrap();

            transfer.write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            }).unwrap();

            transfer.perform().map_err(|e| TokenError::other(e.to_string()))?;
        }

        let code = easy.response_code().unwrap();

        if code != 200 {
            let reason = String::from_utf8_lossy(data.as_slice());
            let error = match serde_json::from_str::<TokenError>(&reason) {
                Ok(error) => error,
                Err(error) => TokenError::other(format!("couldn't parse json response: {}", error))
            };
            return Err(error);
        }

        let content_type = easy.content_type().unwrap_or(None).unwrap_or("application/x-www-formurlencoded");
        if content_type.contains("application/json") {
            Token::from_json(data)
        } else {
            Token::from_form(data)
        }
    }
}

///
/// The possible values for the `response_type` parameter.
///
/// See https://tools.ietf.org/html/rfc6749#section-3.1.1
///
#[allow(missing_docs)]
#[derive(Clone)]
pub enum ResponseType {
    Code,
    Token,
    Extension(String),
}

impl<'a> From<&'a str> for ResponseType {
    fn from(response_type: &str) -> ResponseType {
        match response_type {
            "code" => ResponseType::Code,
            "token" => ResponseType::Token,
            extension => ResponseType::Extension(extension.to_string()),
        }
    }
}

impl Display for ResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let formatted = match self {
            &ResponseType::Code => "code",
            &ResponseType::Token => "token",
            &ResponseType::Extension(ref value) => value,
        };

        write!(f, "{}", formatted)
    }
}

///
/// The token returned after a successful authorization process.
///
/// See https://tools.ietf.org/html/rfc6749#section-5.1
///
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Token {
    pub token_type: String,
    pub access_token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in: Option<u32>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

impl Token {
    fn from_form(data: Vec<u8>) -> Result<Self, TokenError> {
        let form = url::form_urlencoded::parse(&data);

        debug!("reponse: {:?}", form.collect::<Vec<_>>());

        let mut token = Token {
            access_token: String::new(),
            scopes: Vec::new(),
            token_type: String::new(),
            expires_in: None,
            refresh_token: None,
        };

        let mut error: Option<ErrorType> = None;
        let mut error_description = None;
        let mut error_uri = None;
        let mut state = None;

        for(k, v) in form.into_iter() {
            match &k[..] {
                "access_token" => token.access_token = v.into_owned(),
                "token_type" => token.token_type = v.into_owned(),
                "scope" => token.scopes = v.split(',').map(|s| s.to_string()).collect(),
                "error" => error = Some(v.as_ref().into()),
                "error_description" => error_description = Some(v.into_owned()),
                "error_uri" => error_uri = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                _ => {}
            }
        }

        if token.access_token.len() != 0 {
            Ok(token)
        } else if let Some(error) = error {
            let token_error = TokenError { error, error_description, error_uri, state };
            Err(token_error)
        } else {
            Err(TokenError::other("couldn't parse form response"))
        }
    }

    fn from_json(data: Vec<u8>) -> Result<Self, TokenError> {
        let data = String::from_utf8(data).unwrap();

        debug!("response: {}", data);

        serde_json::from_str(&data).map_err(|parse_error| {
            match serde_json::from_str::<TokenError>(&data) {
                Ok(token_error) => token_error,
                Err(_) => TokenError::other(format!("couldn't parse json response: {}", parse_error)),
            }
        })
    }
}

///
/// An error that occured after a failed authorization process.
///
/// The same structure is returned both for OAuth2 specific errors, but also for parsing/transport errors.
/// The latter can be differentiated by looking for the `ErrorType::Other` variant.
///
/// See https://tools.ietf.org/html/rfc6749#section-4.2.2.1
///
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenError {
    pub error: ErrorType,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub error_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

impl TokenError {
    fn other<E>(error: E) -> TokenError
    where E: Into<String> {
        TokenError {
            error: ErrorType::Other(error.into()),
            error_description: None,
            error_uri: None,
            state: None,
        }
    }
}

impl Display for TokenError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let mut formatted = self.error.to_string();

        if let Some(ref error_description) = self.error_description {
            formatted.push_str(": ");
            formatted.push_str(error_description);
        }

        if let Some(ref error_uri) = self.error_uri {
            formatted.push_str(" / See ");
            formatted.push_str(error_uri);
        }

        write!(f, "{}", formatted)
    }
}

impl Error for TokenError {
    fn description(&self) -> &str {
        (&self.error).into()
    }
}

///
/// An OAuth2-specific error type or *other*.
///
/// See https://tools.ietf.org/html/rfc6749#section-4.2.2.1
///
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum ErrorType {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    Other(String),
}

impl<'a> From<&'a str> for ErrorType {
    fn from(error_type: &str) -> ErrorType {
        match error_type {
            "invalid_request" => ErrorType::InvalidRequest,
            "unauthorized_client" => ErrorType::UnauthorizedClient,
            "access_denied" => ErrorType::AccessDenied,
            "unsupported_response_type" => ErrorType::UnsupportedResponseType,
            "invalid_scope" => ErrorType::InvalidScope,
            "server_error" => ErrorType::ServerError,
            "temporarily_unavailable" => ErrorType::TemporarilyUnavailable,
            other => ErrorType::Other(other.to_string()),
        }
    }
}

impl<'a> Into<&'a str> for &'a ErrorType {
    fn into(self) -> &'a str {
        match self {
            &ErrorType::InvalidRequest => "invalid_request",
            &ErrorType::UnauthorizedClient => "unauthorized_client",
            &ErrorType::AccessDenied => "access_denied",
            &ErrorType::UnsupportedResponseType => "unsupported_response_type",
            &ErrorType::InvalidScope => "invalid_scope",
            &ErrorType::ServerError => "server_error",
            &ErrorType::TemporarilyUnavailable => "temporarily_unavailable",
            &ErrorType::Other(ref other) => other,
        }
    }
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let message: &str = self.into();

        write!(f, "{}", message)
    }
}
