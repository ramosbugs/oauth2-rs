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
use url::Url;
use curl::easy::Easy;

/// Configuration of an oauth2 application.
pub struct Config {
    client_id: String,
    client_secret: String,
    auth_url: Url,
    token_url: Url,
    scopes: Vec<String>,
    response_type: ResponseType,
    redirect_url: Option<String>,
    state: Option<String>,
}

impl Config {
    pub fn new<I, S, A, T>(client_id: I, client_secret: S, auth_url: A, token_url: T) -> Self
    where I: Into<String>, S: Into<String>, A: AsRef<str>, T: AsRef<str> {
        Config {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: Url::parse(auth_url.as_ref()).unwrap(),
            token_url: Url::parse(token_url.as_ref()).unwrap(),
            scopes: Vec::new(),
            response_type: ResponseType::Code,
            redirect_url: None,
            state: None,
        }
    }

    pub fn add_scope<S>(mut self, scope: S) -> Self
    where S: Into<String> {
        self.scopes.push(scope.into());

        self
    }

    pub fn set_response_type<R>(mut self, response_type: R) -> Self
    where R: Into<ResponseType> {
        self.response_type = response_type.into();

        self
    }

    pub fn set_redirect_url<R>(mut self, redirect_url: R) -> Self
    where R: Into<String> {
        self.redirect_url = Some(redirect_url.into());

        self
    }

    pub fn set_state<S>(mut self, state: S) -> Self
    where S: Into<String> {
        self.state = Some(state.into());

        self
    }

    pub fn authorize_url(&self) -> Url {
        let scopes = self.scopes.join(",");
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

        url.query_pairs_mut().clear().extend_pairs(
            pairs.iter().map(|&(k, v)| { (k, &v[..]) })
        );

        url
    }

    #[deprecated(since="0.4.0", note="please use `exchange_code` instead")]
    pub fn exchange<C>(&self, code: C) -> Result<Token, TokenError>
    where C: Into<String> {
        let params = vec![
            ("code", code.into())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.1.3
    pub fn exchange_code<C>(&self, code: C) -> Result<Token, TokenError>
    where C: Into<String> {
        let params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.into())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.4.2
    pub fn exchange_client_credentials(&self) -> Result<Token, TokenError> {
        let params = vec![
            ("grant_type", "client_credentials".to_string())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.3.2
    pub fn exchange_password<U, P>(&self, username: U, password: P) -> Result<Token, TokenError>
    where U: Into<String>, P: Into<String> {
        let params = vec![
            ("grant_type", "password".to_string()),
            ("username", username.into()),
            ("password", password.into())
        ];

        self.request_token(params)
    }

    fn request_token(&self, mut params: Vec<(&str, String)>) -> Result<Token, TokenError> {
        params.push(("client_id", self.client_id.clone()));
        params.push(("client_secret", self.client_secret.clone()));

        if let Some(ref redirect_url) = self.redirect_url {
            params.push(("redirect_uri", redirect_url.to_string()));
        }

        let form = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
        let form = form.into_bytes();
        let mut form = &form[..];

        let mut easy = Easy::new();

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

            transfer.perform().unwrap();
        }

        let code = easy.response_code().unwrap();

        if code != 200 {
            let reason = String::from_utf8_lossy(data.as_slice());
            return Err(TokenError::other(format!("expected `200`, found `{}`\nerr: {}", code, reason)))
        }

        let content_type = easy.content_type().unwrap_or(None).unwrap_or("application/x-www-formurlencoded");
        if content_type.contains("application/json") {
            Token::from_json(data)
        } else {
            Token::from_form(data)
        }
    }
}

// https://tools.ietf.org/html/rfc6749#section-3.1.1
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

// See https://tools.ietf.org/html/rfc6749#section-5.1
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Deserialize)]
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

// https://tools.ietf.org/html/rfc6749#section-4.2.2.1
#[derive(Debug, PartialEq, Deserialize)]
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

#[derive(Debug, PartialEq, Deserialize)]
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

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let formatted = match self {
            &ErrorType::InvalidRequest => "invalid_request",
            &ErrorType::UnauthorizedClient => "unauthorized_client",
            &ErrorType::AccessDenied => "access_denied",
            &ErrorType::UnsupportedResponseType => "unsupported_response_type",
            &ErrorType::InvalidScope => "invalid_scope",
            &ErrorType::ServerError => "server_error",
            &ErrorType::TemporarilyUnavailable => "temporarily_unavailable",
            &ErrorType::Other(ref other) => other,
        };

        write!(f, "{}", formatted)
    }
}
