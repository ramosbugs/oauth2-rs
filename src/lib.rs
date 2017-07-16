#![cfg_attr(test, deny(warnings))]

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

// See https://tools.ietf.org/html/rfc6749#section-5.2
#[derive(Debug, Deserialize)]
struct TokenError {
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    error_uri: String,
}

impl Display for TokenError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "error `{}`: {}, see {}", self.error, self.error_description, self.error_uri)
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
    pub fn exchange<C>(&self, code: C) -> Result<Token, String>
        where C: Into<String> {
        let params = vec![
            ("code", code.into())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.1.3
    pub fn exchange_code<C>(&self, code: C) -> Result<Token, String>
        where C: Into<String> {
        let params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.into())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.4.2
    pub fn exchange_client_credentials(&self) -> Result<Token, String> {
        let params = vec![
            ("grant_type", "client_credentials".to_string())
        ];

        self.request_token(params)
    }

    // See https://tools.ietf.org/html/rfc6749#section-4.3.2
    pub fn exchange_password<U, P>(&self, username: U, password: P) -> Result<Token, String>
        where U: Into<String>, P: Into<String> {
        let params = vec![
            ("grant_type", "password".to_string()),
            ("username", username.into()),
            ("password", password.into())
        ];

        self.request_token(params)
    }

    fn request_token(&self, mut params: Vec<(&str, String)>) -> Result<Token, String> {
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
            return Err(format!("expected `200`, found `{}`\nerr: {}", code, reason))
        }

        let content_type = easy.content_type().unwrap_or(None).unwrap_or("application/x-www-formurlencoded");
        if content_type.contains("application/json") {
            Token::from_json(data)
        } else {
            Token::from_form(data)
        }
    }
}

impl Token {
    fn from_form(data: Vec<u8>) -> Result<Self, String> {
        let form = url::form_urlencoded::parse(&data);

        debug!("reponse: {:?}", form.collect::<Vec<_>>());

        let mut token = Token {
            access_token: String::new(),
            scopes: Vec::new(),
            token_type: String::new(),
            expires_in: None,
            refresh_token: None,
        };

        let mut error = String::new();
        let mut error_description = String::new();
        let mut error_uri = String::new();

        for(k, v) in form.into_iter() {
            match &k[..] {
                "access_token" => token.access_token = v.into_owned(),
                "token_type" => token.token_type = v.into_owned(),
                "scope" => {
                    token.scopes = v.split(',')
                                    .map(|s| s.to_string()).collect();
                }
                "error" => error = v.into_owned(),
                "error_description" => error_description = v.into_owned(),
                "error_uri" => error_uri = v.into_owned(),
                _ => {}
            }
        }

        if token.access_token.len() != 0 {
            Ok(token)
        } else if error.len() > 0 {
            let token_error = TokenError { error, error_description, error_uri };
            Err(token_error.to_string())
        } else {
            Err(format!("couldn't find access_token in the response"))
        }
    }

    fn from_json(data: Vec<u8>) -> Result<Self, String> {
        let data = String::from_utf8(data).unwrap();

        debug!("response: {}", data);

        serde_json::from_str(&data).map_err(|parse_error| {
            match serde_json::from_str::<TokenError>(&data) {
                Ok(token_error) => token_error.to_string(),
                Err(_) => parse_error.to_string(),
            }
        })
    }
}
