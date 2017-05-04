#![cfg_attr(test, deny(warnings))]

extern crate url;
extern crate curl;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate log;

use std::collections::HashMap;
use std::io::Read;
use std::convert::Into;
use std::fmt::{Display, Formatter};
use std::fmt::Error as FormatterError;
use url::Url;
use curl::easy::Easy;

/// Configuration of an oauth2 application.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub auth_url: Url,
    pub token_url: Url,
    pub redirect_url: String,
}

// See https://tools.ietf.org/html/rfc6749#section-5.1
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Deserialize)]
pub struct Token {
    pub access_token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub token_type: String,
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

impl Config {
    pub fn new(id: &str, secret: &str, auth_url: &str, token_url: &str) -> Config {
        Config {
            client_id: id.to_string(),
            client_secret: secret.to_string(),
            scopes: Vec::new(),
            auth_url: Url::parse(auth_url).unwrap(),
            token_url: Url::parse(token_url).unwrap(),
            redirect_url: String::new(),
        }
    }

    pub fn authorize_url(&self, state: String) -> Url {
        let scopes = self.scopes.join(",");
        let mut pairs = vec![
            ("client_id", &self.client_id),
            ("state", &state),
            ("scope", &scopes),
        ];

        if self.redirect_url.len() > 0 {
            pairs.push(("redirect_uri", &self.redirect_url));
        }

        let mut url = self.auth_url.clone();
        url.query_pairs_mut().clear().extend_pairs(
            pairs.iter().map(|&(k, v)| { (k, &v[..]) })
        );

        url
    }

    pub fn exchange<C: Into<String>>(&self, code: C) -> Result<Token, String> {
        let mut form = HashMap::new();
        form.insert("client_id", self.client_id.clone());
        form.insert("client_secret", self.client_secret.clone());
        form.insert("code", code.into());
        if self.redirect_url.len() > 0 {
            form.insert("redirect_uri", self.redirect_url.clone());
        }

        let form = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(
            form.iter().map(|(k, v)| { (&k[..], &v[..]) })
        ).finish();

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
            return Err(format!("expected `200`, found `{}`", code))
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
    pub fn from_form(data: Vec<u8>) -> Result<Self, String> {
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

    pub fn from_json(data: Vec<u8>) -> Result<Self, String> {
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
