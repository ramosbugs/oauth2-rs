#![feature(phase)]

extern crate url;
extern crate curl;
#[phase(plugin, link)] extern crate log;

use url::Url;
use std::collections::HashMap;
use std::io::MemReader;

use curl::http;

/// Configuration of an oauth2 application.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub auth_url: Url,
    pub token_url: Url,
    pub redirect_url: String,
}

#[deriving(Show, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Token {
    pub access_token: String,
    pub scopes: Vec<String>,
    pub token_type: String,
}

/// Helper trait for extending the builder-style pattern of curl::Request.
///
/// This trait allows chaining the correct authorization headers onto a curl
/// request via the builder style.
pub trait Authorization {
    fn auth_with(self, token: &Token) -> Self;
}

impl Config {
    pub fn new(id: &str, secret: &str, auth_url: &str,
               token_url: &str) -> Config {
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
        let scopes = self.scopes.connect(",");
        let mut pairs = vec![
            ("client_id", &self.client_id),
            ("state", &state),
            ("scope", &scopes),
        ];
        if self.redirect_url.len() > 0 {
            pairs.push(("redirect_uri", &self.redirect_url));
        }
        let mut url = self.auth_url.clone();
        url.set_query_from_pairs(pairs.iter().map(|&(k, v)| {
            (k, v.as_slice())
        }));
        return url;
    }

    pub fn exchange(&self, code: String) -> Result<Token, String> {
        let mut form = HashMap::new();
        form.insert("client_id", self.client_id.clone());
        form.insert("client_secret", self.client_secret.clone());
        form.insert("code", code);
        if self.redirect_url.len() > 0 {
            form.insert("redirect_uri", self.redirect_url.clone());
        }

        let form = url::form_urlencoded::serialize(form.iter().map(|(k, v)| {
            (k.as_slice(), v.as_slice())
        }));
        let mut form = MemReader::new(form.into_bytes());

        let result = try!(http::handle()
                               .post(self.token_url.to_string().as_slice(),
                                     &mut form)
                               .header("Content-Type",
                                       "application/x-www-form-urlencoded")
                               .exec()
                               .map_err(|s| s.to_string()));

        if result.get_code() != 200 {
            return Err(format!("expected `200`, found `{}`", result.get_code()))
        }

        let mut token = Token {
            access_token: String::new(),
            scopes: Vec::new(),
            token_type: String::new(),
        };
        let mut error = String::new();
        let mut error_desc = String::new();
        let mut error_uri = String::new();

        let form = url::form_urlencoded::parse(result.get_body());
        debug!("reponse: {}", form);
        for(k, v) in form.into_iter() {
            match k.as_slice() {
                "access_token" => token.access_token = v,
                "token_type" => token.token_type = v,
                "scope" => {
                    token.scopes = v.as_slice().split(',')
                                    .map(|s| s.to_string()).collect();
                }
                "error" => error = v,
                "error_description" => error_desc = v,
                "error_uri" => error_uri = v,
                _ => {}
            }
        }

        if token.access_token.len() != 0 {
            Ok(token)
        } else if error.len() > 0 {
            Err(format!("error `{}`: {}, see {}", error, error_desc, error_uri))
        } else {
            Err(format!("couldn't find access_token in the response"))
        }
    }
}

impl<'a, 'b> Authorization for http::Request<'a, 'b> {
    fn auth_with(self, token: &Token) -> http::Request<'a, 'b> {
        self.header("Authorization",
                    format!("token {}", token.access_token).as_slice())
    }
}
