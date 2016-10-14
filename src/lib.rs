#![cfg_attr(test, deny(warnings))]

extern crate url;
extern crate curl;
#[macro_use] extern crate log;

use url::Url;
use std::collections::HashMap;

use std::io::Read;
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

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Token {
    pub access_token: String,
    pub scopes: Vec<String>,
    pub token_type: String,
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

        let form = url::form_urlencoded::parse(&data);

        let mut token = Token {
            access_token: String::new(),
            scopes: Vec::new(),
            token_type: String::new(),
        };
        let mut error = String::new();
        let mut error_desc = String::new();
        let mut error_uri = String::new();

        debug!("reponse: {:?}", form.collect::<Vec<_>>());
        for(k, v) in form.into_iter() {
            match &k[..] {
                "access_token" => token.access_token = v.into_owned(),
                "token_type" => token.token_type = v.into_owned(),
                "scope" => {
                    token.scopes = v.split(',')
                                    .map(|s| s.to_string()).collect();
                }
                "error" => error = v.into_owned(),
                "error_description" => error_desc = v.into_owned(),
                "error_uri" => error_uri = v.into_owned(),
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
