extern crate mockito;
extern crate url;
extern crate oauth2;

use url::Url;
use mockito::{mock, SERVER_URL};
use oauth2::Config;

#[test]
fn test_new_config() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");

    assert_eq!("aaa", config.client_id);
    assert_eq!("bbb", config.client_secret);
    assert_eq!(Url::parse("http://example.com/auth").unwrap(), config.auth_url);
    assert_eq!(Url::parse("http://example.com/token").unwrap(), config.token_url);
    assert_eq!(0, config.scopes.len());
    assert_eq!(String::new(), config.redirect_url);
}

#[test]
fn test_authorize_url() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");
    let url = config.authorize_url(String::new());

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&state=&scope=").unwrap(), url);
}

#[test]
fn test_authorize_url_with_scopes() {
    let mut config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");
    config.scopes.push("read".to_string());
    config.scopes.push("write".to_string());

    let url = config.authorize_url(String::new());

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&state=&scope=read%2Cwrite").unwrap(), url);
}

#[test]
fn test_authorize_url_with_state() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");
    let url = config.authorize_url("some state".to_string());

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&state=some+state&scope=").unwrap(), url);
}

#[test]
fn test_authorize_url_with_redirect_url() {
    let mut config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");
    config.redirect_url = "http://localhost/redirect".to_string();

    let url = config.authorize_url(String::new());

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&state=&scope=&redirect_uri=http%3A%2F%2Flocalhost%2Fredirect").unwrap(), url);
}

#[test]
fn test_exchange_code_successful_with_form_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_body("access_token=12%2F34&token_type=bearer&scope=read,write")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}

#[test]
fn test_exchange_code_successful_with_json_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scopes\": [\"read\", \"write\"]}")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}

#[test]
fn test_exchange_client_credentials_with_form_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=client_credentials&client_id=aaa&client_secret=bbb")
        .with_body("access_token=12%2F34&token_type=bearer&scope=read,write")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_client_credentials();

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}

#[test]
fn test_exchange_client_credentials_with_json_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=client_credentials&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scopes\": [\"read\", \"write\"]}")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_client_credentials();

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}

#[test]
fn test_exchange_password_with_form_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=password&username=user&password=pass&client_id=aaa&client_secret=bbb")
        .with_body("access_token=12%2F34&token_type=bearer&scope=read,write")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_password("user", "pass");

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}

#[test]
fn test_exchange_password_with_json_response() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=password&username=user&password=pass&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scopes\": [\"read\", \"write\"]}")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_password("user", "pass");

    mock.assert();

    assert!(token.is_ok());

    let token = token.unwrap();
    assert_eq!("12/34", token.access_token);
    assert_eq!("bearer", token.token_type);
    assert_eq!(vec!["read".to_string(), "write".to_string()], token.scopes);
    assert_eq!(None, token.expires_in);
    assert_eq!(None, token.refresh_token);
}
