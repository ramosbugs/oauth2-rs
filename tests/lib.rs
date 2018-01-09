extern crate mockito;
extern crate url;
extern crate oauth2;

use std::error::Error;
use url::Url;
use mockito::{mock, SERVER_URL};
use oauth2::{Config, ResponseType, ErrorType};

#[test]
fn test_authorize_url() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=&response_type=code").unwrap(), url);
}

#[test]
fn test_authorize_url_with_param() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth?foo=bar", "http://example.com/token");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?foo=bar&client_id=aaa&scope=&response_type=code").unwrap(), url);
}

#[test]
fn test_authorize_url_with_scopes() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token")
        .add_scope("read")
        .add_scope("write");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=read+write&response_type=code").unwrap(), url);
}

#[test]
fn test_authorize_url_with_state() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token")
        .set_state("some state");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=&response_type=code&state=some+state").unwrap(), url);
}

#[test]
fn test_authorize_url_with_response_type() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token")
        .set_response_type(ResponseType::Token);

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=&response_type=token").unwrap(), url);
}

#[test]
fn test_authorize_url_with_extension_response_type() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token")
        .set_response_type("code token");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=&response_type=code+token").unwrap(), url);
}

#[test]
fn test_authorize_url_with_redirect_url() {
    let config = Config::new("aaa", "bbb", "http://example.com/auth", "http://example.com/token")
        .set_redirect_url("http://localhost/redirect");

    let url = config.authorize_url();

    assert_eq!(Url::parse("http://example.com/auth?client_id=aaa&scope=&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fredirect").unwrap(), url);
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
        .match_body("grant_type=client_credentials&scope=&client_id=aaa&client_secret=bbb")
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
        .match_body("grant_type=client_credentials&scope=&client_id=aaa&client_secret=bbb")
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

#[test]
fn test_exchange_code_successful_with_redirect_url() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb&redirect_uri=http%3A%2F%2Fredirect")
        .with_body("access_token=12%2F34&token_type=bearer&scope=read,write")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"))
        .set_redirect_url("http://redirect");

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
fn test_exchange_code_with_simple_form_error() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_body("error=invalid_request")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::InvalidRequest, error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(None, error.state);
}

#[test]
fn test_exchange_code_with_simple_json_error() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("{\"error\": \"invalid_request\"}")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::InvalidRequest, error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(None, error.state);
}

#[test]
fn test_exchange_code_with_simple_form_error_trait() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_body("error=invalid_request")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!("invalid_request", error.description());
}

#[test]
fn test_exchange_code_with_form_error_with_state() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_body("error=invalid_request&state=some%20state")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::InvalidRequest, error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(Some("some state".to_string()), error.state);
}

#[test]
fn test_exchange_code_with_json_error_with_state() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("{\"error\": \"invalid_request\", \"state\": \"some state\"}")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::InvalidRequest, error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(Some("some state".to_string()), error.state);
}

#[test]
fn test_exchange_code_with_form_parse_error() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_body("broken form")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::Other("couldn't parse form response".to_string()), error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(None, error.state);
}

#[test]
fn test_exchange_code_with_json_parse_error() {
    let mock = mock("POST", "/token")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body("broken json")
        .create();

    let config = Config::new("aaa", "bbb", "http://example.com/auth", &(SERVER_URL.to_string() + "/token"));
    let token = config.exchange_code("ccc");

    mock.assert();

    assert!(token.is_err());

    let error = token.err().unwrap();
    assert_eq!(ErrorType::Other("couldn't parse json response: expected value at line 1 column 1".to_string()), error.error);
    assert_eq!(None, error.error_description);
    assert_eq!(None, error.error_uri);
    assert_eq!(None, error.state);
}

#[test]
fn test_exchange_code_fails_gracefully_on_transport_error() {
    let config = Config::new("aaa", "bbb", "http://auth", "http://token");
    let token = config.exchange_code("ccc");

    assert!(token.is_err());

    // The variant argument is "[6] Couldn't resolve host name (Couldn't resolve host 'token')"...
    // ...or "[6] Couldn't resolve host name (Could not resolve host token)" in some circumstances
    let error = token.err().unwrap();
    match error.error {
        ErrorType::Other(_) => assert!(true),
        _ => assert!(false),
    }
}
