extern crate mockito;
extern crate oauth2;
extern crate serde;
extern crate url;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use mockito::{mock, server_url};
use url::form_urlencoded::byte_serialize;
use url::Url;

use oauth2::basic::*;
use oauth2::prelude::*;
use oauth2::*;

fn new_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("http://example.com/token").unwrap(),
        )),
    )
}

fn new_mock_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    )
}

fn new_mock_client_with_unsafe_chars() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa/;&".to_string()),
        Some(ClientSecret::new("bbb/;&".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    )
}

#[test]
#[should_panic]
fn test_code_verifier_too_short() {
    PkceCodeVerifierS256::new_random_len(31);
}

#[test]
#[should_panic]
fn test_code_verifier_too_long() {
    PkceCodeVerifierS256::new_random_len(97);
}

#[test]
fn test_code_verifier_min() {
    let code_verifier = PkceCodeVerifierS256::new_random_len(32);
    assert!(code_verifier.secret().len() == 43);
}

#[test]
fn test_code_verifier_max() {
    let code_verifier = PkceCodeVerifierS256::new_random_len(96);
    assert!(code_verifier.secret().len() == 128);
}

#[test]
fn test_code_verifier_challenge() {
    // Example from https://tools.ietf.org/html/rfc7636#appendix-B
    let code_verifier =
        PkceCodeVerifierS256::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
    assert!(
        code_verifier.code_challenge().as_str() == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn test_authorize_url() {
    let client = new_client();
    let (url, _) = client.authorize_url(|| CsrfToken::new("csrf_token".to_string()));

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=code&client_id=aaa&state=csrf_token")
            .unwrap(),
        url
    );
}

#[test]
fn test_authorize_random() {
    let client = new_client();
    let (url, csrf_state) = client.authorize_url(CsrfToken::new_random);

    assert_eq!(
        Url::parse(&format!(
            "http://example.com/auth?response_type=code&client_id=aaa&state={}",
            byte_serialize(csrf_state.secret().clone().into_bytes().as_slice())
                .collect::<Vec<_>>()
                .join("")
        ))
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_insecure() {
    let client = new_client();

    let url = oauth2::insecure::authorize_url(&client);

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=code&client_id=aaa").unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_pkce() {
    // Example from https://tools.ietf.org/html/rfc7636#appendix-B
    let client = new_client();
    let verifier =
        PkceCodeVerifierS256::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
    let (url, _) = client.authorize_url_extension(
        &ResponseType::new("code".to_string()),
        || CsrfToken::new("csrf_token".to_string()),
        &verifier.authorize_url_params(),
    );
    assert_eq!(
        Url::parse(concat!(
            "http://example.com/auth",
            "?response_type=code&client_id=aaa",
            "&state=csrf_token",
            "&code_challenge_method=S256",
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ))
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_implicit() {
    let client = new_client();

    let (url, _) = client.authorize_url_implicit(|| CsrfToken::new("csrf_token".to_string()));

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=token&client_id=aaa&state=csrf_token")
            .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_implicit_insecure() {
    let client = new_client();

    let url = oauth2::insecure::authorize_url_implicit(&client);

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=token&client_id=aaa").unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_param() {
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth?foo=bar").unwrap()),
        Some(TokenUrl::new(
            Url::parse("http://example.com/token").unwrap(),
        )),
    );

    let (url, _) = client.authorize_url(|| CsrfToken::new("csrf_token".to_string()));

    assert_eq!(
        Url::parse(
            "http://example.com/auth?foo=bar&response_type=code&client_id=aaa&state=csrf_token"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_scopes() {
    let client = new_client()
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()));

    let (url, _) = client.authorize_url(|| CsrfToken::new("csrf_token".to_string()));

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code&client_id=aaa&scope=read+write&\
             state=csrf_token"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_extension_response_type() {
    let client = new_client();

    let (url, _) = client.authorize_url_extension(
        &ResponseType::new("code token".to_string()),
        || CsrfToken::new("csrf_token".to_string()),
        &vec![("foo", "bar")],
    );

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code+token&client_id=aaa&state=csrf_token\
             &foo=bar"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_redirect_url() {
    let client = new_client().set_redirect_url(RedirectUrl::new(
        Url::parse("http://localhost/redirect").unwrap(),
    ));

    let (url, _) = client.authorize_url(|| CsrfToken::new("csrf_token".to_string()));

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code&client_id=aaa&redirect_uri=http\
             %3A%2F%2Flocalhost%2Fredirect&state=csrf_token"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_exchange_code_successful_with_minimal_json_response() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc")
        // Ensure that token_type is case insensitive.
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"BEARER\"}")
        // Omit the Content-Type header to ensure that we still parse it as JSON.
        .create();

    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"bearer\"}".to_string(),
        serialized_json
    );

    let deserialized_token = serde_json::from_str::<BasicTokenResponse>(&serialized_json).unwrap();
    assert_eq!(token, deserialized_token);
}

#[test]
fn test_exchange_code_successful_with_complete_json_response() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("Content-Type", "application/json")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\", \
             \"expires_in\": 3600, \"refresh_token\": \"foobar\"}",
        )
        .create();

    let client = new_mock_client().set_auth_type(oauth2::AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(3600, token.expires_in().unwrap().as_secs());
    assert_eq!("foobar", token.refresh_token().clone().unwrap().secret());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"bearer\",\"expires_in\":3600,\
         \"refresh_token\":\"foobar\",\"scope\":\"read write\"}"
            .to_string(),
        serialized_json
    );

    let deserialized_token = serde_json::from_str::<BasicTokenResponse>(&serialized_json).unwrap();
    assert_eq!(token, deserialized_token);
}

#[test]
fn test_exchange_client_credentials_with_basic_auth() {
    let mock = mock("POST", "/token")
        // base64(urlencode("aaa/;&") + ":" + urlencode("bbb/;&"))
        .match_header(
            "Authorization",
            "Basic YWFhJTJGJTNCJTI2OmJiYiUyRiUzQiUyNg==",
        )
        .match_body("grant_type=client_credentials")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client_with_unsafe_chars().set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client.exchange_client_credentials().unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_client_credentials_with_body_auth_and_scope() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body(
            "grant_type=client_credentials&scope=read+write&client_id=aaa&client_secret=bbb",
        )
        // Ensure we parse headers case insensitively.
        .with_header("content-TYPE", "APPLICATION/jSoN")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .set_auth_type(oauth2::AuthType::RequestBody)
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()));
    let token = client.exchange_client_credentials().unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_refresh_token_with_basic_auth() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=refresh_token&refresh_token=ccc")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client().set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_refresh_token_with_json_response() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=refresh_token&refresh_token=ccc")
        // Ensure we can handle (ignore) charsets
        .with_header("content-type", "application/json; charset=\"utf-8\"")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client();
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_password_with_json_response() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=password&username=user&password=pass&scope=read+write")
        .with_header("content-type", "application/json")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()));
    let token = client
        .exchange_password(
            &ResourceOwnerUsername::new("user".to_string()),
            &ResourceOwnerPassword::new("pass".to_string()),
        )
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_code_successful_with_redirect_url() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body(
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb&redirect_uri=\
             http%3A%2F%2Fredirect%2Fhere",
        )
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .set_auth_type(oauth2::AuthType::RequestBody)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_code_successful_with_basic_auth() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body(
            "grant_type=authorization_code&code=ccc&redirect_uri=http%3A%2F%2Fredirect%2Fhere",
        )
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_code_successful_with_extension() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body(
            "grant_type=authorization_code&code=ccc\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &redirect_uri=http%3A%2F%2Fredirect%2Fhere",
        )
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://redirect/here").unwrap(),
        ));

    let params: Vec<(&str, &str)> = vec![(
        "code_verifier",
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )];

    let token = client
        .exchange_code_extension(AuthorizationCode::new("ccc".to_string()), &params)
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_refresh_token_successful_with_extension() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body(
            "grant_type=refresh_token&refresh_token=ccc\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &redirect_uri=http%3A%2F%2Fredirect%2Fhere",
        )
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}",
        )
        .create();

    let client = new_mock_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://redirect/here").unwrap(),
        ));

    let params: Vec<(&str, &str)> = vec![(
        "code_verifier",
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )];

    let token = client
        .exchange_refresh_token_extension(&RefreshToken::new("ccc".to_string()), &params)
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
}

#[test]
fn test_exchange_code_with_simple_json_error() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body("{\"error\": \"invalid_request\", \"error_description\": \"stuff happened\"}")
        .create();

    let client = new_mock_client();
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());

    let token_err = token.err().unwrap();
    match &token_err {
        &RequestTokenError::ServerResponse(ref error_response) => {
            assert_eq!(
                BasicErrorResponseType::InvalidRequest,
                *error_response.error()
            );
            assert_eq!(
                Some(&"stuff happened".to_string()),
                error_response.error_description()
            );
            assert_eq!(None, error_response.error_uri());

            // Test Debug trait for ErrorResponse
            assert_eq!(
                "ErrorResponse { error: invalid_request, \
                 error_description: Some(\"stuff happened\"), error_uri: None }",
                format!("{:?}", error_response)
            );
            // Test Display trait for ErrorResponse
            assert_eq!(
                "invalid_request: stuff happened",
                format!("{}", error_response)
            );

            // Test Debug trait for BasicErrorResponseType
            assert_eq!("invalid_request", format!("{:?}", error_response.error()));
            // Test Display trait for BasicErrorResponseType
            assert_eq!("invalid_request", format!("{}", error_response.error()));

            // Ensure that serialization produces an equivalent JSON value.
            let serialized_json = serde_json::to_string(&error_response).unwrap();
            assert_eq!(
                "{\"error\":\"invalid_request\",\"error_description\":\"stuff happened\"}"
                    .to_string(),
                serialized_json
            );

            let deserialized_error =
                serde_json::from_str::<BasicErrorResponse>(&serialized_json).unwrap();
            assert_eq!(error_response, &deserialized_error);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Test Debug trait for RequestTokenError
    assert_eq!(
        "ServerResponse(ErrorResponse { error: invalid_request, \
         error_description: Some(\"stuff happened\"), error_uri: None })",
        format!("{:?}", token_err)
    );
    // Test Display trait for RequestTokenError
    assert_eq!(
        "Server returned error response `invalid_request: stuff happened`",
        format!("{}", token_err)
    );
}

#[test]
fn test_exchange_code_with_json_parse_error() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_header("authorization", "YWFhOmJiYg==") // base64("aaa:bbb")
        .with_header("content-type", "application/json")
        .with_body("broken json")
        .create();

    let client = new_mock_client();
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Parse(json_err, _) => {
            assert_eq!(1, json_err.line());
            assert_eq!(1, json_err.column());
            assert_eq!(serde_json::error::Category::Syntax, json_err.classify());
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_exchange_code_with_unexpected_content_type() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_header("authorization", "YWFhOmJiYg==") // base64("aaa:bbb")
        .with_header("content-type", "text/plain")
        .with_body("broken json")
        .create();

    let client = new_mock_client();
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Other(error_str) => {
            assert_eq!(
                "Unexpected response Content-Type: `text/plain`, should be `application/json`",
                error_str
            );
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_exchange_code_with_invalid_token_type() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOg==") // base64("aaa:")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_header("content-type", "application/json")
        // "magic" is not a recognized token type.
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"magic\"}")
        .create();

    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        None,
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    );

    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());
    match token.err().unwrap() {
        RequestTokenError::Parse(json_err, _) => {
            assert_eq!(1, json_err.line());
            assert_eq!(48, json_err.column());
            assert_eq!(serde_json::error::Category::Data, json_err.classify());
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_exchange_code_with_400_status_code() {
    let body = r#"{"error":"invalid_request","error_description":"Expired code."}"#;
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_header("content-type", "application/json")
        .with_body(body)
        .with_status(400)
        .create();

    let client = new_mock_client();
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::ServerResponse(error_response) => {
            assert_eq!(
                BasicErrorResponseType::InvalidRequest,
                *error_response.error()
            );
            assert_eq!(
                Some(&"Expired code.".to_string()),
                error_response.error_description()
            );
            assert_eq!(None, error_response.error_uri());
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_exchange_code_fails_gracefully_on_transport_error() {
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://auth").unwrap()),
        Some(TokenUrl::new(Url::parse("http://token").unwrap())),
    );
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    assert!(token.is_err());

    // The variant argument is "[6] Couldn't resolve host name (Couldn't resolve host 'token')"...
    // ...or "[6] Couldn't resolve host name (Could not resolve host token)" in some circumstances
    match token.err().unwrap() {
        RequestTokenError::Request(_) => (),
        other => panic!("Unexpected error: {:?}", other),
    }
}

mod colorful_extension {
    extern crate serde_json;

    use oauth2::*;
    use std::fmt::Error as FormatterError;
    use std::fmt::{Debug, Display, Formatter};

    pub type ColorfulClient = Client<
        ColorfulErrorResponseType,
        StandardTokenResponse<ColorfulFields, ColorfulTokenType>,
        ColorfulTokenType,
    >;

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ColorfulTokenType {
        Green,
        Red,
    }
    impl TokenType for ColorfulTokenType {}

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct ColorfulFields {
        #[serde(rename = "shape")]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub shape: Option<String>,
        #[serde(rename = "height")]
        pub height: u32,
    }
    impl ColorfulFields {
        pub fn shape(&self) -> Option<&String> {
            self.shape.as_ref()
        }
        pub fn height(&self) -> u32 {
            self.height
        }
    }
    impl ExtraTokenFields for ColorfulFields {}

    #[derive(Clone, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ColorfulErrorResponseType {
        TooDark,
        TooLight,
        WrongColorSpace,
    }

    impl ColorfulErrorResponseType {
        fn to_str(&self) -> &str {
            match self {
                &ColorfulErrorResponseType::TooDark => "too_dark",
                &ColorfulErrorResponseType::TooLight => "too_light",
                &ColorfulErrorResponseType::WrongColorSpace => "wrong_color_space",
            }
        }
    }

    impl ErrorResponseType for ColorfulErrorResponseType {}

    impl Debug for ColorfulErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            Display::fmt(self, f)
        }
    }

    impl Display for ColorfulErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            let message: &str = self.to_str();

            write!(f, "{}", message)
        }
    }

    pub type ColorfulTokenResponse = StandardTokenResponse<ColorfulFields, ColorfulTokenType>;
}

#[test]
fn test_extension_successful_with_minimal_json_response() {
    use colorful_extension::*;

    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_header("content-type", "application/json")
        .with_body("{\"access_token\": \"12/34\", \"token_type\": \"green\", \"height\": 10}")
        .create();

    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(ColorfulTokenType::Green, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, token.refresh_token());
    assert_eq!(None, token.extra_fields().shape());
    assert_eq!(10, token.extra_fields().height());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"green\",\"height\":10}".to_string(),
        serialized_json
    );

    let deserialized_token =
        serde_json::from_str::<ColorfulTokenResponse>(&serialized_json).unwrap();
    assert_eq!(token, deserialized_token);
}

#[test]
fn test_extension_successful_with_complete_json_response() {
    use colorful_extension::*;

    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body("grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb")
        .with_header("content-type", "application/json")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"red\", \"scope\": \"read write\", \
             \"expires_in\": 3600, \"refresh_token\": \"foobar\", \"shape\": \"round\", \
             \"height\": 12}",
        )
        .create();

    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    )
    .set_auth_type(oauth2::AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(ColorfulTokenType::Red, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(3600, token.expires_in().unwrap().as_secs());
    assert_eq!("foobar", token.refresh_token().clone().unwrap().secret());
    assert_eq!(Some(&"round".to_string()), token.extra_fields().shape());
    assert_eq!(12, token.extra_fields().height());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"red\",\"expires_in\":3600,\
         \"refresh_token\":\"foobar\",\"scope\":\"read write\",\"shape\":\"round\",\"height\":12}"
            .to_string(),
        serialized_json
    );

    let deserialized_token =
        serde_json::from_str::<ColorfulTokenResponse>(&serialized_json).unwrap();
    assert_eq!(token, deserialized_token);
}

#[test]
fn test_extension_with_simple_json_error() {
    use colorful_extension::*;

    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            "{\"error\": \"too_light\", \"error_description\": \"stuff happened\", \
             \"error_uri\": \"https://errors\"}",
        )
        .create();

    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("http://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse(&(server_url().to_string() + "/token")).unwrap(),
        )),
    );
    let token = client.exchange_code(AuthorizationCode::new("ccc".to_string()));

    mock.assert();

    assert!(token.is_err());

    let token_err = token.err().unwrap();
    match &token_err {
        &RequestTokenError::ServerResponse(ref error_response) => {
            assert_eq!(ColorfulErrorResponseType::TooLight, *error_response.error());
            assert_eq!(
                Some(&"stuff happened".to_string()),
                error_response.error_description()
            );
            assert_eq!(
                Some(&"https://errors".to_string()),
                error_response.error_uri()
            );

            // Ensure that serialization produces an equivalent JSON value.
            let serialized_json = serde_json::to_string(&error_response).unwrap();
            assert_eq!(
                "{\"error\":\"too_light\",\"error_description\":\"stuff happened\",\
                 \"error_uri\":\"https://errors\"}"
                    .to_string(),
                serialized_json
            );

            let deserialized_error = serde_json::from_str::<
                oauth2::ErrorResponse<ColorfulErrorResponseType>,
            >(&serialized_json)
            .unwrap();
            assert_eq!(error_response, &deserialized_error);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Test Debug trait for RequestTokenError
    assert_eq!(
        "ServerResponse(ErrorResponse { error: too_light, \
         error_description: Some(\"stuff happened\"), error_uri: Some(\"https://errors\") })",
        format!("{:?}", token_err)
    );
    // Test Display trait for RequestTokenError
    assert_eq!(
        "Server returned error response `too_light: stuff happened / See https://errors`",
        format!("{}", token_err)
    );
}

#[test]
fn test_extension_serializer() {
    use colorful_extension::{ColorfulFields, ColorfulTokenResponse, ColorfulTokenType};
    let mut token_response = ColorfulTokenResponse::new(
        AccessToken::new("mysecret".to_string()),
        ColorfulTokenType::Red,
        ColorfulFields {
            shape: Some("circle".to_string()),
            height: 10,
        },
    );
    token_response.set_expires_in(Some(3600));
    token_response.set_refresh_token(Some(RefreshToken::new("myothersecret".to_string())));
    let serialized = serde_json::to_string(&token_response).unwrap();
    assert_eq!(
        "{\
         \"access_token\":\"mysecret\",\
         \"token_type\":\"red\",\
         \"expires_in\":3600,\
         \"refresh_token\":\"myothersecret\",\
         \"shape\":\"circle\",\
         \"height\":10\
         }",
        serialized,
    );
}

#[test]
fn test_error_response_serializer() {
    assert_eq!(
        "{\"error\":\"unauthorized_client\"}",
        serde_json::to_string(&BasicErrorResponse::new(
            BasicErrorResponseType::UnauthorizedClient,
            None,
            None,
        ))
        .unwrap(),
    );

    assert_eq!(
        "{\
         \"error\":\"invalid_client\",\
         \"error_description\":\"Invalid client_id\",\
         \"error_uri\":\"https://example.com/errors/invalid_client\"\
         }",
        serde_json::to_string(&BasicErrorResponse::new(
            BasicErrorResponseType::InvalidClient,
            Some("Invalid client_id".to_string()),
            Some("https://example.com/errors/invalid_client".to_string()),
        ))
        .unwrap(),
    );
}

#[test]
fn test_secret_redaction() {
    let secret = ClientSecret::new("top_secret".to_string());
    assert_eq!("ClientSecret([redacted])", format!("{:?}", secret));
}
