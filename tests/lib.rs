extern crate failure;
extern crate failure_derive;
extern crate oauth2;
extern crate serde;
extern crate url;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use failure::Fail;
use url::form_urlencoded::byte_serialize;
use url::Url;

use oauth2::basic::*;
use oauth2::*;

fn new_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    )
}

fn mock_http_client(
    request_headers: Vec<(&'static str, &'static str)>,
    request_body: &'static str,
    response: HttpResponse,
) -> impl FnOnce(HttpRequest) -> Result<HttpResponse, FakeError> {
    move |request: HttpRequest| {
        assert_eq!(
            request.url,
            Url::parse("https://example.com/token").unwrap()
        );
        assert_eq!(
            request
                .headers
                .iter()
                .map(|(k, v)| (k.as_ref(), v.as_ref()))
                .collect::<Vec<_>>(),
            request_headers,
        );
        assert_eq!(&String::from_utf8(request.body).unwrap(), request_body);

        Ok(response)
    }
}

#[test]
#[should_panic]
fn test_code_verifier_too_short() {
    PkceCodeChallenge::new_random_sha256_len(31);
}

#[test]
#[should_panic]
fn test_code_verifier_too_long() {
    PkceCodeChallenge::new_random_sha256_len(97);
}

#[test]
fn test_code_verifier_min() {
    let code = PkceCodeChallenge::new_random_sha256_len(32);
    assert_eq!(code.1.secret().len(), 43);
}

#[test]
fn test_code_verifier_max() {
    let code = PkceCodeChallenge::new_random_sha256_len(96);
    assert_eq!(code.1.secret().len(), 128);
}

#[test]
fn test_code_verifier_challenge() {
    // Example from https://tools.ietf.org/html/rfc7636#appendix-B
    let code_verifier =
        PkceCodeVerifier::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
    assert_eq!(
        PkceCodeChallenge::from_code_verifier_sha256(&code_verifier).as_str(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
}

#[test]
fn test_authorize_url() {
    let client = new_client();
    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .url();

    assert_eq!(
        Url::parse("https://example.com/auth?response_type=code&client_id=aaa&state=csrf_token")
            .unwrap(),
        url
    );
}

#[test]
fn test_authorize_random() {
    let client = new_client();
    let (url, csrf_state) = client.authorize_url(CsrfToken::new_random).url();

    assert_eq!(
        Url::parse(&format!(
            "https://example.com/auth?response_type=code&client_id=aaa&state={}",
            byte_serialize(csrf_state.secret().clone().into_bytes().as_slice())
                .collect::<Vec<_>>()
                .join("")
        ))
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_pkce() {
    // Example from https://tools.ietf.org/html/rfc7636#appendix-B
    let client = new_client();

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .set_pkce_challenge(PkceCodeChallenge::from_code_verifier_sha256(
            &PkceCodeVerifier::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        ))
        .url();
    assert_eq!(
        Url::parse(concat!(
            "https://example.com/auth",
            "?response_type=code&client_id=aaa",
            "&state=csrf_token",
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "&code_challenge_method=S256",
        ))
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_implicit() {
    let client = new_client();

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .use_implicit_flow()
        .url();

    assert_eq!(
        Url::parse("https://example.com/auth?response_type=token&client_id=aaa&state=csrf_token")
            .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_param() {
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth?foo=bar").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .url();

    assert_eq!(
        Url::parse(
            "https://example.com/auth?foo=bar&response_type=code&client_id=aaa&state=csrf_token"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_scopes() {
    let (url, _) = new_client()
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .url();

    assert_eq!(
        Url::parse(
            "https://example.com/auth\
             ?response_type=code\
             &client_id=aaa\
             &state=csrf_token\
             &scope=read+write"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_extension_response_type() {
    let client = new_client();

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .set_response_type(&ResponseType::new("code token".to_string()))
        .add_extra_param("foo", "bar")
        .url();

    assert_eq!(
        Url::parse(
            "https://example.com/auth?response_type=code+token&client_id=aaa&state=csrf_token\
             &foo=bar"
        )
        .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_redirect_url() {
    let client = new_client().set_redirect_url(RedirectUrl::new(
        Url::parse("https://localhost/redirect").unwrap(),
    ));

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .url();

    assert_eq!(
        Url::parse(
            "https://example.com/auth?response_type=code\
             &client_id=aaa\
             &state=csrf_token\
             &redirect_uri=https%3A%2F%2Flocalhost%2Fredirect"
        )
        .unwrap(),
        url
    );
}

#[derive(Debug, Fail)]
enum FakeError {
    #[fail(display = "error")]
    Err,
}

#[test]
fn test_exchange_code_successful_with_minimal_json_response() {
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 200,
                headers: Vec::new(),
                body: "{\"access_token\": \"12/34\", \"token_type\": \"BEARER\"}"
                    .to_string()
                    .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client().set_auth_type(oauth2::AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![("Accept", "application/json")],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb",
            HttpResponse {
                status_code: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\", \
                       \"expires_in\": 3600, \
                       \"refresh_token\": \"foobar\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = BasicClient::new(
        ClientId::new("aaa/;&".to_string()),
        Some(ClientSecret::new("bbb/;&".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    )
    .set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client
        .exchange_client_credentials()
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                (
                    "Authorization",
                    "Basic YWFhJTJGJTNCJTI2OmJiYiUyRiUzQiUyNg==",
                ),
            ],
            "grant_type=client_credentials",
            HttpResponse {
                status_code: 200,
                headers: Vec::new(),
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client().set_auth_type(oauth2::AuthType::RequestBody);
    let token = client
        .exchange_client_credentials()
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .request(mock_http_client(
            vec![("Accept", "application/json")],
            "grant_type=client_credentials&scope=read+write&client_id=aaa&client_secret=bbb",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-TYPE".to_string(), "APPLICATION/jSoN".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client().set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            HttpResponse {
                status_code: 200,
                headers: Vec::new(),
                body: "{\"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client();
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            HttpResponse {
                status_code: 200,
                headers: Vec::new(),
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client();
    let token = client
        .exchange_password(
            &ResourceOwnerUsername::new("user".to_string()),
            &ResourceOwnerPassword::new("pass".to_string()),
        )
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=password&username=user&password=pass&scope=read+write",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client()
        .set_auth_type(oauth2::AuthType::RequestBody)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("https://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![("Accept", "application/json")],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb&\
             redirect_uri=https%3A%2F%2Fredirect%2Fhere",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("https://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc&redirect_uri=https%3A%2F%2Fredirect%2Fhere",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
fn test_exchange_code_successful_with_pkce_and_extension() {
    let client = new_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("https://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        ))
        .add_extra_param("foo", "bar")
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code\
             &code=ccc\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &redirect_uri=https%3A%2F%2Fredirect%2Fhere\
             &foo=bar",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client()
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new(
            Url::parse("https://redirect/here").unwrap(),
        ));

    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .add_extra_param("foo", "bar")
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc&foo=bar",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 400,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"error\": \"invalid_request\", \
                       \"error_description\": \"stuff happened\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ));

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
                "StandardErrorResponse { error: invalid_request, \
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
        "ServerResponse(StandardErrorResponse { error: invalid_request, \
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
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "broken json".to_string().into_bytes(),
            },
        ));

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
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 200,
                headers: vec![
                    ("authorization".to_string(), "YWFhOmJiYg==".to_string()),
                    ("content-type".to_string(), "text/plain".to_string()),
                ],
                body: "broken json".to_string().into_bytes(),
            },
        ));

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
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        None,
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\"access_token\": \"12/34\", \"token_type\": \"magic\"}"
                    .to_string()
                    .into_bytes(),
            },
        ));

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
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 400,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: body.to_string().into_bytes(),
            },
        ));

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
        AuthUrl::new(Url::parse("https://auth").unwrap()),
        Some(TokenUrl::new(Url::parse("https://token").unwrap())),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(|_| Err(FakeError::Err));

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Request(FakeError::Err) => (),
        other => panic!("Unexpected error: {:?}", other),
    }
}

mod colorful_extension {
    extern crate serde_json;

    use oauth2::*;
    use std::fmt::Error as FormatterError;
    use std::fmt::{Debug, Display, Formatter};

    pub type ColorfulClient = Client<
        StandardErrorResponse<ColorfulErrorResponseType>,
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
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\"access_token\": \"12/34\", \"token_type\": \"green\", \"height\": 10}"
                    .to_string()
                    .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    )
    .set_auth_type(oauth2::AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![("Accept", "application/json")],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb",
            HttpResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"red\", \
                       \"scope\": \"read write\", \
                       \"expires_in\": 3600, \
                       \"refresh_token\": \"foobar\", \
                       \"shape\": \"round\", \
                       \"height\": 12\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

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
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 400,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\"error\": \"too_light\", \"error_description\": \"stuff happened\", \
                       \"error_uri\": \"https://errors\"}"
                    .to_string()
                    .into_bytes(),
            },
        ));

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
                oauth2::StandardErrorResponse<ColorfulErrorResponseType>,
            >(&serialized_json)
            .unwrap();
            assert_eq!(error_response, &deserialized_error);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Test Debug trait for RequestTokenError
    assert_eq!(
        "ServerResponse(StandardErrorResponse { error: too_light, \
         error_description: Some(\"stuff happened\"), error_uri: Some(\"https://errors\") })",
        format!("{:?}", token_err)
    );
    // Test Display trait for RequestTokenError
    assert_eq!(
        "Server returned error response `too_light: stuff happened / See https://errors`",
        format!("{}", token_err)
    );
}

mod custom_errors {
    use std::fmt::Error as FormatterError;
    use std::fmt::{Display, Formatter};

    extern crate serde_json;

    use colorful_extension::*;
    use oauth2::*;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct CustomErrorResponse {
        pub custom_error: String,
    }

    impl Display for CustomErrorResponse {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            write!(f, "Custom Error from server")
        }
    }

    impl ErrorResponse for CustomErrorResponse {}

    pub type CustomErrorClient = Client<
        CustomErrorResponse,
        StandardTokenResponse<ColorfulFields, ColorfulTokenType>,
        ColorfulTokenType,
    >;

}

#[test]
fn test_extension_with_custom_json_error() {
    use custom_errors::*;
    let client = CustomErrorClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new(Url::parse("https://example.com/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://example.com/token").unwrap(),
        )),
    );

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                ("Accept", "application/json"),
                ("Authorization", "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            HttpResponse {
                status_code: 400,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: "{\"custom_error\": \"non-compliant oauth implementation ;-)\"}"
                    .to_string()
                    .into_bytes(),
            },
        ));

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::ServerResponse(e) => {
            assert_eq!("non-compliant oauth implementation ;-)", e.custom_error)
        }
        e => panic!("failed to correctly parse custom server error, got {:?}", e),
    };
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
