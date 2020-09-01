use http::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::status::StatusCode;
use thiserror::Error;
use url::form_urlencoded::byte_serialize;
use url::Url;

use super::basic::*;
use super::devicecode::*;
use super::*;

fn new_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    )
}

fn mock_http_client(
    request_headers: Vec<(HeaderName, &'static str)>,
    request_body: &'static str,
    request_url: Option<Url>,
    response: HttpResponse,
) -> impl Fn(HttpRequest) -> Result<HttpResponse, FakeError> {
    move |request: HttpRequest| {
        assert_eq!(
            &request.url,
            request_url
                .as_ref()
                .unwrap_or(&Url::parse("https://example.com/token").unwrap())
        );
        assert_eq!(
            request.headers,
            request_headers
                .iter()
                .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
                .collect(),
        );
        assert_eq!(&String::from_utf8(request.body).unwrap(), request_body);

        Ok(response.clone())
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
        AuthUrl::new("https://example.com/auth?foo=bar".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
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
    let client = new_client()
        .set_redirect_url(RedirectUrl::new("https://localhost/redirect".to_string()).unwrap());

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

#[test]
fn test_authorize_url_with_redirect_url_override() {
    let client = new_client()
        .set_redirect_url(RedirectUrl::new("https://localhost/redirect".to_string()).unwrap());

    let (url, _) = client
        .authorize_url(|| CsrfToken::new("csrf_token".to_string()))
        .set_redirect_url(Cow::Owned(
            RedirectUrl::new("https://localhost/alternative".to_string()).unwrap(),
        ))
        .url();

    assert_eq!(
        Url::parse(
            "https://example.com/auth?response_type=code\
             &client_id=aaa\
             &state=csrf_token\
             &redirect_uri=https%3A%2F%2Flocalhost%2Falternative"
        )
        .unwrap(),
        url
    );
}

#[derive(Debug, Error)]
enum FakeError {
    #[error("error")]
    Err,
}

// Because the secret types don't implement PartialEq, we can't directly use == to compare tokens.
fn assert_token_eq<EF, TT>(a: &StandardTokenResponse<EF, TT>, b: &StandardTokenResponse<EF, TT>)
where
    EF: ExtraTokenFields + PartialEq,
    TT: TokenType,
{
    assert_eq!(a.access_token().secret(), b.access_token().secret());
    assert_eq!(a.token_type(), b.token_type());
    assert_eq!(a.expires_in(), b.expires_in());
    assert_eq!(
        a.refresh_token().map(RefreshToken::secret),
        b.refresh_token().map(RefreshToken::secret)
    );
    assert_eq!(a.scopes(), b.scopes());
    assert_eq!(a.extra_fields(), b.extra_fields());
}

#[test]
fn test_exchange_code_successful_with_minimal_json_response() {
    let client = BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
                body: "{\"access_token\": \"12/34\", \"token_type\": \"BEARER\"}"
                    .to_string()
                    .into_bytes(),
            },
        ))
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"bearer\"}".to_string(),
        serialized_json
    );

    let deserialized_token = serde_json::from_str::<BasicTokenResponse>(&serialized_json).unwrap();
    assert_token_eq(&token, &deserialized_token);
}

#[test]
fn test_exchange_code_successful_with_complete_json_response() {
    let client = new_client().set_auth_type(AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
            ],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert_token_eq(&token, &deserialized_token);
}

#[test]
fn test_exchange_client_credentials_with_basic_auth() {
    let client = BasicClient::new(
        ClientId::new("aaa/;&".to_string()),
        Some(ClientSecret::new("bbb/;&".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    )
    .set_auth_type(AuthType::BasicAuth);
    let token = client
        .exchange_client_credentials()
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhJTJGJTNCJTI2OmJiYiUyRiUzQiUyNg=="),
            ],
            "grant_type=client_credentials",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_client_credentials_with_body_auth_and_scope() {
    let client = new_client().set_auth_type(AuthType::RequestBody);
    let token = client
        .exchange_client_credentials()
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
            ],
            "grant_type=client_credentials&scope=read+write&client_id=aaa&client_secret=bbb",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("APPLICATION/jSoN").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_refresh_token_with_basic_auth() {
    let client = new_client().set_auth_type(AuthType::BasicAuth);
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_refresh_token_with_json_response() {
    let client = new_client();
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
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
    assert!(token.refresh_token().is_none());
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
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=password&username=user&password=pass&scope=read+write",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_code_successful_with_redirect_url() {
    let client = new_client()
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_url(RedirectUrl::new("https://redirect/here".to_string()).unwrap());

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
            ],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb&\
             redirect_uri=https%3A%2F%2Fredirect%2Fhere",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_code_successful_with_basic_auth() {
    let client = new_client()
        .set_auth_type(AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new("https://redirect/here".to_string()).unwrap());

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc&redirect_uri=https%3A%2F%2Fredirect%2Fhere",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_code_successful_with_pkce_and_extension() {
    let client = new_client()
        .set_auth_type(AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new("https://redirect/here".to_string()).unwrap());

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        ))
        .add_extra_param("foo", "bar")
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code\
             &code=ccc\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &redirect_uri=https%3A%2F%2Fredirect%2Fhere\
             &foo=bar",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_refresh_token_successful_with_extension() {
    let client = new_client()
        .set_auth_type(AuthType::BasicAuth)
        .set_redirect_url(RedirectUrl::new("https://redirect/here".to_string()).unwrap());

    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .add_extra_param("foo", "bar")
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc&foo=bar",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_code_with_simple_json_error() {
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert_eq!("Server returned error response", format!("{}", token_err));
}

#[test]
fn test_exchange_code_with_json_parse_error() {
    let client = new_client();
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(CONTENT_TYPE, HeaderValue::from_str("text/plain").unwrap())]
                    .into_iter()
                    .collect(),
                body: "broken json".to_string().into_bytes(),
            },
        ));

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Other(error_str) => {
            assert_eq!(
                "Unexpected response Content-Type: \"text/plain\", should be `application/json`",
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
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    );

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\"access_token\": \"12/34\", \"token_type\": 123}"
                    .to_string()
                    .into_bytes(),
            },
        ));

    assert!(token.is_err());
    match token.err().unwrap() {
        RequestTokenError::Parse(json_err, _) => {
            assert_eq!(1, json_err.line());
            assert_eq!(43, json_err.column());
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
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
        AuthUrl::new("https://auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://token".to_string()).unwrap()),
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

    use super::super::*;
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
                ColorfulErrorResponseType::TooDark => "too_dark",
                ColorfulErrorResponseType::TooLight => "too_light",
                ColorfulErrorResponseType::WrongColorSpace => "wrong_color_space",
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
    use self::colorful_extension::*;
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\"access_token\": \"12/34\", \"token_type\": \"green\", \"height\": 10}"
                    .to_string()
                    .into_bytes(),
            },
        ))
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(ColorfulTokenType::Green, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
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
    assert_token_eq(&token, &deserialized_token);
}

#[test]
fn test_extension_successful_with_complete_json_response() {
    use self::colorful_extension::*;
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    )
    .set_auth_type(AuthType::RequestBody);
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
            ],
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    assert_token_eq(&token, &deserialized_token);
}

#[test]
fn test_extension_with_simple_json_error() {
    use self::colorful_extension::*;
    let client = ColorfulClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    );
    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
                StandardErrorResponse<ColorfulErrorResponseType>,
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
    assert_eq!("Server returned error response", format!("{}", token_err));
}

mod custom_errors {
    use std::fmt::Error as FormatterError;
    use std::fmt::{Display, Formatter};

    extern crate serde_json;

    use super::super::*;
    use super::colorful_extension::*;

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
    use self::custom_errors::*;
    let client = CustomErrorClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    );

    let token = client
        .exchange_code(AuthorizationCode::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=authorization_code&code=ccc",
            None,
            HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
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
    use self::colorful_extension::{ColorfulFields, ColorfulTokenResponse, ColorfulTokenType};
    let mut token_response = ColorfulTokenResponse::new(
        AccessToken::new("mysecret".to_string()),
        ColorfulTokenType::Red,
        ColorfulFields {
            shape: Some("circle".to_string()),
            height: 10,
        },
    );
    token_response.set_expires_in(Some(&Duration::from_secs(3600)));
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

fn new_device_auth_details(expires_in: u32) -> DeviceAuthorizationResponse {
    let body = format!(
        "{{\
        \"device_code\": \"12345\", \
        \"verification_uri\": \"https://verify/here\", \
        \"user_code\": \"abcde\", \
        \"verification_uri_complete\": \"https://verify/here?abcde\", \
        \"expires_in\": {}, \
        \"interval\": 1 \
        }}",
        expires_in
    );

    let device_auth_url =
        DeviceAuthorizationUrl::new("https://deviceauth/here".to_string()).unwrap();

    let client = new_client().set_device_authorization_url(device_auth_url.clone());
    client
        .exchange_device_code()
        .add_extra_param("foo", "bar")
        .add_scope(Scope::new("openid".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "scope=openid&foo=bar",
            Some(device_auth_url.url().to_owned()),
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: body.into_bytes(),
            },
        ))
        .unwrap()
}

#[test]
fn test_exchange_device_code_and_token() {
    let details = new_device_auth_details(3600);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(3600), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            None,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"access_token\": \"12/34\", \
                    \"token_type\": \"bearer\", \
                    \"scope\": \"openid\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        std::thread::sleep)
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![Scope::new("openid".to_string()),]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_device_token_authorization_timeout() {
    let details = new_device_auth_details(2);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(2), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            None,
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"authorization_pending\", \
                    \"error_description\": \"Still waiting for user\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        std::thread::sleep)
        .err()
        .unwrap();
    match token {
        RequestTokenError::Other(msg) => assert_eq!(msg, "Device code expired"),
        _ => unreachable!("Error should be an expiry"),
    }
}

#[test]
fn test_send_sync_impl() {
    fn is_sync_and_send<T: Sync + Send>() {};
    #[derive(Debug)]
    struct TestError;
    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestError")
        }
    }
    impl std::error::Error for TestError {}

    is_sync_and_send::<AccessToken>();
    is_sync_and_send::<AuthUrl>();
    is_sync_and_send::<AuthorizationCode>();
    is_sync_and_send::<AuthorizationRequest>();
    is_sync_and_send::<
        Client<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<
        ClientCredentialsTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<ClientId>();
    is_sync_and_send::<ClientSecret>();
    is_sync_and_send::<
        CodeTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<CsrfToken>();
    is_sync_and_send::<EmptyExtraTokenFields>();
    is_sync_and_send::<HttpRequest>();
    is_sync_and_send::<HttpResponse>();
    is_sync_and_send::<
        PasswordTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<PkceCodeChallenge>();
    is_sync_and_send::<PkceCodeChallengeMethod>();
    is_sync_and_send::<PkceCodeVerifier>();
    is_sync_and_send::<RedirectUrl>();
    is_sync_and_send::<RefreshToken>();
    is_sync_and_send::<
        RefreshTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<ResourceOwnerPassword>();
    is_sync_and_send::<ResourceOwnerUsername>();
    is_sync_and_send::<ResponseType>();
    is_sync_and_send::<Scope>();
    is_sync_and_send::<StandardErrorResponse<BasicErrorResponseType>>();
    is_sync_and_send::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>();
    is_sync_and_send::<TokenUrl>();

    is_sync_and_send::<AuthType>();
    is_sync_and_send::<BasicErrorResponseType>();
    is_sync_and_send::<BasicTokenType>();
    is_sync_and_send::<RequestTokenError<TestError, StandardErrorResponse<BasicErrorResponseType>>>(
    );

    is_sync_and_send::<DeviceCode>();
    is_sync_and_send::<EndUserVerificationUrl>();
    is_sync_and_send::<UserCode>();
    is_sync_and_send::<DeviceAuthorizationUrl>();
    is_sync_and_send::<DeviceAuthorizationResponse>();
    is_sync_and_send::<
        DeviceAccessTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<DeviceAuthorizationRequest<StandardErrorResponse<BasicErrorResponseType>>>();
    is_sync_and_send::<DeviceCodeAction<HttpResponse>>();
    is_sync_and_send::<DeviceCodeErrorResponseType>();
    is_sync_and_send::<DeviceCodeErrorResponse>();

    #[cfg(feature = "curl")]
    is_sync_and_send::<super::curl::Error>();
    #[cfg(feature = "reqwest-010")]
    is_sync_and_send::<super::reqwest::Error<TestError>>();
}
