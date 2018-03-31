extern crate mockito;
extern crate url;
extern crate oauth2;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

use mockito::{mock, SERVER_URL};
use oauth2::{Token, RequestTokenError};
use oauth2::basic::*;
use url::Url;

#[test]
fn test_authorize_url() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap();

    let url = client.authorize_url("csrf_token".to_string());

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code&client_id=aaa&state=csrf_token"
        ).unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_insecure() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap();

    let url = oauth2::insecure::authorize_url(&client);

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=code&client_id=aaa").unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_implicit() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap();

    let url = client.authorize_url_implicit("csrf_token".to_string());

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=token&client_id=aaa&state=csrf_token"
        ).unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_implicit_insecure() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap();

    let url = oauth2::insecure::authorize_url_implicit(&client);

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=token&client_id=aaa").unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_param() {
    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth?foo=bar",
            "http://example.com/token"
        ).unwrap();

    let url = client.authorize_url("csrf_token".to_string());

    assert_eq!(
        Url::parse(
            "http://example.com/auth?foo=bar&response_type=code&client_id=aaa&state=csrf_token"
        ).unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_scopes() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap()
            .add_scope("read")
            .add_scope("write");

    let url = client.authorize_url("csrf_token".to_string());

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code&client_id=aaa&scope=read+write&\
            state=csrf_token"
        ).unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_extension_response_type() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap();

    let url = client.authorize_url_extension("code token", vec![("foo", "bar")]);

    assert_eq!(
        Url::parse("http://example.com/auth?response_type=code+token&client_id=aaa&foo=bar")
            .unwrap(),
        url
    );
}

#[test]
fn test_authorize_url_with_redirect_url() {
    let client =
        BasicClient::new("aaa", Some("bbb"), "http://example.com/auth", "http://example.com/token")
            .unwrap()
            .set_redirect_url("http://localhost/redirect");

    let url = client.authorize_url("csrf_token".to_string());

    assert_eq!(
        Url::parse(
            "http://example.com/auth?response_type=code&client_id=aaa&redirect_uri=http\
             %3A%2F%2Flocalhost%2Fredirect&state=csrf_token"
        ).unwrap(),
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

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"bearer\",\"expires_in\":null,\
        \"refresh_token\":null,\"scope\":null}".to_string(),
        serialized_json
    );

    let deserialized_token = BasicToken::from_json(&serialized_json).unwrap();
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
              \"expires_in\": 3600, \"refresh_token\": \"foobar\"}")
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::RequestBody);
    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(3600, token.expires_in().unwrap().as_secs());
    assert_eq!(Some("foobar".to_string()), *token.refresh_token());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"bearer\",\"expires_in\":3600,\
        \"refresh_token\":\"foobar\",\"scope\":\"read write\"}".to_string(),
        serialized_json
    );

    let deserialized_token = BasicToken::from_json(&serialized_json).unwrap();
    assert_eq!(token, deserialized_token);
}

#[test]
fn test_exchange_client_credentials_with_basic_auth() {
    let mock = mock("POST", "/token")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=client_credentials")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client.exchange_client_credentials().unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
}

#[test]
fn test_exchange_client_credentials_with_body_auth_and_scope() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body(
            "grant_type=client_credentials&scope=read+write&client_id=aaa&client_secret=bbb"
        )
        // Ensure we parse headers case insensitively.
        .with_header("content-TYPE", "APPLICATION/jSoN")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::RequestBody)
            .add_scope("read")
            .add_scope("write");
    let token = client.exchange_client_credentials().unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
}

#[test]
fn test_exchange_refresh_token_with_basic_auth() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=refresh_token&refresh_token=ccc")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::BasicAuth);
    let token = client.exchange_refresh_token("ccc").unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
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
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap();
    let token = client.exchange_refresh_token("ccc").unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
}

#[test]
fn test_exchange_password_with_json_response() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=password&username=user&password=pass")
        .with_header("content-type", "application/json")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap();
    let token = client.exchange_password("user", "pass").unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
}

#[test]
fn test_exchange_code_successful_with_redirect_url() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_body(
            "grant_type=authorization_code&code=ccc&client_id=aaa&client_secret=bbb&redirect_uri=\
            http%3A%2F%2Fredirect"
        )
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_redirect_url("http://redirect");

    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
}

#[test]
fn test_exchange_code_successful_with_basic_auth() {
    let mock = mock("POST", "/token")
        .match_header("Accept", "application/json")
        .match_header("Authorization", "Basic YWFhOmJiYg==") // base64("aaa:bbb")
        .match_body("grant_type=authorization_code&code=ccc&redirect_uri=http%3A%2F%2Fredirect")
        .with_body(
            "{\"access_token\": \"12/34\", \"token_type\": \"bearer\", \"scope\": \"read write\"}"
        )
        .create();

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::BasicAuth)
            .set_redirect_url("http://redirect");

    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
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

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());

    let token_err = token.err().unwrap();
    match &token_err {
        &RequestTokenError::ServerResponse(ref error_response) => {
            assert_eq!(BasicErrorResponseType::InvalidRequest, *error_response.error());
            assert_eq!(Some("stuff happened".to_string()), *error_response.error_description());
            assert_eq!(None, *error_response.error_uri());

            // Test Debug trait for ErrorResponse
            assert_eq!(
                "ErrorResponse { _error: invalid_request, \
                _error_description: Some(\"stuff happened\"), _error_uri: None }",
                format!("{:?}", error_response)
            );
            // Test Display trait for ErrorResponse
            assert_eq!(
                "invalid_request: stuff happened",
                format!("{}", error_response)
            );

            // Test Debug trait for BasicErrorResponseType
            assert_eq!(
                "invalid_request",
                format!("{:?}", error_response.error())
            );
            // Test Display trait for BasicErrorResponseType
            assert_eq!(
                "invalid_request",
                format!("{}", error_response.error())
            );

            // Ensure that serialization produces an equivalent JSON value.
            let serialized_json = serde_json::to_string(&error_response).unwrap();
            assert_eq!(
                "{\"error\":\"invalid_request\",\"error_description\":\"stuff happened\",\
                \"error_uri\":null}".to_string(),
                serialized_json
            );

            let deserialized_error =
                serde_json::from_str::<BasicErrorResponse>(&serialized_json).unwrap();
            assert_eq!(error_response, &deserialized_error);
        },
        other => panic!("Unexpected error: {:?}", other),
    }

    // Test Debug trait for RequestTokenError
    assert_eq!(
        "ServerResponse(ErrorResponse { _error: invalid_request, \
        _error_description: Some(\"stuff happened\"), _error_uri: None })",
        format!("{:?}", token_err)
    );
    // Test Display trait for RequestTokenError
    assert_eq!(
        "Server response: invalid_request: stuff happened",
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

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Parse(json_err) => {
            assert_eq!(1, json_err.line());
            assert_eq!(1, json_err.column());
            assert_eq!(serde_json::error::Category::Syntax, json_err.classify());
        },
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

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::Other(error_str) => {
            assert_eq!(
                "Unexpected response Content-Type: `text/plain`, should be `application/json`",
                error_str
            );
        },
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

    let client =
        BasicClient::new::<_, &str, _, _>(
            "aaa",
            None,
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap();

    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());
    match token.err().unwrap() {
        RequestTokenError::Parse(json_err) => {
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

    let client =
        BasicClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());

    match token.err().unwrap() {
        RequestTokenError::ServerResponse(error_response) => {
            assert_eq!(BasicErrorResponseType::InvalidRequest, *error_response.error());
            assert_eq!(Some("Expired code.".to_string()), *error_response.error_description());
            assert_eq!(None, *error_response.error_uri());
        },
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_exchange_code_fails_gracefully_on_transport_error() {
    let client = BasicClient::new("aaa", Some("bbb"), "http://auth", "http://token").unwrap();
    let token = client.exchange_code("ccc".to_string());

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
    use oauth2::basic::BasicToken;
    use std::fmt::{Debug, Display, Formatter};
    use std::fmt::Error as FormatterError;
    use std::time::Duration;

    pub type ColorfulClient = Client<ColorfulTokenType, ColorfulToken, ColorfulErrorResponseType>;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ColorfulTokenType {
        Green,
        Red,
    }
    impl TokenType for ColorfulTokenType {}

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    pub struct ColorfulToken {
        #[serde(flatten)]
        _basic_token: BasicToken<ColorfulTokenType>,
        #[serde(rename = "shape")]
        _shape: Option<String>,
        #[serde(rename = "height")]
        _height: u32,
    }
    impl ColorfulToken {
        pub fn shape(&self) -> &Option<String> { &self._shape }
        pub fn height(&self) -> u32 { self._height }
    }

    impl Token<ColorfulTokenType> for ColorfulToken {
        fn access_token(&self) -> &str { &self._basic_token.access_token() }
        fn token_type(&self) -> &ColorfulTokenType { &self._basic_token.token_type() }
        fn expires_in(&self) -> Option<Duration> { self._basic_token.expires_in() }
        fn refresh_token(&self) -> &Option<String> { &self._basic_token.refresh_token() }
        fn scopes(&self) -> &Option<Vec<String>> { &self._basic_token.scopes() }

        fn from_json(data: &str) -> Result<Self, serde_json::error::Error> {
            serde_json::from_str(data)
        }
    }

    #[derive(Deserialize, PartialEq, Serialize)]
    #[serde(rename_all="snake_case")]
    pub enum ColorfulErrorResponseType {
        TooDark,
        TooLight,
        WrongColorSpace,
    }

    impl ErrorResponseType for ColorfulErrorResponseType {
        fn to_str(&self) -> &str {
            match self {
                &ColorfulErrorResponseType::TooDark => "too_dark",
                &ColorfulErrorResponseType::TooLight => "too_light",
                &ColorfulErrorResponseType::WrongColorSpace => "wrong_color_space",
            }
        }
    }

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

    let client =
        ColorfulClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(ColorfulTokenType::Green, *token.token_type());
    assert_eq!(None, token.expires_in());
    assert_eq!(None, *token.refresh_token());
    assert_eq!(None, *token.shape());
    assert_eq!(10, token.height());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"green\",\"expires_in\":null,\
        \"refresh_token\":null,\"scope\":null,\"shape\":null,\"height\":10}".to_string(),
        serialized_json
    );

    let deserialized_token = ColorfulToken::from_json(&serialized_json).unwrap();
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
              \"height\": 12}")
        .create();

    let client =
        ColorfulClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        )
            .unwrap()
            .set_auth_type(oauth2::AuthType::RequestBody);
    let token = client.exchange_code("ccc".to_string()).unwrap();

    mock.assert();

    assert_eq!("12/34", token.access_token());
    assert_eq!(ColorfulTokenType::Red, *token.token_type());
    assert_eq!(Some(vec!["read".to_string(), "write".to_string()]), *token.scopes());
    assert_eq!(3600, token.expires_in().unwrap().as_secs());
    assert_eq!(Some("foobar".to_string()), *token.refresh_token());
    assert_eq!(Some("round".to_string()), *token.shape());
    assert_eq!(12, token.height());

    // Ensure that serialization produces an equivalent JSON value.
    let serialized_json = serde_json::to_string(&token).unwrap();
    assert_eq!(
        "{\"access_token\":\"12/34\",\"token_type\":\"red\",\"expires_in\":3600,\
        \"refresh_token\":\"foobar\",\"scope\":\"read write\",\"shape\":\"round\",\"height\":12}"
            .to_string(),
        serialized_json
    );

    let deserialized_token = ColorfulToken::from_json(&serialized_json).unwrap();
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
              \"error_uri\": \"https://errors\"}")
        .create();

    let client =
        ColorfulClient::new(
            "aaa",
            Some("bbb"),
            "http://example.com/auth",
            &(SERVER_URL.to_string() + "/token")
        ).unwrap();
    let token = client.exchange_code("ccc".to_string());

    mock.assert();

    assert!(token.is_err());

    let token_err = token.err().unwrap();
    match &token_err {
        &RequestTokenError::ServerResponse(ref error_response) => {
            assert_eq!(
                ColorfulErrorResponseType::TooLight,
                *error_response.error()
            );
            assert_eq!(Some("stuff happened".to_string()), *error_response.error_description());
            assert_eq!(Some("https://errors".to_string()), *error_response.error_uri());

            // Ensure that serialization produces an equivalent JSON value.
            let serialized_json = serde_json::to_string(&error_response).unwrap();
            assert_eq!(
                "{\"error\":\"too_light\",\"error_description\":\"stuff happened\",\
                \"error_uri\":\"https://errors\"}".to_string(),
                serialized_json
            );

            let deserialized_error =
                serde_json::from_str::<oauth2::ErrorResponse<ColorfulErrorResponseType>>(
                    &serialized_json
                ).unwrap();
            assert_eq!(error_response, &deserialized_error);

        },
        other => panic!("Unexpected error: {:?}", other),
    }

    // Test Debug trait for RequestTokenError
    assert_eq!(
        "ServerResponse(ErrorResponse { _error: too_light, \
        _error_description: Some(\"stuff happened\"), _error_uri: Some(\"https://errors\") })",
        format!("{:?}", token_err)
    );
    // Test Display trait for RequestTokenError
    assert_eq!(
        "Server response: too_light: stuff happened / See https://errors",
        format!("{}", token_err)
    );
}
