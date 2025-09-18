//!
//! This example showcases the Twitch OAuth2 process for requesting access to the user's
//! email address and follows.
//!
//! Twitch's token response requires a custom implementation to extract the scopes, as it returns
//! them as a standard JSON array instead of a space-separated string as the spec expects.
//!
//! Before running it, you'll need to generate your own Twitch OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! TWITCH_CLIENT_ID=xxx TWITCH_CLIENT_SECRET=yyy cargo run --example twitch
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::AuthType::RequestBody;
use oauth2::{
    reqwest, AccessToken, Client, EmptyExtraTokenFields, EndpointNotSet, ExtraTokenFields,
    RefreshToken, StandardRevocableToken, TokenType,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use url::Url;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TwitchCustomTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    // Twitch returns scopes as a JSON array instead of the standard space-separated string.
    #[serde(rename = "scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,
    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}

impl<EF, TT> TokenResponse for TwitchCustomTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    type TokenType = TT;
    /// REQUIRED. The access token issued by the authorization server.
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    fn token_type(&self) -> &TT {
        &self.token_type
    }
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    /// Twitch returns scopes as a JSON array instead of the specified space-delimited field.
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

type TwitchTokenResponse = TwitchCustomTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

pub type TwitchClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    TwitchTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

fn main() {
    let twitch_client_id = ClientId::new(
        env::var("TWITCH_CLIENT_ID").expect("Missing the TWITCH_CLIENT_ID environment variable."),
    );
    let twitch_client_secret = ClientSecret::new(
        env::var("TWITCH_CLIENT_SECRET")
            .expect("Missing the TWITCH_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("https://id.twitch.tv/oauth2/authorize".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://id.twitch.tv/oauth2/token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Twitch OAuth2 process.
    let client = TwitchClient::new(twitch_client_id)
        .set_client_secret(twitch_client_secret)
        .set_auth_type(RequestBody)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
        );

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's email and follows.
        .add_scope(Scope::new("user:read:email".to_string()))
        .add_scope(Scope::new("user:read:follows".to_string()))
        .url();

    println!("Open this URL in your browser:\n{authorize_url}\n");

    let (code, state) = {
        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

        // The server will terminate itself after collecting the first code.
        let Some(mut stream) = listener.incoming().flatten().next() else {
            panic!("listener terminated without accepting a connection");
        };

        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
            .unwrap();

        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, state)| CsrfToken::new(state.into_owned()))
            .unwrap();

        let message = "Go back to your terminal :)";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).unwrap();

        (code, state)
    };

    println!("Twitch returned the following code:\n{}\n", code.secret());
    println!(
        "Twitch returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    let token_res = client.exchange_code(code).request(&http_client);

    println!("Twitch returned the following token:\n{token_res:?}\n");
}
