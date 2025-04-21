//!
//! This example showcases the Github OAuth2 device flow process for requesting access to the user's public and private repos.
//!
//! Before running it, you'll need to generate your own Github OAuth2 credentials.
//!
//! In order to run the example, call:
//!
//! ```sh
//! GITHUB_CLIENT_ID=xxx cargo run --example github_devicecode_async
//! ```
//!
//! ...and follow the instructions.
//!
//! Note that this example does not require a client secret, making it useful 
//! for building local applications that require Github auth.
//!

use oauth2::basic::BasicClient;
use oauth2::{
    reqwest, DeviceAuthorizationResponse, DeviceAuthorizationUrl,
    EmptyExtraDeviceAuthorizationFields,
};
use oauth2::{
    AuthUrl, ClientId, Scope,
    TokenUrl,
};
use url::Url;

use std::env;

#[tokio::main]
async fn main() {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build client");

    let client = BasicClient::new(github_client_id)
        .set_auth_uri(AuthUrl::from_url(
            Url::parse("https://github.com/login/oauth/authorize").unwrap(),
        ))
        .set_token_uri(TokenUrl::from_url(
            Url::parse("https://github.com/login/oauth/access_token").unwrap(),
        ))
        .set_device_authorization_url(DeviceAuthorizationUrl::from_url(
            Url::parse("https://github.com/login/device/code").unwrap(),
        ));

    let details: DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields> = client
        .exchange_device_code()
        .add_scope(Scope::new("repo".into()))
        .request_async(&http_client)
        .await
        .unwrap();

    println!("{:?}", details);

    let verify_url = details.verification_uri().to_string();
    let user_code = details.user_code().secret();

    println!("Open {} and enter code {}", verify_url, user_code);

    let token = client
        .exchange_device_access_token(&details)
        .request_async(&http_client, tokio::time::sleep, None)
        .await.unwrap();

    println!("{:?}", token);
}
