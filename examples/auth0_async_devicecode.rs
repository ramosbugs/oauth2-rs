//!
//! This example showcases the Auth0 device authorization flow using the async methods.
//!
//! Before running it, you'll need to create an API and an Application on [auth0.com](https://auth0.com). Take a look at this tutorial, for the details: [Call Your API Using the Device Authorization Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow/call-your-api-using-the-device-authorization-flow).
//!
//! In order to run the example call:
//!
//! ```sh
//! AUTH0_CLIENT_ID=xxx AUTH0_AUDIENCE=<your_api_identifier> AUTH_URL=yyy TOKEN_URL=zzz DEVICE_CODE_URL=abc cargo run --example auth0_async_devicecode
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::reqwest::async_http_client;
use oauth2::{AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenUrl};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth0_client_id = ClientId::new(
        env::var("AUTH0_CLIENT_ID").expect("Missing the AUTH0_CLIENT_ID environment variable."),
    );
    let audience: String =
        env::var("AUTH0_AUDIENCE").expect("MISSING AUTH0_AUDIENCE environment variable.");
    let auth_url =
        AuthUrl::new(env::var("AUTH_URL").expect("MISSING AUTH_URL environment variable."))
            .expect("Invalid authorization endpoint URL");
    let token_url =
        TokenUrl::new(env::var("TOKEN_URL").expect("MISSING TOKEN_URL environment variable."))
            .expect("Invalid token endpoint URL");
    let device_auth_url = DeviceAuthorizationUrl::new(
        env::var("DEVICE_CODE_URL").expect("MISSING DEVICE_CODE_URL environment variable."),
    )
    .expect("Invalid device authorization endpoint URL");

    // Set up the config for the Auth0 OAuth2 process.
    //
    // Auth0's OAuth endpoint expects the client_id to be in the request body,
    // so ensure that option is set.
    let device_client = BasicClient::new(auth0_client_id, None, auth_url, Some(token_url))
        .set_device_authorization_url(device_auth_url)
        .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: StandardDeviceAuthorizationResponse = device_client
        .exchange_device_code()
        .unwrap()
        .add_scope(Scope::new("profile".to_string()))
        .add_extra_param("audience".to_string(), audience) // This is a required parameter
        .request_async(async_http_client)
        .await?;

    // Display the URL and user-code.
    println!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        details.verification_uri().to_string(),
        details.user_code().secret().to_string()
    );

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request_async(
            async_http_client,
            |dur| async move {
                let _ = tokio::time::sleep(dur).await;
            },
            None,
        )
        .await?;

    println!("Auth0 returned the following token:\n{:?}\n", token);

    Ok(())
}
