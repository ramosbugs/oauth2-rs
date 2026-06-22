//!
//! This example registers an OAuth 2.0 client dynamically per
//! [RFC 7591](https://tools.ietf.org/html/rfc7591).
//!
//! You need an authorization server that exposes a client registration endpoint. Many servers
//! require HTTPS and either allow open registration or an initial access token for protected
//! registration.
//!
//! In order to run the example call:
//!
//! ```sh
//! DCR_REGISTRATION_URL=https://server.example.com/register \
//! DCR_CLIENT_NAME="My Example Client" \
//! DCR_REDIRECT_URI=http://localhost:8080/callback \
//! cargo run --example dynamic_client_registration
//! ```
//!
//! For protected registration, also provide an initial access token:
//!
//! ```sh
//! DCR_INITIAL_ACCESS_TOKEN=eyJhbGciOi... \
//! DCR_REGISTRATION_URL=https://server.example.com/register \
//! DCR_CLIENT_NAME="My Example Client" \
//! cargo run --example dynamic_client_registration
//! ```

use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AccessToken, ClientName, DynamicClientRegistrationUrl, RedirectUrl, ResponseType, Scope,
};

use std::env;

fn main() {
    let registration_url = DynamicClientRegistrationUrl::new(
        env::var("DCR_REGISTRATION_URL")
            .expect("Missing the DCR_REGISTRATION_URL environment variable."),
    )
    .expect("Invalid client registration endpoint URL");

    let client_name = ClientName::new(
        env::var("DCR_CLIENT_NAME").unwrap_or_else(|_| "oauth2-rs DCR Example Client".to_string()),
    );

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let mut request = BasicClient::dynamic_client(client_name, &registration_url)
        .add_grant_type("authorization_code")
        .add_response_type(ResponseType::new("code".to_string()))
        .set_token_endpoint_auth_method("client_secret_basic");

    if let Ok(redirect_uri) = env::var("DCR_REDIRECT_URI") {
        request = request.add_redirect_uri(
            RedirectUrl::new(redirect_uri).expect("Invalid DCR_REDIRECT_URI value"),
        );
    }

    if let Ok(scope) = env::var("DCR_SCOPE") {
        request = request.set_scope(Scope::new(scope));
    }

    if let Ok(token) = env::var("DCR_INITIAL_ACCESS_TOKEN") {
        request = request.set_initial_access_token(AccessToken::new(token));
    }

    let client = request
        .register(&http_client)
        .expect("Failed to register client");

    println!("Registered client_id: {:?}", client.client_id());
}
