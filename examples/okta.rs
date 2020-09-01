//!
//! This example showcases the Okta OAuth2 process for requesting access to the user's public repos and
//! email address.
//!
//! Before running it, you'll need to generate your own Okta OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! OKTA_APP_HOST=xxx OKTA_CLIENT_ID=xxx OKTA_CLIENT_SECRET=yyy cargo run --example okta
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::basic::BasicClient;

// Alternatively, this can be `oauth2::curl::http_client` or a custom client.
use oauth2::reqwest::http_client;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl, AccessToken};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

const AUTH_URL:&str = 		"oauth2/default/v1/authorize";
const TOKEN_URL:&str = 		"oauth2/default/v1/token";
const REDIRECT_URL:&str = 	"http://127.0.0.1:8080/auth";
const THIS_HOST:&str = 		"127.0.0.1:8080";

fn main() {

	// load environment variables
    let okta_client_id = ClientId::new(
		env::var("OKTA_CLIENT_ID")
			.expect("Missing the OKTA_CLIENT_ID environment variable."), );
    let okta_client_secret = ClientSecret::new(
		env::var("OKTA_CLIENT_SECRET")
			.expect("Missing the OKTA_CLIENT_SECRET environment variable."), );
	let okta_client_host = env::var("OKTA_APP_HOST")
		.expect("Missing the OKTA_APP_HOST environment variable.");

    // let auth_url = AuthUrl::new(AUTH_URL.to_string())
	let auth_url = AuthUrl::new(format!("https://{}/{}", okta_client_host, AUTH_URL))
        .expect("Invalid authorization endpoint URL");
    //let token_url = TokenUrl::new(TOKEN_URL.to_string())
	let token_url = TokenUrl::new(format!("https://{}/{}", okta_client_host.as_str(), TOKEN_URL))
        .expect("Invalid token endpoint URL");

    // Set up the config for the Okta OAuth2 process.
    let client = BasicClient::new(
		okta_client_id,
		Some(okta_client_secret),
		auth_url,
		Some(token_url),
    )

    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_url(
        RedirectUrl::new(REDIRECT_URL.to_string()).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        // .add_scope(Scope::new("public_repo".to_string()))
        // .add_scope(Scope::new("user:email".to_string()))
		.add_scope(Scope::new("openid".to_string()))
		.add_scope(Scope::new("email".to_string()))
		.add_scope(Scope::new("profile".to_string()))
		.url();

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind(THIS_HOST.to_string()).unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Okta returned the following code:\n{}\n", code.secret());
            println!(
                "Okta returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_res = client.exchange_code(code).request(http_client);

            println!("Okta returned the following token:\n{:?}\n", token_res);

            if let Ok(token) = &token_res {

				// Danger: "Leaking this value may compromise the security of the OAuth2 flow."
				println!("Token: \n{}\n", &token.access_token().secret());

				// Same for Okta:
				// NB: [Github] returns a single comma-separated "scope" parameter instead of multiple
                // space-separated scopes. Okta-specific clients can parse this scope into
                // multiple scopes by splitting at the commas. Note that it's not safe for the
                // library to do this by default because RFC 6749 allows scopes to contain commas.
                let scopes = if let Some(scopes_vec) = token.scopes() {
                    scopes_vec
                        .iter()
                        .map(|comma_separated| comma_separated.split(','))
                        .flatten()
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                println!("Okta returned the following scopes:\n{:?}\n", scopes);
            }

            // The server will terminate itself after collecting the first code.
            break;
        }
    }
}
