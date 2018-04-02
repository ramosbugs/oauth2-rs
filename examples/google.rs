//!
//! This example showcases the Google OAuth2 process for requesting access to the Google Calendar features
//! and the user's profile.
//!
//! Before running it, you'll need to generate your own Google OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy cargo run --example google
//! ```
//!
//! ...and follow the instructions.
//!

extern crate base64;
extern crate oauth2;
extern crate rand;
extern crate url;

use oauth2::*;
use oauth2::basic::BasicClient;
use rand::{thread_rng, Rng};
use std::env;
use std::net::TcpListener;
use std::io::{BufRead, BufReader, Write};
use url::Url;

fn main() {
    let google_client_id =
        ClientId::new(
            env::var("GOOGLE_CLIENT_ID")
                .expect("Missing the GOOGLE_CLIENT_ID environment variable.")
        );
    let google_client_secret =
        ClientSecret::new(
            env::var("GOOGLE_CLIENT_SECRET")
                .expect("Missing the GOOGLE_CLIENT_SECRET environment variable.")
        );
    let auth_url =
        AuthUrl::new(
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("Invalid authorization endpoint URL")
        );
    let token_url =
        TokenUrl::new(
            Url::parse("https://www.googleapis.com/oauth2/v3/token")
                .expect("Invalid token endpoint URL")
        );

    // Set up the config for the Google OAuth2 process.
    let client =
        BasicClient::new(google_client_id, Some(google_client_secret), auth_url, token_url)
            // This example is requesting access to the "calendar" features and the user's profile.
            .add_scope(Scope::new("https://www.googleapis.com/auth/calendar".to_string()))
            .add_scope(Scope::new("https://www.googleapis.com/auth/plus.me".to_string()))

            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_url(
                RedirectUrl::new(
                    Url::parse("http://localhost:8080")
                        .expect("Invalid redirect URL")
                )
            );

    let mut rng = thread_rng();
    // Generate a 128-bit random string for CSRF protection (each time!).
    let random_bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    let csrf_state = CsrfToken::new(base64::encode(&random_bytes));

    // Generate the authorization URL to which we'll redirect the user.
    let authorize_url = client.authorize_url(&csrf_state);

    println!("Open this URL in your browser:\n{}\n", authorize_url.to_string());

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
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

                let code_pair = url.query_pairs().find(|pair| {
                    let &(ref key, _) = pair;
                    key == "code"
                }).unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url.query_pairs().find(|pair| {
                    let &(ref key, _) = pair;
                    key == "state"
                }).unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}", message.len(), message);
            stream.write_all(response.as_bytes()).unwrap();

            println!("Google returned the following code:\n{}\n", code.secret());
            println!(
                "Google returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token = client.exchange_code(code);

            println!("Google returned the following token:\n{:?}\n", token);

            // The server will terminate itself after collecting the first code.
            break;
        }
    };
}
