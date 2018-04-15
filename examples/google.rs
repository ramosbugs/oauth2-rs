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

use oauth2::basic::BasicClient;
use rand::{thread_rng, Rng};
use std::env;
use std::net::TcpListener;
use std::io::{BufRead, BufReader, Write};
use url::Url;

fn main() {
    let google_client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable.");
    let google_client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing the GOOGLE_CLIENT_SECRET environment variable.");
    let auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
    let token_url = "https://www.googleapis.com/oauth2/v3/token";

    // Set up the config for the Google OAuth2 process.
    let client =
        BasicClient::new(google_client_id, Some(google_client_secret), auth_url, token_url)
            .expect("failed to create client")
            // This example is requesting access to the "calendar" features and the user's profile.
            .add_scope("https://www.googleapis.com/auth/calendar")
            .add_scope("https://www.googleapis.com/auth/plus.me")

            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_url("http://localhost:8080");

    let mut rng = thread_rng();
    // Generate a 128-bit random string for CSRF protection (each time!).
    let random_bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    let csrf_state = base64::encode(&random_bytes);

    // Generate the authorization URL to which we'll redirect the user.
    let authorize_url = client.authorize_url(csrf_state.clone());

    println!("Open this URL in your browser:\n{}\n", authorize_url.to_string());

    // These variables will store the code & state retrieved during the authorization process.
    let mut code = String::new();
    let mut state = String::new();

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
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
                    code = value.into_owned();

                    let state_pair = url.query_pairs().find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    }).unwrap();

                    let (_, value) = state_pair;
                    state = value.into_owned();
                }

                let message = "Go back to your terminal :)";
                let response = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}", message.len(), message);
                stream.write_all(response.as_bytes()).unwrap();

                // The server will terminate itself after collecting the first code.
                break;
            }
            Err(_) => {},
        }
    };

    println!("Google returned the following code:\n{}\n", code);
    println!("Google returned the following state:\n{} (expected `{}`)\n", state, csrf_state);

    // Exchange the code with a token.
    let token = client.exchange_code(code);

    println!("Google returned the following token:\n{:?}\n", token);
}
