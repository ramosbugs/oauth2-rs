//!
//! This example showcases the Github OAuth2 process for requesting access to the user's public repos and
//! email address.
//!
//! Before running it, you'll need to generate your own Github OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GITHUB_CLIENT_ID=xxx GITHUB_CLIENT_SECRET=yyy cargo run --example github
//! ```
//!
//! ...and follow the instructions.
//!

extern crate url;
extern crate oauth2;

use std::env;
use std::net::TcpListener;
use std::io::{BufRead, BufReader, Write};
use url::Url;
use oauth2::Config;

fn main() {
    let github_client_id = env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable.");
    let github_client_secret = env::var("GITHUB_CLIENT_SECRET").expect("Missing the GITHUB_CLIENT_SECRET environment variable.");
    let auth_url = "https://github.com/login/oauth/authorize";
    let token_url = "https://github.com/login/oauth/access_token";

    // Set up the config for the Github OAuth2 process.
    let mut config = Config::new(github_client_id, github_client_secret, auth_url, token_url);

    // This example is requesting access to the user's public repos and email.
    config = config.add_scope("public_repo");
    config = config.add_scope("user:email");

    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    config = config.set_redirect_url("http://localhost:8080");

    // Set the state parameter (optional)
    config = config.set_state("1234");

    // Generate the authorization URL to which we'll redirect the user.
    let authorize_url = config.authorize_url();

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

    println!("Github returned the following code:\n{}\n", code);
    println!("Github returned the following state:\n{}\n", state);

    // Exchange the code with a token.
    let token = config.exchange_code(code);

    println!("Github returned the following token:\n{:?}\n", token);
}
