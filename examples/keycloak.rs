use oauth2::basic::{BasicClient};

// Alternatively, this can be `oauth2::curl::http_client` or a custom client.
use oauth2::reqwest::http_client;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, TokenResponse, TokenUrl, IntrospectUrl};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let client_id = ClientId::new(String::from("test-client"));
    let client_secret = ClientSecret::new(String::from("a7c61ec7-43ff-4e28-9b00-a1c78d14c5ff"));
    let auth_url = AuthUrl::new(String::from("http://127.0.0.1:8080/auth/realms/test-realm/protocol/openid-connect/auth"))?;
    let token_url = TokenUrl::new(String::from("http://127.0.0.1:8080/auth/realms/test-realm/protocol/openid-connect/token"))?;

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_url(
        RedirectUrl::new("http://localhost:9999".to_string()).expect("Invalid redirect URL"),
    )
    .set_introspection_url(
        IntrospectUrl::new("http://127.0.0.1:8080/auth/realms/test-realm/protocol/openid-connect/token/introspect".to_string()).expect("Invalid introspect URL")
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .url();

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("localhost:9999").unwrap();
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

            println!("Keycloak returned the following code:\n{}\n", code.secret());
            println!(
                "Keycloak returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_res = client.exchange_code(code).request(http_client);

            println!("Keycloak returned the following token:\n{:?}\n", token_res);

            if let Ok(token) = token_res {
                // NB: Github returns a single comma-separated "scope" parameter instead of multiple
                // space-separated scopes. Github-specific clients can parse this scope into
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
                println!("Keycloak returned the following scopes:\n{:?}\n", scopes);

                let access_token = token.access_token();
                println!("Access token: {}", access_token.secret());

                let token_inspection_response = client.introspect(&access_token).request(http_client);
                println!("Token inspection response: {:#?}", token_inspection_response);
            }

            // The server will terminate itself after collecting the first code.
            break;
        }
    }

    Ok(())
}
