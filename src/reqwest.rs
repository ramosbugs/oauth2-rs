use thiserror::Error;

/// Error type returned by failed reqwest HTTP requests.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Error returned by reqwest crate.
    #[error("request failed")]
    Reqwest(#[from] reqwest::Error),
    /// Non-reqwest HTTP error.
    #[error("HTTP error")]
    Http(#[from] http::Error),
    /// I/O error.
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

#[cfg(not(target_arch = "wasm32"))]
pub use blocking::http_client;

pub use async_client::async_http_client;

#[cfg(not(target_arch = "wasm32"))]
mod blocking {
    use super::super::{HttpRequest, HttpResponse};
    use super::Error;

    pub use reqwest;
    use reqwest::blocking;
    use reqwest::redirect::Policy as RedirectPolicy;

    use std::io::Read;

    /// Synchronous HTTP client.
    pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
        let client = blocking::Client::builder()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(RedirectPolicy::none())
            .build()?;

        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);

        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let mut response = client.execute(request_builder.build()?)?;

        let mut body = Vec::new();
        response.read_to_end(&mut body)?;

        Ok(HttpResponse {
            status_code: response.status(),
            headers: response.headers().to_owned(),
            body,
        })
    }
}

mod async_client {
    use super::super::{HttpRequest, HttpResponse};
    use super::Error;

    pub use reqwest;

    /// Asynchronous HTTP client.
    pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
        let client = {
            let builder = reqwest::Client::builder();

            // Following redirects opens the client up to SSRF vulnerabilities.
            // but this is not possible to prevent on wasm targets
            #[cfg(not(target_arch = "wasm32"))]
            let builder = builder.redirect(reqwest::redirect::Policy::none());

            builder.build()?
        };

        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);
        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let request = request_builder.build()?;

        let response = client.execute(request).await?;

        let status_code = response.status();
        let headers = response.headers().to_owned();
        let chunks = response.bytes().await?;
        Ok(HttpResponse {
            status_code,
            headers,
            body: chunks.to_vec(),
        })
    }
}
