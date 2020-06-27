use thiserror::Error;

///
/// Error type returned by failed reqwest HTTP requests.
///
#[derive(Debug, Error)]
pub enum Error<T>
where
    T: std::error::Error + 'static,
{
    /// Error returned by reqwest crate.
    #[error("request failed")]
    Reqwest(#[source] T),
    /// Non-reqwest HTTP error.
    #[error("HTTP error")]
    Http(#[source] http::Error),
    /// I/O error.
    #[error("I/O error")]
    Io(#[source] std::io::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
}

pub use blocking::http_client;
///
/// Error type returned by failed reqwest blocking HTTP requests.
///
pub type HttpClientError = Error<blocking::reqwest::Error>;

pub use async_client::async_http_client;

///
/// Error type returned by failed reqwest async HTTP requests.
///
pub type AsyncHttpClientError = Error<reqwest_0_10::Error>;

mod blocking {
    use super::super::{HttpRequest, HttpResponse};
    use super::Error;

    pub use reqwest_0_10 as reqwest;
    use reqwest_0_10::blocking;
    use reqwest_0_10::redirect::Policy as RedirectPolicy;

    use std::io::Read;

    ///
    /// Synchronous HTTP client.
    ///
    pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error<reqwest::Error>> {
        let client = blocking::Client::builder()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(RedirectPolicy::none())
            .build()
            .map_err(Error::Reqwest)?;

        #[cfg(feature = "reqwest-010")]
        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);

        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let mut response = client
            .execute(request_builder.build().map_err(Error::Reqwest)?)
            .map_err(Error::Reqwest)?;

        let mut body = Vec::new();
        response.read_to_end(&mut body).map_err(Error::Io)?;

        #[cfg(feature = "reqwest-010")]
        {
            let headers = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        http::header::HeaderName::from_bytes(name.as_str().as_ref())
                            .expect("failed to convert HeaderName from http 0.2 to 0.1"),
                        http::HeaderValue::from_bytes(value.as_bytes())
                            .expect("failed to convert HeaderValue from http 0.2 to 0.1"),
                    )
                })
                .collect::<http::HeaderMap>();
            Ok(HttpResponse {
                status_code: http::StatusCode::from_u16(response.status().as_u16())
                    .expect("failed to convert StatusCode from http 0.2 to 0.1"),
                headers,
                body,
            })
        }
    }
}

mod async_client {
    use super::super::{HttpRequest, HttpResponse};
    use super::Error;

    pub use reqwest_0_10 as reqwest;
    use reqwest_0_10::redirect::Policy as RediretPolicy;

    use http::header::HeaderName;
    use http::{HeaderMap, HeaderValue, StatusCode};

    ///
    /// Asynchronous HTTP client.
    ///
    pub async fn async_http_client(
        request: HttpRequest,
    ) -> Result<HttpResponse, Error<reqwest::Error>> {
        let client = reqwest::Client::builder()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(RediretPolicy::none())
            .build()
            .map_err(Error::Reqwest)?;

        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);
        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let request = request_builder.build().map_err(Error::Reqwest)?;

        let response = client.execute(request).await.map_err(Error::Reqwest)?;

        let status_code = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    HeaderName::from_bytes(name.as_str().as_ref())
                        .expect("failed to convert HeaderName from http 0.2 to 0.1"),
                    HeaderValue::from_bytes(value.as_bytes())
                        .expect("failed to convert HeaderValue from http 0.2 to 0.1"),
                )
            })
            .collect::<HeaderMap>();
        let chunks = response.bytes().await.map_err(Error::Reqwest)?;
        Ok(HttpResponse {
            status_code: StatusCode::from_u16(status_code.as_u16())
                .expect("failed to convert StatusCode from http 0.2 to 0.1"),
            headers,
            body: chunks.to_vec(),
        })
    }
}
