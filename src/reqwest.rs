use std::io::Read;

use failure::Fail;
#[cfg(feature = "futures-01")]
use futures_0_1::{Future, IntoFuture, Stream};

#[cfg(feature = "futures-01")]
use reqwest::r#async::Client as AsyncClient;
#[cfg(feature = "futures-01")]
use reqwest as blocking;
#[cfg(feature = "futures-01")]
use reqwest;
#[cfg(feature = "futures-01")]
use reqwest::RedirectPolicy;

#[cfg(feature = "futures-03")]
use reqwest_futures_03::blocking;
#[cfg(feature = "futures-03")]
use reqwest_futures_03::{Client, RedirectPolicy};
#[cfg(feature = "futures-03")]
use reqwest_futures_03 as reqwest;

use super::{HttpRequest, HttpResponse};

///
/// Error type returned by failed reqwest HTTP requests.
///
#[derive(Debug, Fail)]
pub enum Error {
    /// Error returned by reqwest crate.
    #[fail(display = "request failed")]
    Reqwest(#[cause] reqwest::Error),
    /// Non-reqwest HTTP error.
    #[fail(display = "HTTP error")]
    Http(#[cause] http::Error),
    /// I/O error.
    #[fail(display = "I/O error")]
    Io(#[cause] std::io::Error),
    /// Other error.
    #[fail(display = "Other error: {}", _0)]
    Other(String),
}

///
/// Synchronous HTTP client.
///
pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let client = blocking::Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(RedirectPolicy::none())
        .build()
        .map_err(Error::Reqwest)?;
    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name, value);
    }
    let mut response = client
        .execute(request_builder.build().map_err(Error::Reqwest)?)
        .map_err(Error::Reqwest)?;

    let mut body = Vec::new();
    response.read_to_end(&mut body).map_err(Error::Io)?;
    Ok(HttpResponse {
        status_code: response.status(),
        headers: response.headers().clone(),
        body,
    })
}

///
/// Asynchronous HTTP client.
///
#[cfg(feature = "futures-03")]
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let client = Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(RedirectPolicy::none())
        .build()
        .map_err(Error::Reqwest)?;


    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name, value);
    }
    let request = request_builder
        .build()
        .map_err(Error::Reqwest)?;

    let response = client
        .execute(request)
        .await
        .map_err(Error::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().clone();
    let chunks = response
        .bytes()
        .await
        .map_err(Error::Reqwest)?;

     Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}

///
/// Asynchronous HTTP client.
///
#[cfg(feature = "futures-01")]
pub fn async_http_client(request: HttpRequest) -> impl Future<Item = HttpResponse, Error = Error> {
    AsyncClient::builder()
    // Following redirects opens the client up to SSRF vulnerabilities.
    .redirect(RedirectPolicy::none())
    .build()
    .map_err(Error::Reqwest)
    .into_future()
    .and_then(|client| {
        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);
        for (name, value) in &request.headers {
            request_builder = request_builder.header(name, value);
        }
        request_builder
            .build()
            .map_err(Error::Reqwest)
            .into_future()
            .and_then(move |request| {
                client
                    .execute(request)
                    .and_then(|response| {
                        let status_code = response.status();
                        let headers = response.headers().clone();
                        response
                            .into_body()
                            .map(|chunk| chunk.as_ref().to_vec())
                            .collect()
                            .map(move |body| HttpResponse {
                                status_code,
                                headers,
                                body: body.into_iter().flatten().collect::<_>(),
                            })
                    })
                    .map_err(Error::Reqwest)
            })
    })
}
