#[cfg(any(feature = "reqwest", feature = "reqwest-09"))]
use std::io::Read;

use failure::Fail;
#[cfg(all(feature = "futures-01", feature = "reqwest-09"))]
use futures_0_1::{Future, IntoFuture, Stream};

#[cfg(all(feature = "futures-01", feature = "reqwest-09"))]
use reqwest_09::r#async::Client as AsyncClient;
#[cfg(feature = "reqwest-09")]
use reqwest_09 as blocking;
#[cfg(feature = "reqwest-09")]
use reqwest_09::{RedirectPolicy};
#[cfg(feature = "reqwest-09")]
use reqwest_09 as reqwest;


#[cfg(feature = "reqwest")]
use reqwest::blocking;
#[cfg(feature = "reqwest")]
use reqwest::RedirectPolicy;
#[cfg(all(feature = "futures-03", feature = "reqwest"))]
use reqwest;

#[cfg(any(feature = "reqwest", feature = "reqwest-09"))]
use super::{HttpRequest, HttpResponse};

///
/// Error type returned by failed reqwest HTTP requests.
///
#[derive(Debug, Fail)]
pub enum Error {
    /// Error returned by reqwest crate.
    #[fail(display = "request failed")]
    #[cfg(any(feature = "reqwest", feature = "reqwest-09"))]
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
#[cfg(any(feature = "reqwest", feature = "reqwest-09"))]
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
#[cfg(all(feature = "futures-01", feature = "reqwest-09"))]
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

///
/// Asynchronous HTTP client.
///
#[cfg(all(feature = "reqwest", feature = "futures-03"))]
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let client = reqwest::Client::builder()
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
