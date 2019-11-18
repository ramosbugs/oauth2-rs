use failure::Fail;

///
/// Error type returned by failed reqwest HTTP requests.
///
#[derive(Debug, Fail)]
pub enum Error<T>
where
    T: std::error::Error + Send + Sync + 'static,
{
    /// Error returned by reqwest crate.
    #[fail(display = "request failed")]
    Reqwest(#[cause] T),
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

#[cfg(feature = "reqwest")]
pub use blocking::http_client;

#[cfg(all(feature = "futures-01", feature = "reqwest"))]
pub use future_client::future_http_client;

#[cfg(all(feature = "reqwest", feature = "futures-03"))]
pub use async_client::async_http_client;

#[cfg(feature = "reqwest")]
mod blocking {
    use super::Error;
    use super::super::{HttpRequest, HttpResponse};

    #[cfg(not(feature = "futures-03"))]
    use reqwest_0_9 as blocking;
    #[cfg(not(feature = "futures-03"))]
    use reqwest_0_9 as reqwest;
    #[cfg(not(feature = "futures-03"))]
    use reqwest_0_9::RedirectPolicy;

    #[cfg(feature = "futures-03")]
    use reqwest_0_10 as reqwest;
    #[cfg(feature = "futures-03")]
    use reqwest_0_10::blocking;
    #[cfg(feature = "futures-03")]
    use reqwest_0_10::RedirectPolicy;

    use std::io::Read;

    ///
    /// Synchronous HTTP client.
    ///
    #[cfg(feature = "reqwest")]
    pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error<reqwest::Error>> {
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
}

#[cfg(all(feature = "futures-01", feature = "reqwest"))]
mod future_client {
    use super::Error;
    use super::super::{HttpRequest, HttpResponse};

    use futures_0_1::{Future, IntoFuture, Stream};
    use reqwest_0_9 as reqwest;
    use reqwest_0_9::r#async::Client as AsyncClient;

    ///
    /// Asynchronous HTTP client.
    ///
    pub fn future_http_client(
        request: HttpRequest,
    ) -> impl Future<Item = HttpResponse, Error = Error<reqwest::Error>> {
        AsyncClient::builder()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::RedirectPolicy::none())
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
}

#[cfg(feature = "futures-03")]
mod async_client;
