use crate::{AsyncHttpClient, HttpRequest, HttpResponse};

use thiserror::Error;

use std::future::Future;
use std::pin::Pin;

pub use reqwest;

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

impl<'c> AsyncHttpClient<'c> for reqwest::Client {
    type Error = Error;

    fn call(
        &'c self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + 'c>> {
        Box::pin(async move {
            let response = self.execute(request.try_into()?).await?;

            // This should be simpler once https://github.com/seanmonstar/reqwest/pull/2060 is
            // merged.
            let mut builder = http::Response::builder().status(response.status());

            #[cfg(not(target_arch = "wasm32"))]
            {
                builder = builder.version(response.version());
            }

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await?.to_vec())
                .map_err(Error::Http)
        })
    }
}

#[cfg(all(feature = "reqwest-blocking", not(target_arch = "wasm32")))]
impl crate::SyncHttpClient for reqwest::blocking::Client {
    type Error = Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut response = self.execute(request.try_into()?)?;

        // This should be simpler once https://github.com/seanmonstar/reqwest/pull/2060 is
        // merged.
        let mut builder = http::Response::builder()
            .status(response.status())
            .version(response.version());

        for (name, value) in response.headers().iter() {
            builder = builder.header(name, value);
        }

        let mut body = Vec::new();
        <reqwest::blocking::Response as std::io::Read>::read_to_end(&mut response, &mut body)?;

        builder.body(body).map_err(Error::Http)
    }
}
