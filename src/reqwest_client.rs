use crate::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};

use std::future::Future;
use std::pin::Pin;

impl<'c> AsyncHttpClient<'c> for reqwest::Client {
    type Error = HttpClientError<reqwest::Error>;

    fn call(
        &'c self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>> {
        Box::pin(async move {
            let response = self
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

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
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}

#[cfg(all(feature = "reqwest-blocking", not(target_arch = "wasm32")))]
impl crate::SyncHttpClient for reqwest::blocking::Client {
    type Error = HttpClientError<reqwest::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut response = self
            .execute(request.try_into().map_err(Box::new)?)
            .map_err(Box::new)?;

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

        builder.body(body).map_err(HttpClientError::Http)
    }
}
