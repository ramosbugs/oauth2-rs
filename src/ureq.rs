use crate::{HttpRequest, HttpResponse};

use http::{
    header::{HeaderValue, CONTENT_TYPE},
    method::Method,
    status::StatusCode,
};

use std::io::Read;

/// Error type returned by failed ureq HTTP requests.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Non-ureq HTTP error.
    #[error("HTTP error")]
    Http(#[from] http::Error),
    /// IO error
    #[error("IO error")]
    IO(#[from] std::io::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
    /// Error returned by ureq crate.
    // boxed due to https://github.com/algesten/ureq/issues/296
    #[error("ureq request failed")]
    Ureq(#[from] Box<ureq::Error>),
}

impl crate::SyncHttpClient for ureq::Agent {
    type Error = Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut req = if *request.method() == Method::POST {
            self.post(&request.uri().to_string())
        } else {
            debug_assert_eq!(*request.method(), Method::GET);
            self.get(&request.uri().to_string())
        };

        for (name, value) in request.headers() {
            req = req.set(
                name.as_ref(),
                // TODO: In newer `ureq` it should be easier to convert arbitrary byte sequences
                // without unnecessary UTF-8 fallibility here.
                value.to_str().map_err(|_| {
                    Error::Other(format!(
                        "invalid {} header value {:?}",
                        name,
                        value.as_bytes()
                    ))
                })?,
            );
        }

        let response = if let Method::POST = *request.method() {
            req.send_bytes(request.body())
        } else {
            req.call()
        }
        .map_err(Box::new)?;

        let mut builder = http::Response::builder()
            .status(StatusCode::from_u16(response.status()).map_err(http::Error::from)?);

        if let Some(content_type) = response
            .header(CONTENT_TYPE.as_str())
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(http::Error::from)?
        {
            builder = builder.header(CONTENT_TYPE, content_type);
        }

        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body)?;

        builder.body(body).map_err(Error::Http)
    }
}
