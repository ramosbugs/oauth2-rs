use crate::{HttpRequest, HttpResponse, SyncHttpClient};

use curl::easy::Easy;
use http::header::{HeaderValue, CONTENT_TYPE};
use http::method::Method;
use http::status::StatusCode;

use std::io::Read;

pub use curl;

/// Error type returned by failed curl HTTP requests.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error returned by curl crate.
    #[error("curl request failed")]
    Curl(#[from] curl::Error),
    /// Non-curl HTTP error.
    #[error("HTTP error")]
    Http(#[from] http::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
}

/// A synchronous HTTP client using [`curl`].
pub struct CurlHttpClient;
impl SyncHttpClient for CurlHttpClient {
    type Error = Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut easy = Easy::new();
        easy.url(&request.uri().to_string()[..])?;

        let mut headers = curl::easy::List::new();
        for (name, value) in request.headers() {
            headers.append(&format!(
                "{}: {}",
                name,
                // TODO: Unnecessary fallibility, curl uses a CString under the hood
                value.to_str().map_err(|_| Error::Other(format!(
                    "invalid {} header value {:?}",
                    name,
                    value.as_bytes()
                )))?
            ))?
        }

        easy.http_headers(headers)?;

        if let Method::POST = *request.method() {
            easy.post(true)?;
            easy.post_field_size(request.body().len() as u64)?;
        } else {
            assert_eq!(*request.method(), Method::GET);
        }

        let mut form_slice = &request.body()[..];
        let mut data = Vec::new();
        {
            let mut transfer = easy.transfer();

            transfer.read_function(|buf| Ok(form_slice.read(buf).unwrap_or(0)))?;

            transfer.write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })?;

            transfer.perform()?;
        }

        let mut builder = http::Response::builder()
            .status(StatusCode::from_u16(easy.response_code()? as u16).map_err(http::Error::from)?);

        if let Some(content_type) = easy
            .content_type()?
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(http::Error::from)?
        {
            builder = builder.header(CONTENT_TYPE, content_type);
        }

        builder.body(data).map_err(Error::Http)
    }
}
