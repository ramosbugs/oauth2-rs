use std::io::Read;

use curl::easy::Easy;
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http::method::Method;
use http::status::StatusCode;

use super::{HttpRequest, HttpResponse};

///
/// Error type returned by failed curl HTTP requests.
///
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

///
/// Synchronous HTTP client.
///
pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let mut easy = Easy::new();
    easy.url(&request.url.to_string()[..])?;

    let mut headers = curl::easy::List::new();
    for (name, value) in &request.headers {
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

    if let Method::POST = request.method {
        easy.post(true)?;
        easy.post_field_size(request.body.len() as u64)?;
    } else {
        assert_eq!(request.method, Method::GET);
    }

    let mut form_slice = &request.body[..];
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

    let status_code = easy.response_code()? as u16;

    Ok(HttpResponse {
        status_code: StatusCode::from_u16(status_code).map_err(http::Error::from)?,
        headers: easy
            .content_type()?
            .map(|content_type| HeaderValue::from_str(content_type).map_err(http::Error::from))
            .transpose()?
            .map_or_else(HeaderMap::new, |content_type| {
                vec![(CONTENT_TYPE, content_type)]
                    .into_iter()
                    .collect::<HeaderMap>()
            }),
        body: data,
    })
}
