use crate::{HttpRequest, HttpResponse};

use http::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    method::Method,
    status::StatusCode,
};

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

/// Synchronous HTTP client for ureq.
pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let mut req = if request.method == Method::POST {
        ureq::post(request.url.as_ref())
    } else {
        ureq::get(request.url.as_ref())
    };

    for (name, value) in request.headers {
        if let Some(name) = name {
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
    }

    let response = if let Method::POST = request.method {
        req.send_bytes(&request.body)
    } else {
        req.call()
    }
    .map_err(Box::new)?;

    Ok(HttpResponse {
        status_code: StatusCode::from_u16(response.status()).map_err(http::Error::from)?,
        headers: vec![(
            CONTENT_TYPE,
            HeaderValue::from_str(response.content_type()).map_err(http::Error::from)?,
        )]
        .into_iter()
        .collect::<HeaderMap>(),
        body: response.into_string()?.as_bytes().into(),
    })
}
