use super::super::{HttpRequest, HttpResponse};
use super::Error;

use http::header::HeaderName;
use http::{HeaderMap, HeaderValue, StatusCode};

pub use reqwest_0_10 as reqwest;

///
/// Asynchronous HTTP client.
///
pub async fn async_http_client(
    request: HttpRequest,
) -> Result<HttpResponse, Error<reqwest::Error>> {
    let client = reqwest::Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::Reqwest)?;

    let mut request_builder = client
        .request(
            http_0_2::Method::from_bytes(request.method.as_str().as_ref())
                .expect("failed to convert Method from http 0.2 to 0.1"),
            request.url.as_str(),
        )
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
