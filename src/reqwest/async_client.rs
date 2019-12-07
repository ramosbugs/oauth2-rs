use super::super::{HttpRequest, HttpResponse};
use super::Error;

pub use reqwest_0_10 as reqwest;

///
/// Asynchronous HTTP client.
///
pub async fn async_http_client(
    request: HttpRequest,
) -> Result<HttpResponse, Error<reqwest::Error>> {
    let client = reqwest::Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::RedirectPolicy::none())
        .build()
        .map_err(Error::Reqwest)?;

    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name, value);
    }
    let request = request_builder.build().map_err(Error::Reqwest)?;

    let response = client.execute(request).await.map_err(Error::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().clone();
    let chunks = response.bytes().await.map_err(Error::Reqwest)?;

    Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}
