use std::io::Read;

use curl_::easy::Easy;

use super::{HttpRequest, HttpRequestMethod, HttpResponse};

///
/// Error type returned by failed curl HTTP requests.
///
pub type Error = curl::Error;

///
/// Synchronous HTTP client.
///
pub fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let mut easy = Easy::new();
    easy.url(&request.url.to_string()[..])?;

    let mut headers = curl::easy::List::new();
    request
        .headers
        .iter()
        .map(|(name, value)| headers.append(&format!("{}: {}", name, value)))
        .collect::<Result<_, _>>()?;

    easy.http_headers(headers)?;

    if let HttpRequestMethod::Post = request.method {
        easy.post(true)?;
        easy.post_field_size(request.body.len() as u64)?;
    }

    let mut form_slice = &request.body[..];
    let mut data = Vec::new();
    {
        let mut transfer = easy.transfer();

        transfer.read_function(|buf| Ok(form_slice.read(buf).unwrap_or(0)))?;

        if let HttpRequestMethod::Post = request.method {
            transfer.write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })?;
        }

        transfer.perform()?;
    }

    let status_code = easy.response_code()?;

    Ok(HttpResponse {
        status_code,
        headers: easy
            .content_type()?
            .map(|content_type| vec![("Content-type".to_string(), content_type.to_string())])
            .unwrap_or_else(Vec::new),
        body: data,
    })
}
