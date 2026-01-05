use crate::{HttpClientError, HttpRequest, HttpResponse};

use http::{
    header::CONTENT_TYPE,
    method::Method,
};

impl crate::SyncHttpClient for ureq::Agent {
    type Error = HttpClientError<ureq::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let uri = request.uri().to_string();

        let response = if *request.method() == Method::POST {
            let mut req = self.post(&uri);
            for (name, value) in request.headers() {
                req = req.header(name, value);
            }
            req.send(request.body())
        } else {
            debug_assert_eq!(*request.method(), Method::GET);
            let mut req = self.get(&uri);
            for (name, value) in request.headers() {
                req = req.header(name, value);
            }
            req.call()
        }
        .map_err(Box::new)?;

        let (parts, mut body_reader) = response.into_parts();
        let mut builder = http::Response::builder().status(parts.status);

        if let Some(content_type) = parts.headers.get(CONTENT_TYPE) {
            builder = builder.header(CONTENT_TYPE, content_type);
        }

        let body = body_reader.read_to_vec().map_err(Box::new)?;

        builder.body(body).map_err(HttpClientError::Http)
    }
}
