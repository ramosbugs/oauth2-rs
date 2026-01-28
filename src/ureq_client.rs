use crate::{HttpClientError, HttpRequest, HttpResponse};

impl crate::SyncHttpClient for ureq::Agent {
    type Error = HttpClientError<ureq::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let uri = request.uri().to_string();

        let response = match request.method() {
            &http::Method::POST => {
                let req = request
                    .headers()
                    .iter()
                    .fold(self.post(&uri), |req, (name, value)| {
                        req.header(name, value)
                    });
                req.send(request.body()).map_err(Box::new)?
            }
            &http::Method::GET => {
                let req = request
                    .headers()
                    .iter()
                    .fold(self.get(&uri), |req, (name, value)| req.header(name, value));
                req.call().map_err(Box::new)?
            }
            m => {
                return Err(crate::HttpClientError::Other(format!(
                    "unexpected method: {m}"
                )));
            }
        };

        let mut builder = http::Response::builder().status(response.status());

        if let Some(content_type) = response.headers().get(http::header::CONTENT_TYPE) {
            builder = builder.header(http::header::CONTENT_TYPE, content_type);
        }

        let (_, mut body) = response.into_parts();

        let body = body.read_to_vec().map_err(Box::new)?;

        builder.body(body).map_err(crate::HttpClientError::Http)
    }
}
