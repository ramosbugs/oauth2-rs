use std::io::Read;

use crate::{HttpClientError, HttpRequest, HttpResponse};

impl crate::SyncHttpClient for ureq_3::Agent {
    type Error = HttpClientError<ureq_3::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let response = self.run(request).map_err(Box::new)?;

        let (parts, body) = response.into_parts();
        let mut body_vec = Vec::new();
        body.into_reader().read_to_end(&mut body_vec)?;

        Ok(HttpResponse::from_parts(parts, body_vec))
    }
}
