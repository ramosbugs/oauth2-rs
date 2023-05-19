use std::{collections::BTreeMap, marker::PhantomData};

use chrono::{Duration, Utc};
use openssl::{hash::MessageDigest, pkey::PKey, x509::X509};


use jwt::{AlgorithmType, Header, PKeyWithDigest, SignWithKey, Token, header::{HeaderType, HeaderContentType}};

use crate::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenResponse, BasicTokenType,
    },
    Client, ClientCredentialsTokenRequest, StandardRevocableToken,
};

///
/// Microsoft Azure OAuth2 client specialization, suitable for certificate based applications.
///
pub type MicrosoftClient = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

impl MicrosoftClient {
    ///
    /// Requests an access token for the *client credentials* grant type.
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-4.4.2>.
    ///
    pub fn exchange_client_certificate_credentials(
        &self, cert_pem: &[u8], key_pem: &[u8]
    ) -> ClientCredentialsTokenRequest<BasicErrorResponse, BasicTokenResponse, BasicTokenType> {
        let tr = ClientCredentialsTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: None,
            extra_params: Vec::new(),
            scopes: Vec::new(),
            token_url: self.token_url.as_ref(),
            _phantom: PhantomData,
        };

        tr
        .add_extra_param(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ).add_extra_param("client_assertion", self.generate_assertion(cert_pem, key_pem))

    }

    fn generate_assertion(&self, cert_pem: &[u8], key_pem: &[u8]) -> String {
        let cert = X509::from_pem(cert_pem).unwrap();
        let hash = cert.digest(MessageDigest::sha1()).unwrap();

        let hash_string = hash.to_vec().iter()
            .map(|byte| format!("{:02X}", byte))
            .collect::<String>();

        let x5t = base64::encode(hash.to_vec());

        let key = PKey::private_key_from_pem_passphrase(key_pem, &vec![]).unwrap();

        let header = Header {
            algorithm: AlgorithmType::Rs256,
            key_id: Some(hash_string),
            type_: Some(HeaderType::JsonWebToken),
            x5t: Some(x5t),
            ..Default::default()
        };

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: key,
        };

        let exp = (Utc::now() + Duration::minutes(1)).timestamp().to_string();
        let iat = Utc::now().timestamp().to_string();
        let nbf = (Utc::now() - Duration::minutes(1)).timestamp().to_string();

        let mut claims = BTreeMap::new();
        claims.insert(
            "aud",
            self.token_url.as_ref().unwrap().to_string(),
        );
        claims.insert("exp", exp);
        claims.insert("iss", self.client_id.to_string());
        claims.insert("jti", "06cd143c-477f-4cdb-aa30-90d03b5b2269".to_string());
        claims.insert("nbf", nbf);
        claims.insert("sub", self.client_id.to_string());
        claims.insert("iat", iat);

        let token = Token::new(header, claims)
            .sign_with_key(&algorithm)
            .unwrap();

        token.as_str().to_string()
    }
}

// #[cfg(test)]
// mod tests {

//     use super::*;
//     use crate::{HttpResponse, Scope};
//     use crate::{tests::mock_http_client, AuthUrl, ClientId, ClientSecret, TokenUrl};
//     use http::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
//     use http::status::StatusCode;
//     use thiserror::Error;
//     use url::form_urlencoded::byte_serialize;
//     use url::Url;

//     fn new_client() -> MicrosoftClient {
//         const tenant_id: &str = "3d02d73d-a23a-4989-93ef-ac3c459edadd";

//         MicrosoftClient::new(
//             ClientId::new("9aca7c0e-8e4a-4b36-8c69-1c2323092656".to_string()),
//             None,
//             AuthUrl::new(format!(
//                 "https://login.microsoft.com/{}/oauth2/v2.0/authorize",
//                 tenant_id
//             ))
//             .unwrap(),
//             Some(
//                 TokenUrl::new(format!(
//                     "https://login.microsoft.com/{}/oauth2/v2.0/token",
//                     tenant_id
//                 ))
//                 .unwrap(),
//             ),
//         )
//     }

//     use crate::reqwest::http_client;

//     #[test]
//     fn test() {
//         let client = new_client();

//         let cert_pem = include_bytes!("../cert.pem");
//         let key_pem = include_bytes!("../key.pem");

//         let t = client
//             .exchange_client_certificate_credentials(cert_pem, key_pem)
//             .add_scope(Scope::new(
//                 "https://0fsxp-admin.sharepoint.com/.default".to_string(),
//             ));

//         println!("{:?}", t);
//         let client = reqwest::Client::new();

//         let d = t.request(http_client);

//         println!("{:?}", d);
//     }
// }
