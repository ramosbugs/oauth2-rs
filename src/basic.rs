use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};

use super::helpers;
use super::{
    Client, EmptyExtraTokenFields, ErrorResponseType, RequestTokenError, StandardErrorResponse,
    StandardTokenResponse, TokenType,
};

use serde::{Serialize, Deserialize};

///
/// Basic OAuth2 client specialization, suitable for most applications.
///
pub type BasicClient = Client<BasicErrorResponse, BasicTokenResponse, BasicTokenType>;

///
/// Basic OAuth2 authorization token types.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BasicTokenType {
    ///
    /// Bearer token
    /// ([OAuth 2.0 Bearer Tokens - RFC 6750](https://tools.ietf.org/html/rfc6750)).
    ///
    Bearer,
    ///
    /// MAC ([OAuth 2.0 Message Authentication Code (MAC)
    /// Tokens](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05)).
    ///
    Mac,
}
impl TokenType for BasicTokenType {}

///
/// Basic OAuth2 token response.
///
pub type BasicTokenResponse = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

///
/// Basic access token error types.
///
/// These error types are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2).
///
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BasicErrorResponseType {
    ///
    /// The request is missing a required parameter, includes an unsupported parameter value
    /// (other than grant type), repeats a parameter, includes multiple credentials, utilizes
    /// more than one mechanism for authenticating the client, or is otherwise malformed.
    ///
    InvalidRequest,
    ///
    /// Client authentication failed (e.g., unknown client, no client authentication included,
    /// or unsupported authentication method).
    ///
    InvalidClient,
    ///
    /// The provided authorization grant (e.g., authorization code, resource owner credentials)
    /// or refresh token is invalid, expired, revoked, does not match the redirection URI used
    /// in the authorization request, or was issued to another client.
    ///
    InvalidGrant,
    ///
    /// The authenticated client is not authorized to use this authorization grant type.
    ///
    UnauthorizedClient,
    ///
    /// The authorization grant type is not supported by the authorization server.
    ///
    UnsupportedGrantType,
    ///
    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    ///
    InvalidScope,
}

impl ErrorResponseType for BasicErrorResponseType {}

impl Debug for BasicErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        Display::fmt(self, f)
    }
}

impl Display for BasicErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", helpers::variant_name(&self))
    }
}

///
/// Error response specialization for basic OAuth2 implementation.
///
pub type BasicErrorResponse = StandardErrorResponse<BasicErrorResponseType>;

///
/// Token error specialization for basic OAuth2 implementation.
///
pub type BasicRequestTokenError<RE> = RequestTokenError<RE, BasicErrorResponse>;
