use std::collections::HashMap;
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    DeviceCode, EndUserVerificationUrl, ErrorResponseType, StandardErrorResponse, UserCode,
};

/// The minimum amount of time in seconds that the client SHOULD wait
/// between polling requests to the token endpoint.  If no value is
/// provided, clients MUST use 5 as the default.
fn default_devicecode_interval() -> u64 {
    5
}

///
/// Standard OAuth2 device authorization response.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceAuthorizationDetails {
    /// The device verification code.
    device_code: DeviceCode,

    /// The end-user verification code.
    user_code: UserCode,

    /// The end-user verification URI on the authorization The URI should be
    /// short and easy to remember as end users will be asked to manually type
    /// it into their user agent.
    #[serde(alias = "verification_url")]
    verification_uri: EndUserVerificationUrl,

    /// A verification URI that includes the "user_code" (or other information
    /// with the same function as the "user_code"), which is designed for
    /// non-textual transmission.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<EndUserVerificationUrl>,

    /// The lifetime in seconds of the "device_code" and "user_code".
    expires_in: u64,

    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.  If no value is
    /// provided, clients MUST use 5 as the default.
    #[serde(default = "default_devicecode_interval")]
    interval: u64,

    #[serde(flatten)]
    extra_fields: HashMap<String, serde_json::Value>,
}

impl DeviceAuthorizationDetails {
    /// The device verification code.
    pub fn device_code(&self) -> &DeviceCode {
        return &self.device_code;
    }

    /// The end-user verification code.
    pub fn user_code(&self) -> &UserCode {
        return &self.user_code;
    }

    /// The end-user verification URI on the authorization The URI should be
    /// short and easy to remember as end users will be asked to manually type
    /// it into their user agent.
    pub fn verification_uri(&self) -> &EndUserVerificationUrl {
        return &self.verification_uri;
    }

    /// A verification URI that includes the "user_code" (or other information
    /// with the same function as the "user_code"), which is designed for
    /// non-textual transmission.
    pub fn verification_uri_complete(&self) -> Option<&EndUserVerificationUrl> {
        return self.verification_uri_complete.as_ref();
    }

    /// The lifetime in seconds of the "device_code" and "user_code".
    pub fn expires_in(&self) -> Duration {
        return Duration::from_secs(self.expires_in);
    }

    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.  If no value is
    /// provided, clients MUST use 5 as the default.
    pub fn interval(&self) -> Duration {
        return Duration::from_secs(self.interval);
    }

    /// Any extra fields that were added to the response.
    pub fn extra_fields(&self) -> &HashMap<String, serde_json::Value> {
        return &self.extra_fields;
    }
}

///
/// The action that the device code flow should currently be taking.
///
#[derive(Debug, thiserror::Error)]
pub enum DeviceCodeAction<T: Debug> {
    ///
    /// Retry the current request, waiting for the current interval value.
    ///
    #[error("Request failed, retry after waiting")]
    Retry,
    ///
    /// Increase the interval by 5 seconds as per
    /// https://tools.ietf.org/html/rfc8628#section-3.5, then retry the current
    /// request.
    ///
    #[error("Request failed, increase interval then retry after waiting")]
    IncreaseIntervalThenRetry,
    ///
    /// Double the interval to back off the server on a failure, then retry the
    /// current request.
    ///
    #[error("Request failed, double interval then retry after waiting")]
    DoubleIntervalThenRetry,
    ///
    /// Do not do any more requests.
    ///
    #[error("Request failed")]
    NoFurtherRequests(T),
}

///
/// Basic access token error types.
///
/// These error types are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2) and
/// [Section 3.5 of RFC 6749](https://tools.ietf.org/html/rfc8628#section-3.5)
///
#[derive(Clone, PartialEq)]
pub enum DeviceCodeErrorResponseType {
    ///
    /// The authorization request is still pending as the end user hasn't
    /// yet completed the user-interaction steps.  The client SHOULD repeat the
    /// access token request to the token endpoint.  Before each new request,
    /// the client MUST wait at least the number of seconds specified by the
    /// "interval" parameter of the device authorization response, or 5 seconds
    /// if none was provided, and respect any increase in the polling interval
    /// required by the "slow_down" error.
    ///
    AuthorizationPending,
    ///
    /// A variant of "authorization_pending", the authorization request is
    /// still pending and polling should continue, but the interval MUST be
    /// increased by 5 seconds for this and all subsequent requests.
    SlowDown,
    ///
    /// The authorization request was denied.
    ///
    AccessDenied,
    ///
    /// The "device_code" has expired, and the device authorization session has
    /// concluded.  The client MAY commence a new device authorization request
    /// but SHOULD wait for user interaction before restarting to avoid
    /// unnecessary polling.
    ExpiredToken,
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
    /// The request is missing a required parameter, includes an unsupported parameter value
    /// (other than grant type), repeats a parameter, includes multiple credentials, utilizes
    /// more than one mechanism for authenticating the client, or is otherwise malformed.
    ///
    InvalidRequest,
    ///
    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    ///
    InvalidScope,
    ///
    /// The authenticated client is not authorized to use this authorization grant type.
    ///
    UnauthorizedClient,
    ///
    /// The authorization grant type is not supported by the authorization server.
    ///
    UnsupportedGrantType,
    ///
    /// An extension not defined by RFC 6749 or RFC 8628
    ///
    Extension(String),
}
impl DeviceCodeErrorResponseType {
    fn from_str(s: &str) -> Self {
        match s {
            "authorization_pending" => DeviceCodeErrorResponseType::AuthorizationPending,
            "slow_down" => DeviceCodeErrorResponseType::SlowDown,
            "access_denied" => DeviceCodeErrorResponseType::AccessDenied,
            "expired_token" => DeviceCodeErrorResponseType::ExpiredToken,
            "invalid_client" => DeviceCodeErrorResponseType::InvalidClient,
            "invalid_grant" => DeviceCodeErrorResponseType::InvalidGrant,
            "invalid_request" => DeviceCodeErrorResponseType::InvalidRequest,
            "invalid_scope" => DeviceCodeErrorResponseType::InvalidScope,
            "unauthorized_client" => DeviceCodeErrorResponseType::UnauthorizedClient,
            "unsupported_grant_type" => DeviceCodeErrorResponseType::UnsupportedGrantType,
            ext => DeviceCodeErrorResponseType::Extension(ext.to_string()),
        }
    }
}
impl AsRef<str> for DeviceCodeErrorResponseType {
    fn as_ref(&self) -> &str {
        match *self {
            DeviceCodeErrorResponseType::AuthorizationPending => "authorization_pending",
            DeviceCodeErrorResponseType::SlowDown => "slow_down",
            DeviceCodeErrorResponseType::AccessDenied => "access_denied",
            DeviceCodeErrorResponseType::ExpiredToken => "expired_token",
            DeviceCodeErrorResponseType::InvalidClient => "invalid_client",
            DeviceCodeErrorResponseType::InvalidGrant => "invalid_grant",
            DeviceCodeErrorResponseType::InvalidRequest => "invalid_request",
            DeviceCodeErrorResponseType::InvalidScope => "invalid_scope",
            DeviceCodeErrorResponseType::UnauthorizedClient => "unauthorized_client",
            DeviceCodeErrorResponseType::UnsupportedGrantType => "unsupported_grant_type",
            DeviceCodeErrorResponseType::Extension(ref ext) => ext.as_str(),
        }
    }
}
impl<'de> serde::Deserialize<'de> for DeviceCodeErrorResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let variant_str = String::deserialize(deserializer)?;
        Ok(Self::from_str(&variant_str))
    }
}
impl serde::ser::Serialize for DeviceCodeErrorResponseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl ErrorResponseType for DeviceCodeErrorResponseType {}
impl Debug for DeviceCodeErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        Display::fmt(self, f)
    }
}

impl Display for DeviceCodeErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}

///
/// Error response specialization for device code OAuth2 implementation.
///
pub type DeviceCodeErrorResponse = StandardErrorResponse<DeviceCodeErrorResponseType>;

impl DeviceCodeErrorResponse {
    ///
    /// Convert a device code error response to the next action that should
    /// be taken.
    ///
    pub fn to_action<T: Debug>(&self, req: T) -> DeviceCodeAction<T> {
        match &self.error {
            DeviceCodeErrorResponseType::AuthorizationPending => DeviceCodeAction::Retry,
            DeviceCodeErrorResponseType::SlowDown => DeviceCodeAction::IncreaseIntervalThenRetry,
            _ => DeviceCodeAction::NoFurtherRequests(req),
        }
    }
}
