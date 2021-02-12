use serde::{Deserialize, Serialize};
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};

use crate::{basic::BasicErrorResponseType, ErrorResponseType};
use crate::{AccessToken, RefreshToken};

pub trait RevocableToken {
    fn secret(&self) -> &str;

    fn token_type_hint(&self) -> &str;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum StandardRevocableToken {
    AccessToken(AccessToken),
    RefreshToken(RefreshToken),
}
impl RevocableToken for StandardRevocableToken {
    fn secret(&self) -> &str {
        match self {
            Self::AccessToken(token) => token.secret(),
            Self::RefreshToken(token) => token.secret(),
        }
    }

    ///
    /// Indicate the type of the token.
    ///
    /// See: https://tools.ietf.org/html/rfc7009#section-2.1
    ///
    /// OPTIONAL.  A hint about the type of the token
    /// submitted for revocation.  Clients MAY pass this parameter in
    /// order to help the authorization server to optimize the token
    /// lookup.  If the server is unable to locate the token using
    /// the given hint, it MUST extend its search across all of its
    /// supported token types.  An authorization server MAY ignore
    /// this parameter, particularly if it is able to detect the
    /// token type automatically.  This specification defines two
    /// such values:
    ///
    /// * access_token: An access token as defined in [[RFC6749],
    ///   Section 1.4](https://tools.ietf.org/html/rfc6749#section-1.4)
    ///
    /// * refresh_token: A refresh token as defined in [[RFC6749],
    ///   Section 1.5](https://tools.ietf.org/html/rfc6749#section-1.5)
    ///
    /// Specific implementations, profiles, and extensions of this
    /// specification MAY define other values for this parameter
    /// using the registry defined in [Section 4.1.2](https://tools.ietf.org/html/rfc6749#section-4.1.2).
    ///
    fn token_type_hint(&self) -> &str {
        match self {
            StandardRevocableToken::AccessToken(_) => "access_token",
            StandardRevocableToken::RefreshToken(_) => "refresh_token",
        }
    }
}

impl From<AccessToken> for StandardRevocableToken {
    fn from(token: AccessToken) -> Self {
        Self::AccessToken(token)
    }
}

impl From<&AccessToken> for StandardRevocableToken {
    fn from(token: &AccessToken) -> Self {
        Self::AccessToken(token.clone())
    }
}

impl From<RefreshToken> for StandardRevocableToken {
    fn from(token: RefreshToken) -> Self {
        Self::RefreshToken(token)
    }
}

impl From<&RefreshToken> for StandardRevocableToken {
    fn from(token: &RefreshToken) -> Self {
        Self::RefreshToken(token.clone())
    }
}

///
/// OAuth 2.0 Token Revocation error response types
///
/// These error types are defined in
/// [Section 2.2.1 of RFC 7009](https://tools.ietf.org/html/rfc7009#section-2.2.1) and
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc8628#section-5.2)
///
#[derive(Clone, PartialEq)]
pub enum RevocationErrorResponseType {
    ///
    /// The authorization server does not support
    /// the revocation of the presented token type.  That is, the
    /// client tried to revoke an access token on a server not
    /// supporting this feature.
    ///
    UnsupportedTokenType,
    ///
    /// A Basic response type
    ///
    Basic(BasicErrorResponseType),
}
impl RevocationErrorResponseType {
    fn from_str(s: &str) -> Self {
        match BasicErrorResponseType::from_str(s) {
            BasicErrorResponseType::Extension(ext) => match ext.as_str() {
                "unsupported_token_type" => RevocationErrorResponseType::UnsupportedTokenType,
                _ => RevocationErrorResponseType::Basic(BasicErrorResponseType::Extension(ext)),
            },
            basic => RevocationErrorResponseType::Basic(basic),
        }
    }
}
impl AsRef<str> for RevocationErrorResponseType {
    fn as_ref(&self) -> &str {
        match self {
            RevocationErrorResponseType::UnsupportedTokenType => "unsupported_token_type",
            RevocationErrorResponseType::Basic(basic) => basic.as_ref(),
        }
    }
}
impl<'de> serde::Deserialize<'de> for RevocationErrorResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let variant_str = String::deserialize(deserializer)?;
        Ok(Self::from_str(&variant_str))
    }
}
impl serde::ser::Serialize for RevocationErrorResponseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl ErrorResponseType for RevocationErrorResponseType {}
impl Debug for RevocationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        Display::fmt(self, f)
    }
}

impl Display for RevocationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}
