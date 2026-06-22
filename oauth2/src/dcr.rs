use crate::basic::BasicErrorResponseType;
use crate::endpoint::{endpoint_response_with_status, HttpRequest};
use crate::types::{ClientName, DynamicClientRegistrationUrl};
use crate::{
    AccessToken, AsyncHttpClient, AuthType, Client, ClientId, ClientSecret, EndpointNotSet,
    ErrorResponse, ErrorResponseType, RedirectUrl, RequestTokenError, ResponseType, RevocableToken,
    Scope, StandardErrorResponse, SyncHttpClient, TokenIntrospectionResponse, TokenResponse,
    CONTENT_TYPE_JSON,
};

use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::marker::PhantomData;

/// Creates a request to dynamically register an OAuth 2.0 client.
///
/// See [RFC 7591](https://tools.ietf.org/html/rfc7591).
///
/// # Examples
///
/// See the `dynamic_client_registration` example.
pub(crate) fn dynamic_client_registration_impl<'a, TE>(
    client_name: ClientName,
    dynamic_client_registration_url: &'a DynamicClientRegistrationUrl,
) -> DynamicClientRegistrationRequest<'a, TE>
where
    TE: ErrorResponse + 'static,
{
    DynamicClientRegistrationRequest {
        redirect_uris: Vec::new(),
        token_endpoint_auth_method: None,
        grant_types: Vec::new(),
        response_types: Vec::new(),
        client_name: Some(Cow::Owned(client_name)),
        client_uri: None,
        logo_uri: None,
        scope: None,
        contacts: Vec::new(),
        tos_uri: None,
        policy_uri: None,
        jwks_uri: None,
        jwks: None,
        software_id: None,
        software_version: None,
        software_statement: None,
        initial_access_token: None,
        extra_params: Vec::new(),
        dynamic_client_registration_url,
        _phantom: PhantomData,
    }
}

/// The request to dynamically register an OAuth 2.0 client.
///
/// See <https://tools.ietf.org/html/rfc7591#section-3.1>.
#[derive(Debug)]
pub struct DynamicClientRegistrationRequest<'a, TE>
where
    TE: ErrorResponse,
{
    pub(crate) redirect_uris: Vec<Cow<'a, RedirectUrl>>,
    pub(crate) token_endpoint_auth_method: Option<Cow<'a, str>>,
    pub(crate) grant_types: Vec<Cow<'a, str>>,
    pub(crate) response_types: Vec<Cow<'a, ResponseType>>,
    pub(crate) client_name: Option<Cow<'a, ClientName>>,
    pub(crate) client_uri: Option<Cow<'a, str>>,
    pub(crate) logo_uri: Option<Cow<'a, str>>,
    pub(crate) scope: Option<Cow<'a, Scope>>,
    pub(crate) contacts: Vec<Cow<'a, str>>,
    pub(crate) tos_uri: Option<Cow<'a, str>>,
    pub(crate) policy_uri: Option<Cow<'a, str>>,
    pub(crate) jwks_uri: Option<Cow<'a, str>>,
    pub(crate) jwks: Option<serde_json::Value>,
    pub(crate) software_id: Option<Cow<'a, str>>,
    pub(crate) software_version: Option<Cow<'a, str>>,
    pub(crate) software_statement: Option<Cow<'a, str>>,
    pub(crate) initial_access_token: Option<Cow<'a, AccessToken>>,
    pub(crate) extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub(crate) dynamic_client_registration_url: &'a DynamicClientRegistrationUrl,
    pub(crate) _phantom: PhantomData<TE>,
}

impl<'a, TE> DynamicClientRegistrationRequest<'a, TE>
where
    TE: ErrorResponse + 'static,
{
    /// Sets the redirection URIs for redirect-based flows.
    pub fn set_redirect_uris<I>(mut self, redirect_uris: I) -> Self
    where
        I: IntoIterator<Item = Cow<'a, RedirectUrl>>,
    {
        self.redirect_uris = redirect_uris.into_iter().collect();
        self
    }

    /// Appends a redirection URI.
    pub fn add_redirect_uri(mut self, redirect_uri: RedirectUrl) -> Self {
        self.redirect_uris.push(Cow::Owned(redirect_uri));
        self
    }

    /// Sets the requested token endpoint authentication method.
    ///
    /// Values defined by [RFC 7591](https://tools.ietf.org/html/rfc7591#section-2) include
    /// `"none"`, `"client_secret_post"`, and `"client_secret_basic"`.
    pub fn set_token_endpoint_auth_method<N>(mut self, method: N) -> Self
    where
        N: Into<Cow<'a, str>>,
    {
        self.token_endpoint_auth_method = Some(method.into());
        self
    }

    /// Sets the OAuth 2.0 grant types the client may use.
    pub fn set_grant_types<I, S>(mut self, grant_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Cow<'a, str>>,
    {
        self.grant_types = grant_types.into_iter().map(Into::into).collect();
        self
    }

    /// Appends an OAuth 2.0 grant type.
    pub fn add_grant_type<S>(mut self, grant_type: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.grant_types.push(grant_type.into());
        self
    }

    /// Sets the OAuth 2.0 response types the client may use.
    pub fn set_response_types<I>(mut self, response_types: I) -> Self
    where
        I: IntoIterator<Item = Cow<'a, ResponseType>>,
    {
        self.response_types = response_types.into_iter().collect();
        self
    }

    /// Appends an OAuth 2.0 response type.
    pub fn add_response_type(mut self, response_type: ResponseType) -> Self {
        self.response_types.push(Cow::Owned(response_type));
        self
    }

    /// Sets the human-readable client name.
    pub fn set_client_name(mut self, client_name: ClientName) -> Self {
        self.client_name = Some(Cow::Owned(client_name));
        self
    }

    /// Sets the URL of a web page providing information about the client.
    pub fn set_client_uri<U>(mut self, client_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.client_uri = Some(client_uri.into());
        self
    }

    /// Sets the URL of the client's logo.
    pub fn set_logo_uri<U>(mut self, logo_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.logo_uri = Some(logo_uri.into());
        self
    }

    /// Sets the space-separated scope values the client may request.
    pub fn set_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(Cow::Owned(scope));
        self
    }

    /// Sets the space-separated scope values the client may request.
    pub fn set_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        let scope = scopes
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        self.scope = Some(Cow::Owned(Scope::new(scope)));
        self
    }

    /// Sets contact addresses for people responsible for this client.
    pub fn set_contacts<I, S>(mut self, contacts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Cow<'a, str>>,
    {
        self.contacts = contacts.into_iter().map(Into::into).collect();
        self
    }

    /// Appends a contact address.
    pub fn add_contact<S>(mut self, contact: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.contacts.push(contact.into());
        self
    }

    /// Sets the URL of the client's terms of service document.
    pub fn set_tos_uri<U>(mut self, tos_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.tos_uri = Some(tos_uri.into());
        self
    }

    /// Sets the URL of the client's privacy policy document.
    pub fn set_policy_uri<U>(mut self, policy_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.policy_uri = Some(policy_uri.into());
        self
    }

    /// Sets the URL of the client's JSON Web Key Set document.
    pub fn set_jwks_uri<U>(mut self, jwks_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.jwks_uri = Some(jwks_uri.into());
        self
    }

    /// Sets the client's JSON Web Key Set document value.
    ///
    /// The `"jwks_uri"` and `"jwks"` parameters MUST NOT both be present in the same request.
    pub fn set_jwks(mut self, jwks: serde_json::Value) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Sets the software identifier for the client software.
    pub fn set_software_id<S>(mut self, software_id: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.software_id = Some(software_id.into());
        self
    }

    /// Sets the software version identifier for the client software.
    pub fn set_software_version<S>(mut self, software_version: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.software_version = Some(software_version.into());
        self
    }

    /// Sets the signed software statement JWT.
    pub fn set_software_statement<S>(mut self, software_statement: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.software_statement = Some(software_statement.into());
        self
    }

    /// Sets the initial access token used to authorize protected registration requests.
    pub fn set_initial_access_token(mut self, initial_access_token: AccessToken) -> Self {
        self.initial_access_token = Some(Cow::Owned(initial_access_token));
        self
    }

    /// Appends an extra parameter to the registration request.
    ///
    /// This method allows extensions to be used without direct support from this crate. If `name`
    /// conflicts with a parameter managed by this crate, the behavior is undefined. This method is
    /// also the supported way to send locale-specific metadata such as `client_name#en`.
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + 'static,
    {
        let extra: HashMap<&str, &str> = self
            .extra_params
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
            .collect();

        let body = DynamicClientRegistrationRequestBody {
            redirect_uris: self
                .redirect_uris
                .iter()
                .map(|uri| uri.url().as_str())
                .collect(),
            token_endpoint_auth_method: self
                .token_endpoint_auth_method
                .as_deref()
                .map(Cow::Borrowed),
            grant_types: self.grant_types.iter().map(|t| t.as_ref()).collect(),
            response_types: self.response_types.iter().map(|t| t.as_str()).collect(),
            client_name: self.client_name.as_deref().map(|n| n.as_ref()),
            client_uri: self.client_uri.as_deref().map(Cow::Borrowed),
            logo_uri: self.logo_uri.as_deref().map(Cow::Borrowed),
            scope: self.scope.as_deref().map(|s| s.as_ref()),
            contacts: self.contacts.iter().map(|c| c.as_ref()).collect(),
            tos_uri: self.tos_uri.as_deref().map(Cow::Borrowed),
            policy_uri: self.policy_uri.as_deref().map(Cow::Borrowed),
            jwks_uri: self.jwks_uri.as_deref().map(Cow::Borrowed),
            jwks: self.jwks.as_ref(),
            software_id: self.software_id.as_deref().map(Cow::Borrowed),
            software_version: self.software_version.as_deref().map(Cow::Borrowed),
            software_statement: self.software_statement.as_deref().map(Cow::Borrowed),
            extra,
        };

        let body = serde_json::to_vec(&body).map_err(|err| {
            RequestTokenError::Other(format!("failed to serialize registration request: {err}"))
        })?;

        let mut builder = http::Request::builder()
            .uri(self.dynamic_client_registration_url.url().to_string())
            .method(http::Method::POST)
            .header(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON))
            .header(CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE_JSON));

        if let Some(token) = self.initial_access_token.as_ref() {
            builder = builder.header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token.secret())).map_err(|err| {
                    RequestTokenError::Other(format!(
                        "failed to prepare Authorization header: {err}"
                    ))
                })?,
            );
        }

        builder
            .body(body)
            .map_err(|err| RequestTokenError::Other(format!("failed to prepare request: {err}")))
    }

    /// Synchronously sends the request to the client registration endpoint and awaits a response.
    pub fn request<C, EF>(
        self,
        http_client: &C,
    ) -> Result<
        DynamicClientRegistrationResponse<EF>,
        RequestTokenError<<C as SyncHttpClient>::Error, TE>,
    >
    where
        C: SyncHttpClient,
        EF: ExtraDynamicClientRegistrationFields,
    {
        endpoint_response_with_status(
            http_client.call(self.prepare_request()?)?,
            &[StatusCode::OK, StatusCode::CREATED],
        )
    }

    /// Asynchronously sends the request to the client registration endpoint and returns a Future.
    pub fn request_async<'c, C, EF>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<
            DynamicClientRegistrationResponse<EF>,
            RequestTokenError<<C as AsyncHttpClient<'c>>::Error, TE>,
        >,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        EF: ExtraDynamicClientRegistrationFields,
    {
        Box::pin(async move {
            endpoint_response_with_status(
                http_client.call(self.prepare_request()?).await?,
                &[StatusCode::OK, StatusCode::CREATED],
            )
        })
    }
}

/// Proxy for [`DynamicClientRegistrationRequest`] that carries the target [`Client`] type
/// parameters and converts a successful registration response into a [`Client`].
#[derive(Debug)]
pub struct DynamicClient<'a, TE, TR, TIR, RT, TRE, EF = EmptyExtraDynamicClientRegistrationFields>
where
    TE: ErrorResponse,
    EF: ExtraDynamicClientRegistrationFields,
{
    inner: DynamicClientRegistrationRequest<'a, TE>,
    _phantom: PhantomData<(TR, TIR, RT, TRE, EF)>,
}

impl<'a, TE, TR, TIR, RT, TRE, EF> DynamicClient<'a, TE, TR, TIR, RT, TRE, EF>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    EF: ExtraDynamicClientRegistrationFields,
{
    pub(crate) fn new(
        client_name: ClientName,
        dynamic_client_registration_url: &'a DynamicClientRegistrationUrl,
    ) -> Self {
        Self {
            inner: dynamic_client_registration_impl(client_name, dynamic_client_registration_url),
            _phantom: PhantomData,
        }
    }

    /// Sets the redirection URIs for redirect-based flows.
    pub fn set_redirect_uris<I>(mut self, redirect_uris: I) -> Self
    where
        I: IntoIterator<Item = Cow<'a, RedirectUrl>>,
    {
        self.inner = self.inner.set_redirect_uris(redirect_uris);
        self
    }

    /// Appends a redirection URI.
    pub fn add_redirect_uri(mut self, redirect_uri: RedirectUrl) -> Self {
        self.inner = self.inner.add_redirect_uri(redirect_uri);
        self
    }

    /// Sets the requested token endpoint authentication method.
    pub fn set_token_endpoint_auth_method<N>(mut self, method: N) -> Self
    where
        N: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_token_endpoint_auth_method(method);
        self
    }

    /// Sets the OAuth 2.0 grant types the client may use.
    pub fn set_grant_types<I, S>(mut self, grant_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_grant_types(grant_types);
        self
    }

    /// Appends an OAuth 2.0 grant type.
    pub fn add_grant_type<S>(mut self, grant_type: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_grant_type(grant_type);
        self
    }

    /// Sets the OAuth 2.0 response types the client may use.
    pub fn set_response_types<I>(mut self, response_types: I) -> Self
    where
        I: IntoIterator<Item = Cow<'a, ResponseType>>,
    {
        self.inner = self.inner.set_response_types(response_types);
        self
    }

    /// Appends an OAuth 2.0 response type.
    pub fn add_response_type(mut self, response_type: ResponseType) -> Self {
        self.inner = self.inner.add_response_type(response_type);
        self
    }

    /// Sets the human-readable client name.
    pub fn set_client_name(mut self, client_name: ClientName) -> Self {
        self.inner = self.inner.set_client_name(client_name);
        self
    }

    /// Sets the URL of a web page providing information about the client.
    pub fn set_client_uri<U>(mut self, client_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_client_uri(client_uri);
        self
    }

    /// Sets the URL of the client's logo.
    pub fn set_logo_uri<U>(mut self, logo_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_logo_uri(logo_uri);
        self
    }

    /// Sets the space-separated scope values the client may request.
    pub fn set_scope(mut self, scope: Scope) -> Self {
        self.inner = self.inner.set_scope(scope);
        self
    }

    /// Sets the space-separated scope values the client may request.
    pub fn set_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.inner = self.inner.set_scopes(scopes);
        self
    }

    /// Sets contact addresses for people responsible for this client.
    pub fn set_contacts<I, S>(mut self, contacts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_contacts(contacts);
        self
    }

    /// Appends a contact address.
    pub fn add_contact<S>(mut self, contact: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_contact(contact);
        self
    }

    /// Sets the URL of the client's terms of service document.
    pub fn set_tos_uri<U>(mut self, tos_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_tos_uri(tos_uri);
        self
    }

    /// Sets the URL of the client's privacy policy document.
    pub fn set_policy_uri<U>(mut self, policy_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_policy_uri(policy_uri);
        self
    }

    /// Sets the URL of the client's JSON Web Key Set document.
    pub fn set_jwks_uri<U>(mut self, jwks_uri: U) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_jwks_uri(jwks_uri);
        self
    }

    /// Sets the client's JSON Web Key Set document value.
    pub fn set_jwks(mut self, jwks: serde_json::Value) -> Self {
        self.inner = self.inner.set_jwks(jwks);
        self
    }

    /// Sets the software identifier for the client software.
    pub fn set_software_id<S>(mut self, software_id: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_software_id(software_id);
        self
    }

    /// Sets the software version identifier for the client software.
    pub fn set_software_version<S>(mut self, software_version: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_software_version(software_version);
        self
    }

    /// Sets the signed software statement JWT.
    pub fn set_software_statement<S>(mut self, software_statement: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.set_software_statement(software_statement);
        self
    }

    /// Sets the initial access token used to authorize protected registration requests.
    pub fn set_initial_access_token(mut self, initial_access_token: AccessToken) -> Self {
        self.inner = self.inner.set_initial_access_token(initial_access_token);
        self
    }

    /// Appends an extra parameter to the registration request.
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_extra_param(name, value);
        self
    }

    /// Synchronously sends the registration request and returns an OAuth 2.0 client configured
    /// with the registered `client_id` and `client_secret`.
    pub fn register<C>(
        self,
        http_client: &C,
    ) -> Result<
        (
            Client<
                TE,
                TR,
                TIR,
                RT,
                TRE,
                EndpointNotSet,
                EndpointNotSet,
                EndpointNotSet,
                EndpointNotSet,
                EndpointNotSet,
            >,
            DynamicClientRegistrationResponse<EF>,
        ),
        RequestTokenError<<C as SyncHttpClient>::Error, TE>,
    >
    where
        C: SyncHttpClient,
    {
        self.inner
            .request::<C, EF>(http_client)
            .map(|response| (response.to_client(), response))
    }

    /// Asynchronously sends the registration request and returns a Future that resolves to an
    /// OAuth 2.0 client configured with the registered `client_id` and `client_secret`.
    pub fn register_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<
            (
                Client<
                    TE,
                    TR,
                    TIR,
                    RT,
                    TRE,
                    EndpointNotSet,
                    EndpointNotSet,
                    EndpointNotSet,
                    EndpointNotSet,
                    EndpointNotSet,
                >,
                DynamicClientRegistrationResponse<EF>,
            ),
            RequestTokenError<<C as AsyncHttpClient<'c>>::Error, TE>,
        >,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        async move {
            self.inner
                .request_async::<C, EF>(http_client)
                .await
                .map(|response| (response.to_client(), response))
        }
    }
}

#[derive(Serialize)]
struct DynamicClientRegistrationRequestBody<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redirect_uris: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    grant_types: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_types: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_uri: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contacts: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_uri: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_id: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_version: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_statement: Option<Cow<'a, str>>,
    #[serde(flatten)]
    extra: HashMap<&'a str, &'a str>,
}

/// Trait for adding extra fields to the [`DynamicClientRegistrationResponse`].
pub trait ExtraDynamicClientRegistrationFields: DeserializeOwned + Debug + Serialize {}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Empty (default) extra dynamic client registration fields.
pub struct EmptyExtraDynamicClientRegistrationFields {}
impl ExtraDynamicClientRegistrationFields for EmptyExtraDynamicClientRegistrationFields {}

/// Standard OAuth 2.0 dynamic client registration response.
///
/// See <https://tools.ietf.org/html/rfc7591#section-3.2.1>.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DynamicClientRegistrationResponse<EF>
where
    EF: ExtraDynamicClientRegistrationFields,
{
    client_id: ClientId,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<ClientSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id_issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret_expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    redirect_uris: Option<Vec<RedirectUrl>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    response_types: Option<Vec<ResponseType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<ClientName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<String>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "crate::helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "crate::helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_statement: Option<String>,
    #[serde(bound = "EF: ExtraDynamicClientRegistrationFields", flatten)]
    extra_fields: EF,
}

impl<EF> DynamicClientRegistrationResponse<EF>
where
    EF: ExtraDynamicClientRegistrationFields,
{
    /// OAuth 2.0 client identifier assigned by the authorization server.
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// OAuth 2.0 client secret, if issued for a confidential client.
    pub fn client_secret(&self) -> Option<&ClientSecret> {
        self.client_secret.as_ref()
    }

    /// Time at which the client identifier was issued, as seconds since the Unix epoch.
    pub fn client_id_issued_at(&self) -> Option<u64> {
        self.client_id_issued_at
    }

    /// Time at which the client secret will expire, as seconds since the Unix epoch.
    ///
    /// A value of `0` indicates that the secret will not expire.
    pub fn client_secret_expires_at(&self) -> Option<u64> {
        self.client_secret_expires_at
    }

    /// Returns `true` if the client secret will not expire.
    pub fn client_secret_never_expires(&self) -> bool {
        matches!(self.client_secret_expires_at, Some(0))
    }

    /// Registered redirection URIs for redirect-based flows.
    pub fn redirect_uris(&self) -> Option<&Vec<RedirectUrl>> {
        self.redirect_uris.as_ref()
    }

    /// Registered token endpoint authentication method.
    pub fn token_endpoint_auth_method(&self) -> Option<&str> {
        self.token_endpoint_auth_method.as_deref()
    }

    /// Registered OAuth 2.0 grant types.
    pub fn grant_types(&self) -> Option<&Vec<String>> {
        self.grant_types.as_ref()
    }

    /// Registered OAuth 2.0 response types.
    pub fn response_types(&self) -> Option<&Vec<ResponseType>> {
        self.response_types.as_ref()
    }

    /// Registered human-readable client name.
    pub fn client_name(&self) -> Option<&ClientName> {
        self.client_name.as_ref()
    }

    /// Registered URL of a web page providing information about the client.
    pub fn client_uri(&self) -> Option<&str> {
        self.client_uri.as_deref()
    }

    /// Registered URL of the client's logo.
    pub fn logo_uri(&self) -> Option<&str> {
        self.logo_uri.as_deref()
    }

    /// Registered scope values the client may request.
    pub fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }

    /// Registered contact addresses for people responsible for this client.
    pub fn contacts(&self) -> Option<&Vec<String>> {
        self.contacts.as_ref()
    }

    /// Registered URL of the client's terms of service document.
    pub fn tos_uri(&self) -> Option<&str> {
        self.tos_uri.as_deref()
    }

    /// Registered URL of the client's privacy policy document.
    pub fn policy_uri(&self) -> Option<&str> {
        self.policy_uri.as_deref()
    }

    /// Registered URL of the client's JSON Web Key Set document.
    pub fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    /// Registered JSON Web Key Set document value.
    pub fn jwks(&self) -> Option<&serde_json::Value> {
        self.jwks.as_ref()
    }

    /// Registered software identifier for the client software.
    pub fn software_id(&self) -> Option<&str> {
        self.software_id.as_deref()
    }

    /// Registered software version identifier for the client software.
    pub fn software_version(&self) -> Option<&str> {
        self.software_version.as_deref()
    }

    /// Software statement returned unmodified when one was included in the registration request.
    pub fn software_statement(&self) -> Option<&str> {
        self.software_statement.as_deref()
    }

    /// Any extra fields returned on the response.
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }
}

impl<EF> DynamicClientRegistrationResponse<EF>
where
    EF: ExtraDynamicClientRegistrationFields,
{
    /// Converts this registration response into an OAuth 2.0 client with the registered
    /// `client_id` and `client_secret`.
    ///
    /// Authorization, token, and other endpoint URLs are not set and must be configured
    /// separately before the client can be used for authorization flows.
    pub fn to_client<TE, TR, TIR, RT, TRE>(
        &self,
    ) -> Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
    >
    where
        TE: ErrorResponse + 'static,
        TR: TokenResponse,
        TIR: TokenIntrospectionResponse,
        RT: RevocableToken,
        TRE: ErrorResponse + 'static,
    {
        Client {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            auth_url: None,
            auth_type: AuthType::BasicAuth,
            token_url: None,
            redirect_url: None,
            introspection_url: None,
            revocation_url: None,
            device_authorization_url: None,
            phantom: PhantomData,
        }
    }
}

/// Standard implementation of [`DynamicClientRegistrationResponse`] which throws away extra received
/// response fields.
pub type StandardDynamicClientRegistrationResponse =
    DynamicClientRegistrationResponse<EmptyExtraDynamicClientRegistrationFields>;

/// Dynamic client registration error types.
///
/// These error types are defined in
/// [Section 3.2.2 of RFC 7591](https://tools.ietf.org/html/rfc7591#section-3.2.2).
#[derive(Clone, PartialEq, Eq)]
pub enum DynamicClientRegistrationErrorResponseType {
    /// The value of one or more redirection URIs is invalid.
    InvalidRedirectUri,
    /// The value of one of the client metadata fields is invalid and the server has rejected this
    /// request.
    InvalidClientMetadata,
    /// The software statement presented is invalid.
    InvalidSoftwareStatement,
    /// The software statement presented is not approved for use by this authorization server.
    UnapprovedSoftwareStatement,
    /// A Basic response type.
    Basic(BasicErrorResponseType),
}
impl DynamicClientRegistrationErrorResponseType {
    fn from_str(s: &str) -> Self {
        match BasicErrorResponseType::from_str(s) {
            BasicErrorResponseType::Extension(ext) => match ext.as_str() {
                "invalid_redirect_uri" => {
                    DynamicClientRegistrationErrorResponseType::InvalidRedirectUri
                }
                "invalid_client_metadata" => {
                    DynamicClientRegistrationErrorResponseType::InvalidClientMetadata
                }
                "invalid_software_statement" => {
                    DynamicClientRegistrationErrorResponseType::InvalidSoftwareStatement
                }
                "unapproved_software_statement" => {
                    DynamicClientRegistrationErrorResponseType::UnapprovedSoftwareStatement
                }
                _ => DynamicClientRegistrationErrorResponseType::Basic(
                    BasicErrorResponseType::Extension(ext),
                ),
            },
            basic => DynamicClientRegistrationErrorResponseType::Basic(basic),
        }
    }
}
impl AsRef<str> for DynamicClientRegistrationErrorResponseType {
    fn as_ref(&self) -> &str {
        match self {
            DynamicClientRegistrationErrorResponseType::InvalidRedirectUri => {
                "invalid_redirect_uri"
            }
            DynamicClientRegistrationErrorResponseType::InvalidClientMetadata => {
                "invalid_client_metadata"
            }
            DynamicClientRegistrationErrorResponseType::InvalidSoftwareStatement => {
                "invalid_software_statement"
            }
            DynamicClientRegistrationErrorResponseType::UnapprovedSoftwareStatement => {
                "unapproved_software_statement"
            }
            DynamicClientRegistrationErrorResponseType::Basic(basic) => basic.as_ref(),
        }
    }
}
impl<'de> serde::Deserialize<'de> for DynamicClientRegistrationErrorResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let variant_str = String::deserialize(deserializer)?;
        Ok(Self::from_str(&variant_str))
    }
}
impl serde::ser::Serialize for DynamicClientRegistrationErrorResponseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl ErrorResponseType for DynamicClientRegistrationErrorResponseType {}
impl Debug for DynamicClientRegistrationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        Display::fmt(self, f)
    }
}

impl Display for DynamicClientRegistrationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}

/// Error response specialization for dynamic client registration.
pub type DynamicClientRegistrationErrorResponse =
    StandardErrorResponse<DynamicClientRegistrationErrorResponseType>;
