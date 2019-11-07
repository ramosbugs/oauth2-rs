use async_trait::async_trait;
use failure::Fail;
use futures::Future;
use reqwest_futures_03::{Client, RedirectPolicy};

use crate::reqwest::Error;
use crate::{
    token_response, ClientCredentialsTokenRequest, CodeTokenRequest, ErrorResponse, HttpRequest,
    HttpResponse, PasswordTokenRequest, RefreshTokenRequest, RequestTokenError, TokenResponse,
    TokenType,
};

#[async_trait]
pub trait AsyncCodeTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail;
}

#[async_trait]
impl<'a, TE, TR, TT> AsyncCodeTokenRequest<'a, TE, TR, TT> for CodeTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

#[async_trait]
pub trait AsyncRefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail;
}

#[async_trait]
impl<'a, TE, TR, TT> AsyncRefreshTokenRequest<'a, TE, TR, TT>
    for RefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

#[async_trait]
pub trait AsyncPasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail;
}

#[async_trait]
impl<'a, TE, TR, TT> AsyncPasswordTokenRequest<'a, TE, TR, TT>
    for PasswordTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

#[async_trait]
pub trait AsyncClientCredentialsTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail;
}

#[async_trait]
impl<'a, TE, TR, TT> AsyncClientCredentialsTokenRequest<'a, TE, TR, TT>
    for ClientCredentialsTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Fail,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

///
/// Asynchronous HTTP client.
///
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let client = Client::builder()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(RedirectPolicy::none())
        .build()
        .map_err(Error::Reqwest)?;


    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name, value);
    }
    let request = request_builder
        .build()
        .map_err(Error::Reqwest)?;

    let response = client
        .execute(request)
        .await
        .map_err(Error::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().clone();
    let chunks = response
        .bytes()
        .await
        .map_err(Error::Reqwest)?;

     Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}
