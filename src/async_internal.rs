use crate::{
    token_response, ClientCredentialsTokenRequest, CodeTokenRequest, ErrorResponse, HttpRequest,
    HttpResponse, PasswordTokenRequest, RefreshTokenRequest, RequestTokenError, TokenResponse,
    TokenType,
};
use async_trait::async_trait;
use std::error::Error;
use futures_0_3::Future;

///
/// Asynchronous request to exchange an authorization code for an access token.
///
#[async_trait]
pub trait AsyncCodeTokenRequest<TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT> + Send,
    TT: TokenType + Send,
{
    ///
    /// Asynchronously sends the request to the authorization server.
    ///
    async fn request_async<C, F, RE>(self, http_client: C) -> Result<TR, RequestTokenError<RE, TE>>
    where
        C: FnOnce(HttpRequest) -> F + Send,
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: Error + Send + Sync + 'static;
}

#[async_trait]
impl<TE, TR, TT> AsyncCodeTokenRequest<TE, TR, TT> for CodeTokenRequest<'_, TE, TR, TT>
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
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

///
/// Asynchronous request to exchange a refresh token for an access token.
///
#[async_trait]
pub trait AsyncRefreshTokenRequest<TE, TR, TT>
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
        RE: Error + Send + Sync + 'static;
}

#[async_trait]
impl<TE, TR, TT> AsyncRefreshTokenRequest<TE, TR, TT> for RefreshTokenRequest<'_, TE, TR, TT>
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
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

///
/// Asynchronous request to exchange resource owner credentials for an access token.
///
#[async_trait]
pub trait AsyncPasswordTokenRequest<TE, TR, TT>
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
        RE: Error + Send + Sync + 'static;
}

#[async_trait]
impl<TE, TR, TT> AsyncPasswordTokenRequest<TE, TR, TT> for PasswordTokenRequest<'_, TE, TR, TT>
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
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}

///
/// Asynchronous request to exchange client credentials for an access token.
///
#[async_trait]
pub trait AsyncClientCredentialsTokenRequest<TE, TR, TT>
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
        RE: Error + Send + Sync + 'static;
}

#[async_trait]
impl<TE, TR, TT> AsyncClientCredentialsTokenRequest<TE, TR, TT>
    for ClientCredentialsTokenRequest<'_, TE, TR, TT>
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
        RE: Error + Send + Sync + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        token_response(http_response)
    }
}
