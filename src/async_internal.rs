use async_trait::async_trait;
use failure::Fail;
use futures::Future;
use crate::{
    token_response, ClientCredentialsTokenRequest, CodeTokenRequest, ErrorResponse, HttpRequest,
    HttpResponse, PasswordTokenRequest, RefreshTokenRequest, RequestTokenError, TokenResponse,
    TokenType,
};

///
/// Asynchronous request to exchange an authorization code for an access token.
///
#[async_trait]
pub trait AsyncCodeTokenRequest<'a, TE, TR, TT>
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

///
/// Asynchronous request to exchange a refresh token for an access token.
///
#[async_trait]
pub trait AsyncRefreshTokenRequest<'a, TE, TR, TT>
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

///
/// Asynchronous request to exchange resource owner credentials for an access token.
///
#[async_trait]
pub trait AsyncPasswordTokenRequest<'a, TE, TR, TT>
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

///
/// Asynchronous request to exchange client credentials for an access token.
///
#[async_trait]
pub trait AsyncClientCredentialsTokenRequest<'a, TE, TR, TT>
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
