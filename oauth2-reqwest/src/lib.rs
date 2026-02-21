#![warn(missing_docs)]
//! A [`reqwest`] client for [`oauth2`].
//!
//! # Motivation
//!
//! The `reqwest` client [bundled](https://docs.rs/oauth2/latest/oauth2/#http-clients) with `oauth2`
//! supports `reqwest` version 0.12. This separate crate supports `reqwest` version 0.13 and is
//! intended to support future versions of `reqwest` without needing a new SemVer major version
//! number for `oauth2` (which would otherwise be required due to breaking changes to that crate's
//! public API).
//!
//! # Usage
//!
//! To get started, add the following dependencies to your crate's `Cargo.toml`:
//! ```toml
//! # Disables oauth2's default reqwest 0.12 client.
//! oauth2 = { version = "5", default-features = false }
//!
//! # Imports reqwest without any feature flags enabled.
#![doc = concat!("oauth2-reqwest = \"", env!("CARGO_PKG_VERSION"), "\"")]
//!
//! # Enables reqwest's default features.
//! reqwest = "0.13"
//! # Alternatively, specify the desired set of features:
//! # reqwest = { version = "0.13", default-features = false, features = ["native-tls"] }
//! ```
//!
//! For flexibility, this crate disables all of `reqwest`'s Cargo feature flags by default. To
//! enable specific `reqwest` features (including its default `rustls` feature), separately import
//! `reqwest` in your crate's `Cargo.toml` and specify the
//! [desired features](https://docs.rs/crate/reqwest/latest/features). This approach leverages Cargo
//! [feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification).
//! While this approach requires a separate import, it provides maximum flexibility and reduces the
//! need for future breaking changes to this crate.
//!
//! ## Asynchronous Client
//!
//! To use the async `reqwest` client, simply wrap the `reqwest` [`Client`](reqwest::Client) with
//! this crate's [`ReqwestClient`] and pass the `ReqwestClient` to the desired `request_async`
//! method:
//!
//! ```rust,no_run
//! use oauth2_reqwest::ReqwestClient;
//!
//! # async fn err_wrapper() -> Result<(), anyhow::Error> {
//! # let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("client_id".to_string()))
//! #     .set_token_uri(oauth2::TokenUrl::new("http://token".to_string())?);
//! let reqwest_client = reqwest::ClientBuilder::new()
//!     // Following redirects opens the client up to SSRF vulnerabilities.
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("Client should build");
//! let http_client = ReqwestClient::from(reqwest_client);
//!
//! # let code = oauth2::AuthorizationCode::new("code".to_string());
//! // This code assumes `client` is a previously constructed `oauth2::Client` and `code` is an
//! // `oauth2::AuthorizationCode`.
//! let token_result = client
//!     .exchange_code(code)
//!     .request_async(&http_client)
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Synchronous Client
//!
//! To use the blocking `reqwest` client, first enable the `blocking` feature in `Cargo.toml`:
//! ```toml
#![doc = concat!("oauth2-reqwest = { version = \"", env!("CARGO_PKG_VERSION"), "\", features = [\"blocking\"] }")]
//! ```
//!
//! Then, simply wrap the `reqwest` blocking [`Client`](reqwest::blocking::Client) with
//! this crate's [`ReqwestBlockingClient`] and pass the `ReqwestBlockingClient` to the desired
//! `request` method:
//!
//! ```rust,no_run
//! # #[cfg(feature = "blocking")]
//! use oauth2_reqwest::ReqwestBlockingClient;
//!
//! # #[cfg(feature = "blocking")]
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! # let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new("client_id".to_string()))
//! #     .set_token_uri(oauth2::TokenUrl::new("http://token".to_string())?);
//! let reqwest_client = reqwest::blocking::ClientBuilder::new()
//!     // Following redirects opens the client up to SSRF vulnerabilities.
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()
//!     .expect("Client should build");
//! let http_client = ReqwestBlockingClient::from(reqwest_client);
//!
//! # let code = oauth2::AuthorizationCode::new("code".to_string());
//! // This code assumes `client` is a previously constructed `oauth2::Client` and `code` is an
//! // `oauth2::AuthorizationCode`.
//! let token_result = client
//!     .exchange_code(code)
//!     .request(&http_client)?;
//!
//! # Ok(())
//! # }
//! ```
use oauth2::{http, AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};
use std::future::Future;
use std::pin::Pin;

/// Asynchronous `reqwest` [`Client`](reqwest::Client) wrapper.
///
/// See the [crate-level documentation](crate) for usage instructions.
pub struct ReqwestClient(reqwest::Client);

impl From<reqwest::Client> for ReqwestClient {
    fn from(inner: reqwest::Client) -> Self {
        Self(inner)
    }
}

impl<'c> AsyncHttpClient<'c> for ReqwestClient {
    type Error = HttpClientError<reqwest::Error>;

    #[cfg(target_arch = "wasm32")]
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;
    #[cfg(not(target_arch = "wasm32"))]
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder().status(response.status());

            #[cfg(not(target_arch = "wasm32"))]
            {
                builder = builder.version(response.version());
            }

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}

#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
pub use blocking::ReqwestBlockingClient;

#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
mod blocking {
    use oauth2::{http, HttpClientError, HttpRequest, HttpResponse};

    /// Synchronous `reqwest` blocking [`Client`](reqwest::blocking::Client) wrapper.
    ///
    /// See the [crate-level documentation](crate) for usage instructions.
    pub struct ReqwestBlockingClient(reqwest::blocking::Client);

    impl<'c> oauth2::SyncHttpClient for ReqwestBlockingClient {
        type Error = HttpClientError<reqwest::Error>;

        fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let mut response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .map_err(Box::new)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            let mut body = Vec::new();
            <reqwest::blocking::Response as std::io::Read>::read_to_end(&mut response, &mut body)?;

            builder.body(body).map_err(HttpClientError::Http)
        }
    }

    impl From<reqwest::blocking::Client> for ReqwestBlockingClient {
        fn from(inner: reqwest::blocking::Client) -> Self {
            Self(inner)
        }
    }
}
