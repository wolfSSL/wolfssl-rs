// TlsConnector and Connect future — client-side TLS handshake.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use wolfssl::{TlsClientConfig, TlsClientConfigBuilder};

use crate::error::Result;
use crate::stream::TlsStream;

/// Client-side TLS connector.  Cheap to clone; config is behind an `Arc`.
#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<TlsClientConfig>,
}

impl TlsConnector {
    /// Create a connector from an already-built `TlsClientConfig`.
    pub fn from(config: Arc<TlsClientConfig>) -> Self {
        TlsConnector { config }
    }

    /// Begin a TLS handshake on `stream`, verifying against `server_name`.
    ///
    /// Returns a `Connect` future that resolves to a ready `TlsStream`.
    pub fn connect<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        server_name: &str,
        stream: IO,
    ) -> Connect<IO> {
        todo!("allocate WOLFSSL session, wire callbacks, return Connect future")
    }
}

/// Future returned by `TlsConnector::connect`.
///
/// Drives `wolfSSL_connect` in a loop, advancing the buffer machinery,
/// until the handshake completes or a fatal error occurs.
pub struct Connect<IO> {
    state: Option<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("loop: fill_net_in → wolfSSL_connect → flush_net_out → check result")
    }
}
