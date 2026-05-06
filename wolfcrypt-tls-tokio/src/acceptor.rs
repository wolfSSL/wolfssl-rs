// TlsAcceptor and Accept future — server-side TLS handshake.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use wolfssl::TlsServerConfig;

use crate::error::Result;
use crate::stream::TlsStream;

/// Server-side TLS acceptor.  Cheap to clone; config is behind an `Arc`.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<TlsServerConfig>,
}

impl TlsAcceptor {
    /// Create an acceptor from an already-built `TlsServerConfig`.
    pub fn from(config: Arc<TlsServerConfig>) -> Self {
        TlsAcceptor { config }
    }

    /// Begin a TLS handshake on an incoming `stream`.
    ///
    /// Returns an `Accept` future that resolves to a ready `TlsStream`.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, stream: IO) -> Accept<IO> {
        todo!("allocate WOLFSSL session, wire callbacks, return Accept future")
    }
}

/// Future returned by `TlsAcceptor::accept`.
///
/// Drives `wolfSSL_accept` in a loop, advancing the buffer machinery,
/// until the handshake completes or a fatal error occurs.
pub struct Accept<IO> {
    state: Option<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("loop: fill_net_in → wolfSSL_accept → flush_net_out → check result")
    }
}
