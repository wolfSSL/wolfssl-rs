// TlsAcceptor and Accept future — server-side TLS handshake.
//
// Session allocation delegates to TlsServerConfig::new_ssl_with_io_callbacks
// (wolfcrypt-tls option-3 API), which creates the WOLFSSL* and wires up
// bridge::recv_cb / send_cb in one call.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use wolfssl::TlsServerConfig;

use crate::bridge::NetBuffers;
use crate::error::{Error, Result};
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
    /// Allocates a `WOLFSSL` session via
    /// `TlsServerConfig::new_ssl_with_io_callbacks`, wiring bridge::recv_cb /
    /// send_cb as the IO callbacks.  Returns an `Accept` future that drives
    /// `wolfSSL_accept` until the handshake completes.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, stream: IO) -> Result<Accept<IO>> {
        let mut net = Box::new(NetBuffers::new());

        let ssl = self.config
            .new_session_with_io(&mut *net)
            .map_err(Error::Tls)?;

        Ok(Accept {
            state: Some(TlsStream {
                io: stream,
                ssl,
                net,
                read_buf: bytes::BytesMut::new(),
                write_buf: bytes::BytesMut::new(),
                _config: crate::stream::ConfigHolder::Server(self.config.clone()),
            }),
        })
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
