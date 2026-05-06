// TlsAcceptor and Accept future — server-side TLS handshake.
//
// Mirrors wolfcrypt-tls-tokio::acceptor exactly, except the IO bound
// is futures::io::AsyncRead + AsyncWrite + Unpin.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};

use wolfssl::TlsServerConfig;

use crate::bridge::{NetBuffers, RECV_CB, SEND_CB};
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
    /// `stream` must implement `futures::io::AsyncRead + AsyncWrite + Unpin` —
    /// the native IO trait for the smol / async-io ecosystem.
    ///
    /// Returns an `Accept` future that drives `wolfSSL_accept` until the
    /// handshake completes.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, stream: IO) -> Result<Accept<IO>> {
        let net = Box::new(NetBuffers::new());
        let io_ctx = Box::as_ref(&net) as *const NetBuffers as *mut core::ffi::c_void;

        // SAFETY: recv_cb / send_cb are valid for the lifetime of the session.
        // io_ctx points to the NetBuffers box kept alive inside TlsStream.
        let ssl = unsafe {
            self.config
                .new_ssl_with_io_callbacks(RECV_CB, SEND_CB, io_ctx)
                .map_err(Error::Tls)?
        };

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
/// Drives `wolfSSL_accept` in a loop until the handshake completes or a
/// fatal error occurs.
pub struct Accept<IO> {
    state: Option<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("loop: fill_net_in → wolfSSL_accept → flush_net_out → check result")
    }
}
