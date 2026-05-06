// TlsConnector and Connect future — client-side TLS handshake.
//
// Mirrors wolfcrypt-tls-tokio::connector exactly, except the IO bound
// is futures::io::AsyncRead + AsyncWrite + Unpin.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};

use wolfssl::TlsClientConfig;

use crate::bridge::NetBuffers;
use crate::error::{Error, Result};
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
    /// `stream` must implement `futures::io::AsyncRead + AsyncWrite + Unpin` —
    /// the native IO trait for the smol / async-io ecosystem.
    ///
    /// Returns a `Connect` future that drives `wolfSSL_connect` until the
    /// handshake completes.
    pub fn connect<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        server_name: &str,
        stream: IO,
    ) -> Result<Connect<IO>> {
        let mut net = Box::new(NetBuffers::new());

        let ssl = self.config
            .new_session_with_io(server_name, &mut *net)
            .map_err(Error::Tls)?;

        Ok(Connect {
            state: Some(TlsStream {
                io: stream,
                ssl,
                net,
                read_buf: bytes::BytesMut::new(),
                write_buf: bytes::BytesMut::new(),
                _config: crate::stream::ConfigHolder::Client(self.config.clone()),
            }),
        })
    }
}

/// Future returned by `TlsConnector::connect`.
///
/// Drives `wolfSSL_connect` in a loop until the handshake completes or a
/// fatal error occurs.
pub struct Connect<IO> {
    state: Option<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        todo!("loop: fill_net_in → wolfSSL_connect → flush_net_out → check result")
    }
}
