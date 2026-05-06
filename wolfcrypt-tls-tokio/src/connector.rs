// TlsConnector and Connect future — client-side TLS handshake.
//
// Session allocation delegates to TlsClientConfig::new_ssl_with_io_callbacks
// (wolfcrypt-tls option-3 API), which creates the WOLFSSL* and wires up
// bridge::recv_cb / send_cb in one call.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use wolfssl::TlsClientConfig;

use crate::bridge::{NetBuffers, RECV_CB, SEND_CB};
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
    /// Allocates a `WOLFSSL` session via
    /// `TlsClientConfig::new_ssl_with_io_callbacks`, wiring bridge::recv_cb /
    /// send_cb as the IO callbacks.  Returns a `Connect` future that drives
    /// `wolfSSL_connect` until the handshake completes.
    pub fn connect<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        server_name: &str,
        stream: IO,
    ) -> Result<Connect<IO>> {
        // Heap-allocate the network buffers.  The raw pointer is passed as
        // io_ctx to new_ssl_with_io_callbacks and stored inside wolfSSL.
        // Box::into_raw transfers ownership; TlsStream::drop must Box::from_raw
        // it back to free the allocation.
        let net = Box::new(NetBuffers::new());
        let io_ctx = Box::as_ref(&net) as *const NetBuffers as *mut core::ffi::c_void;

        // SAFETY: recv_cb / send_cb are valid for the lifetime of the session.
        // io_ctx points to the NetBuffers box which is kept alive inside TlsStream.
        let ssl = unsafe {
            self.config
                .new_ssl_with_io_callbacks(server_name, RECV_CB, SEND_CB, io_ctx)
                .map_err(Error::Tls)?
        };

        Ok(Connect {
            state: Some(TlsStream {
                io: stream,
                ssl,
                net,
                read_buf: bytes::BytesMut::new(),
                write_buf: bytes::BytesMut::new(),
                // Keep the config alive so the WOLFSSL_CTX outlives the session.
                _config: crate::stream::ConfigHolder::Client(self.config.clone()),
            }),
        })
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
