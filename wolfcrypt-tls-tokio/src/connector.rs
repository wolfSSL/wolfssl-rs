// TlsConnector and Connect future — client-side TLS handshake.
//
// NetBuffers implements wolfssl::IOCallbacks.  new_session_with_io registers
// the wolfcrypt-tls generic shims (io_recv_shim<NetBuffers> / io_send_shim)
// and returns an ssl pointer ready to drive wolfSSL_connect.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

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
        let mut net = Box::new(NetBuffers::new());

        // new_session_with_io registers the shims for NetBuffers: IOCallbacks
        // and returns the raw WOLFSSL* without driving a handshake.
        // SAFETY: net is Box-allocated and kept alive in TlsStream; wolfSSL_free
        // is called in TlsStream::drop before net is dropped.
        let ssl = unsafe {
            self.config.new_session_with_io(server_name, &mut *net)
        }
        .map_err(Error::Tls)?;

        Ok(Connect {
            state: Some(TlsStream {
                io: stream,
                ssl,
                net,
                read_buf: bytes::BytesMut::new(),
                shutdown_sent: false,
                _config: crate::stream::ConfigHolder::Client(self.config.clone()),
            }),
            handshake_done: false,
        })
    }
}

/// Future returned by `TlsConnector::connect`.
///
/// Drives `wolfSSL_connect` in a loop, advancing the buffer machinery,
/// until the handshake completes or a fatal error occurs.
pub struct Connect<IO> {
    state: Option<TlsStream<IO>>,
    /// Set to true once wolfSSL_connect returns WOLFSSL_SUCCESS.
    /// Prevents calling wolfSSL_connect again while we drain net_out.
    handshake_done: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
        let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
        let success = wolfcrypt_sys::WOLFSSL_SUCCESS as i32;

        loop {
            if !self.handshake_done {
                let stream = self.state.as_mut().expect("Connect polled after completion");
                // Drive the handshake one step.  On first call net_in is empty;
                // wolfSSL generates the ClientHello into net_out, returns WANT_READ.
                // SAFETY: ssl is valid; exclusive access via &mut stream.
                let ret = unsafe { wolfcrypt_sys::wolfSSL_connect(stream.ssl) };

                if ret == success {
                    self.handshake_done = true;
                    // Fall through to final flush below.
                } else {
                    let err =
                        unsafe { wolfcrypt_sys::wolfSSL_get_error(stream.ssl, ret) };
                    if err != want_read && err != want_write {
                        return Poll::Ready(Err(Error::Tls(wolfssl::TlsError::Ffi {
                            code: err,
                            func: "wolfSSL_connect",
                        })));
                    }
                    // WANT_READ/WRITE: flush what we produced, then get more data.
                    match stream.flush_net_out(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                        Poll::Ready(Ok(())) => {}
                    }
                    match stream.fill_net_in(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                        Poll::Ready(Ok(())) => continue,
                    }
                }
            }

            // Handshake complete — flush any remaining output then return.
            let stream = self.state.as_mut().unwrap();
            match stream.flush_net_out(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(self.state.take().unwrap())),
            }
        }
    }
}
