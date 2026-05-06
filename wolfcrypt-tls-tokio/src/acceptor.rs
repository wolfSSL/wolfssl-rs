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
                _config: crate::stream::ConfigHolder::Server(self.config.clone()),
            }),
            handshake_done: false,
        })
    }
}

/// Future returned by `TlsAcceptor::accept`.
///
/// Drives `wolfSSL_accept` in a loop, advancing the buffer machinery,
/// until the handshake completes or a fatal error occurs.
pub struct Accept<IO> {
    state: Option<TlsStream<IO>>,
    handshake_done: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
        let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
        let success = wolfcrypt_sys::WOLFSSL_SUCCESS as i32;

        loop {
            if !self.handshake_done {
                let stream = self.state.as_mut().expect("Accept polled after completion");
                // SAFETY: ssl is valid; exclusive access via &mut stream.
                let ret = unsafe { wolfcrypt_sys::wolfSSL_accept(stream.ssl) };

                if ret == success {
                    self.handshake_done = true;
                } else {
                    let err =
                        unsafe { wolfcrypt_sys::wolfSSL_get_error(stream.ssl, ret) };
                    if err != want_read && err != want_write {
                        return Poll::Ready(Err(Error::Tls(wolfssl::TlsError::Ffi {
                            code: err,
                            func: "wolfSSL_accept",
                        })));
                    }
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

            let stream = self.state.as_mut().unwrap();
            match stream.flush_net_out(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(self.state.take().unwrap())),
            }
        }
    }
}
