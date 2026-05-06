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
#[derive(Clone, Debug)]
pub struct TlsConnector {
    config: Arc<TlsClientConfig>,
}

impl From<Arc<TlsClientConfig>> for TlsConnector {
    fn from(config: Arc<TlsClientConfig>) -> Self {
        TlsConnector { config }
    }
}

impl TlsConnector {
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
                _config: crate::stream::ConfigHolder::Client((*self.config).clone()),
            }),
            handshake_done: false,
        })
    }
}

/// Future returned by `TlsConnector::connect`.
///
/// Drives `wolfSSL_connect` in a loop until the handshake completes or a
/// fatal error occurs.
pub struct Connect<IO> {
    state: Option<TlsStream<IO>>,
    handshake_done: bool,
}

impl<IO: std::fmt::Debug> std::fmt::Debug for Connect<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connect")
            .field("handshake_done", &self.handshake_done)
            .finish_non_exhaustive()
    }
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
                let ret = unsafe { wolfcrypt_sys::wolfSSL_connect(stream.ssl) };

                if ret == success {
                    self.handshake_done = true;
                } else {
                    let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(stream.ssl, ret) };
                    if err != want_read && err != want_write {
                        return Poll::Ready(Err(Error::Tls(wolfssl::TlsError::Ffi {
                            code: err,
                            func: "wolfSSL_connect",
                        })));
                    }
                    // Always flush any output wolfSSL produced before continuing.
                    match stream.flush_net_out(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                        Poll::Ready(Ok(())) => {}
                    }
                    if err == want_read {
                        // wolfSSL needs inbound data from the peer to continue.
                        match stream.fill_net_in(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                            Poll::Ready(Ok(())) => {}
                        }
                    }
                    // WANT_WRITE: flushed successfully; loop back to call
                    // wolfSSL_connect again.
                    // WANT_READ: filled net_in (or registered read waker);
                    // loop back to call wolfSSL_connect again.
                    continue
                }
            }

            let stream = self.state.as_mut().expect("polled after completion");
            match stream.flush_net_out(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Io(e))),
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(self.state.take().expect("state was None after handshake_done"))),
            }
        }
    }
}
