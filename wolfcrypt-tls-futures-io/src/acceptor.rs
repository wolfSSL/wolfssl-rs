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
    /// `stream` must implement `futures::io::AsyncRead + AsyncWrite + Unpin` —
    /// the native IO trait for the smol / async-io ecosystem.
    ///
    /// Returns an `Accept` future that drives `wolfSSL_accept` until the
    /// handshake completes.
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, stream: IO) -> Result<Accept<IO>> {
        let mut net = Box::new(NetBuffers::new());

        // SAFETY: net is Box-allocated and kept alive in TlsStream; wolfSSL_free
        // is called in TlsStream::drop before net is dropped.
        let ssl = unsafe {
            self.config.new_session_with_io(&mut *net)
        }
        .map_err(Error::Tls)?;

        Ok(Accept {
            state: Some(TlsStream {
                io: stream,
                ssl,
                net,
                read_buf: bytes::BytesMut::new(),
                shutdown_sent: false,
                _config: crate::stream::ConfigHolder::Server(self.config.clone()),
            }),
            handshake_done: false,
        })
    }
}

/// Future returned by `TlsAcceptor::accept`.
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
                let ret = unsafe { wolfcrypt_sys::wolfSSL_accept(stream.ssl) };

                if ret == success {
                    self.handshake_done = true;
                } else {
                    let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(stream.ssl, ret) };
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
