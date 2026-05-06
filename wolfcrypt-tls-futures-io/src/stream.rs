// TlsStream<IO>: futures::io::AsyncRead + AsyncWrite over a wolfSSL session.
//
// Buffer architecture is identical to wolfcrypt-tls-tokio::stream:
//   net_in   — encrypted bytes from network, waiting for wolfSSL recv callback
//   net_out  — encrypted bytes from wolfSSL, waiting to be flushed to network
//   read_buf — decrypted application data ready for the caller's poll_read
//   write_buf — app data from the caller, waiting to be fed to wolfSSL_write
//
// The key difference from the tokio crate: the IO bound is
//   futures::io::AsyncRead + AsyncWrite + Unpin
// instead of tokio::io::AsyncRead + AsyncWrite + Unpin.
//
// The poll_read signature also differs:
//   futures: poll_read(Pin<&mut Self>, &mut Context, &mut [u8]) -> Poll<io::Result<usize>>
//   tokio:   poll_read(Pin<&mut Self>, &mut Context, &mut ReadBuf<'_>) -> Poll<io::Result<()>>
//
// poll_close (futures::io::AsyncWrite) instead of poll_shutdown (tokio).
//
// Session allocation delegates to wolfcrypt-tls's option-3 API:
//   TlsClientConfig::new_ssl_with_io_callbacks (client side)
//   TlsServerConfig::new_ssl_with_io_callbacks (server side)

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures_io::{AsyncRead, AsyncWrite};

use wolfssl::{TlsClientConfig, TlsServerConfig};

use crate::bridge::NetBuffers;

/// Keeps the `WOLFSSL_CTX` alive for the entire lifetime of the `WOLFSSL` session.
pub(crate) enum ConfigHolder {
    Client(Arc<TlsClientConfig>),
    Server(Arc<TlsServerConfig>),
}

/// A TLS stream wrapping an async IO transport.
///
/// Implements `futures::io::AsyncRead + AsyncWrite`.  Drive the TLS handshake
/// first via `TlsConnector::connect` or `TlsAcceptor::accept`; the resulting
/// `TlsStream` is ready for application data.
///
/// Works with any executor that drives `futures::io` — smol, async-std,
/// async-executor, or tokio with `tokio-util`'s `Compat` wrapper.
pub struct TlsStream<IO> {
    /// The underlying async transport.
    pub(crate) io: IO,

    /// wolfSSL session handle.  Owned; freed on drop.
    pub(crate) ssl: *mut wolfcrypt_sys::WOLFSSL,

    /// Network-side buffers shared with the custom IO callbacks.
    pub(crate) net: Box<NetBuffers>,

    /// Decrypted application data ready for the caller.
    pub(crate) read_buf: BytesMut,

    /// Application data from the caller, waiting to be fed to wolfSSL_write.
    pub(crate) write_buf: BytesMut,

    /// Keeps the WOLFSSL_CTX alive for the lifetime of this session.
    pub(crate) _config: ConfigHolder,
}

// SAFETY: The WOLFSSL pointer is accessed only through &mut self (exclusive).
unsafe impl<IO: Send> Send for TlsStream<IO> {}

impl<IO> Drop for TlsStream<IO> {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            // SAFETY: ssl was created by wolfSSL_new and has not been freed.
            unsafe {
                let _ = wolfcrypt_sys::wolfSSL_shutdown(self.ssl);
                wolfcrypt_sys::wolfSSL_free(self.ssl);
            }
            self.ssl = std::ptr::null_mut();
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Poll the underlying IO to fill `net.net_in` with encrypted bytes.
    ///
    /// Uses `futures::io::AsyncRead::poll_read` — `&mut [u8]` buffer, returns
    /// `usize` on success.  This is the key difference from the tokio version
    /// which uses `ReadBuf<'_>`.
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("read from self.io (futures::io::AsyncRead) into self.net.net_in")
    }

    /// Poll the underlying IO to flush `net.net_out` to the wire.
    ///
    /// Uses `futures::io::AsyncWrite::poll_write`.
    pub(crate) fn flush_net_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("write self.net.net_out to self.io (futures::io::AsyncWrite)")
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    /// futures::io signature: `buf: &mut [u8]`, returns `Poll<io::Result<usize>>`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        todo!("drain read_buf, or fill net_in → wolfSSL_read → read_buf")
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        todo!("wolfSSL_write → net_out, then flush net_out")
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("flush net_out to underlying IO")
    }

    /// futures::io uses `poll_close` where tokio uses `poll_shutdown`.
    /// Sends TLS close_notify, flushes net_out, then closes the underlying IO.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("wolfSSL_shutdown → flush net_out → poll_close underlying IO")
    }
}
