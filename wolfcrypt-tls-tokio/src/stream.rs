// TlsStream<IO>: AsyncRead + AsyncWrite over a wolfSSL session.
//
// Owns all four byte buffers described in PLAN-wolfcrypt-tls-tokio.md:
//   net_in   — encrypted bytes from network, waiting for wolfSSL recv callback
//   net_out  — encrypted bytes from wolfSSL, waiting to be flushed to network
//   read_buf — decrypted application data ready for the caller's poll_read
//   write_buf — app data from the caller, waiting to be fed to wolfSSL_write
//
// The recv/send callbacks (bridge.rs) always succeed immediately against
// net_in/net_out.  All actual async network I/O happens here in poll_read /
// poll_write before and after calling into wolfSSL.
//
// Session allocation is done via wolfcrypt-tls's option-3 API:
//   TlsClientConfig::new_ssl_with_io_callbacks (client side)
//   TlsServerConfig::new_ssl_with_io_callbacks (server side)
// This keeps WOLFSSL_CTX creation and cert/key loading in wolfcrypt-tls.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use wolfssl::{TlsClientConfig, TlsServerConfig};

use crate::bridge::NetBuffers;

/// Keeps the `WOLFSSL_CTX` (owned by the config's `Arc<CtxInner>`) alive
/// for the entire lifetime of the `WOLFSSL` session.
pub(crate) enum ConfigHolder {
    Client(Arc<TlsClientConfig>),
    Server(Arc<TlsServerConfig>),
}

/// A TLS stream wrapping an async IO transport.
///
/// Implements `AsyncRead + AsyncWrite`.  Drive the TLS handshake first via
/// `TlsConnector::connect` or `TlsAcceptor::accept`; the resulting
/// `TlsStream` is ready for application data.
pub struct TlsStream<IO> {
    /// The underlying async transport (e.g. `tokio::net::TcpStream`).
    pub(crate) io: IO,

    /// wolfSSL session handle.  Owned; dropped via `wolfSSL_free`.
    pub(crate) ssl: *mut wolfcrypt_sys::WOLFSSL,

    /// Network-side buffers shared with the custom IO callbacks.
    /// Heap-allocated; the raw pointer stored in wolfSSL is valid for as
    /// long as this Box is alive.
    pub(crate) net: Box<NetBuffers>,

    /// Decrypted application data ready for the caller.
    pub(crate) read_buf: BytesMut,

    /// Application data from the caller, waiting to be fed to wolfSSL_write.
    pub(crate) write_buf: BytesMut,

    /// Keeps the WOLFSSL_CTX alive for the lifetime of this session.
    pub(crate) _config: ConfigHolder,
}

// SAFETY: The WOLFSSL pointer is accessed only through &mut self, which
// enforces exclusive access.  wolfSSL sessions are not thread-safe; callers
// must not share a TlsStream across threads without external synchronization.
unsafe impl<IO: Send> Send for TlsStream<IO> {}

impl<IO> Drop for TlsStream<IO> {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            // SAFETY: ssl was created by wolfSSL_new and has not been freed.
            // Best-effort shutdown; errors intentionally ignored during drop.
            unsafe {
                let _ = wolfcrypt_sys::wolfSSL_shutdown(self.ssl);
                wolfcrypt_sys::wolfSSL_free(self.ssl);
            }
            self.ssl = std::ptr::null_mut();
        }
        // net (NetBuffers) is dropped here via Box — the Box::into_raw /
        // Box::from_raw contract: the NetBuffers box was created in
        // connector.rs / acceptor.rs with Box::new and stored directly as
        // pub(crate) net: Box<NetBuffers>.  Drop of TlsStream drops the Box
        // normally, no manual from_raw needed.
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Poll the underlying IO to fill `net.net_in` with encrypted bytes.
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("read from self.io into self.net.net_in")
    }

    /// Poll the underlying IO to flush `net.net_out` to the wire.
    pub(crate) fn flush_net_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("write self.net.net_out to self.io")
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("wolfSSL_shutdown, then flush net_out")
    }
}
