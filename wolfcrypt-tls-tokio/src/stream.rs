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

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::bridge::NetBuffers;

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
    /// Heap-allocated and pinned so the raw pointer in wolfSSL stays valid.
    pub(crate) net: Box<NetBuffers>,

    /// Decrypted application data ready for the caller.
    pub(crate) read_buf: BytesMut,

    /// Application data from the caller, waiting to be fed to wolfSSL_write.
    pub(crate) write_buf: BytesMut,
}

// SAFETY: The WOLFSSL pointer is accessed only through &mut self, which
// enforces exclusive access.  wolfSSL sessions are not thread-safe; callers
// must not share a TlsStream across threads without external synchronization.
unsafe impl<IO: Send> Send for TlsStream<IO> {}

impl<IO> Drop for TlsStream<IO> {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            unsafe { wolfcrypt_sys::wolfSSL_free(self.ssl) };
            self.ssl = std::ptr::null_mut();
        }
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
