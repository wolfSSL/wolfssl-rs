// TlsStream<IO>: futures::io::AsyncRead + AsyncWrite over a wolfSSL session.
//
// Buffer architecture is identical to wolfcrypt-tls-tokio::stream:
//   net_in   — encrypted bytes from network, waiting for wolfSSL recv callback
//   net_out  — encrypted bytes from wolfSSL, waiting to be flushed to network
//   read_buf — decrypted application data ready for the caller's poll_read
//   write_buf — app data from the caller, waiting to be fed to wolfSSL_write
//
// Key differences from the tokio crate:
//   - IO bound: futures::io::AsyncRead + AsyncWrite + Unpin
//   - poll_read: buf is &mut [u8], returns Poll<io::Result<usize>>
//   - poll_close instead of poll_shutdown
//   - fill_net_in uses the futures::io poll_read signature (no ReadBuf)

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
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

const READ_CHUNK: usize = 4096;

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Poll the underlying IO to fill `net.net_in` with encrypted bytes.
    ///
    /// `futures::io::AsyncRead::poll_read` takes `&mut [u8]` (initialized),
    /// unlike tokio's `ReadBuf` which works with uninitialized memory.
    ///
    /// We use `chunk_mut()` to get a pointer into the spare capacity region
    /// and cast it to `&mut [u8]` without zero-initializing — this is sound
    /// because futures-io's contract is that the implementation writes the
    /// returned number of bytes and we only advance by that count.
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.net.net_in.reserve(READ_CHUNK);

        // SAFETY: chunk_mut() returns the spare capacity region.  We cast
        // to *mut u8 to build an initialized slice reference for poll_read.
        // We only advance_mut by n (the bytes actually written by poll_read),
        // so no uninit bytes are ever exposed as initialized.
        let spare_len = self.net.net_in.spare_capacity_mut().len();
        let buf_slice = unsafe {
            let ptr = self.net.net_in.chunk_mut().as_mut_ptr();
            std::slice::from_raw_parts_mut(ptr, spare_len)
        };

        match Pin::new(&mut self.io).poll_read(cx, buf_slice) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed the connection",
            ))),
            Poll::Ready(Ok(n)) => {
                // SAFETY: poll_read wrote exactly n bytes into the spare region.
                unsafe { self.net.net_in.advance_mut(n) };
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Poll the underlying IO to flush `net.net_out` to the wire.
    pub(crate) fn flush_net_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.net.net_out.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, self.net.net_out.chunk()) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "underlying IO accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.net.net_out.advance(n);
                }
            }
        }
        Poll::Ready(Ok(()))
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
