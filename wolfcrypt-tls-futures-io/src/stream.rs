// TlsStream<IO>: futures::io::AsyncRead + AsyncWrite over a wolfSSL session.
//
// Identical buffer architecture to wolfcrypt-tls-tokio::stream; only the
// async trait signatures differ:
//   poll_read:  buf is &mut [u8], returns Poll<io::Result<usize>>  (not ReadBuf / ())
//   poll_close: futures::io name for poll_shutdown

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use futures_io::{AsyncRead, AsyncWrite};

use wolfssl::{TlsClientConfig, TlsServerConfig};

use crate::bridge::NetBuffers;

/// Keeps the `WOLFSSL_CTX` alive for the lifetime of the WOLFSSL session.
#[allow(dead_code)]
pub(crate) enum ConfigHolder {
    Client(Arc<TlsClientConfig>),
    Server(Arc<TlsServerConfig>),
}

/// An established TLS connection over a futures::io async transport.
///
/// Implements `futures::io::AsyncRead + AsyncWrite`.  Works with smol,
/// async-std, async-executor, or tokio via `tokio-util`'s `Compat` wrapper.
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) ssl: *mut wolfcrypt_sys::WOLFSSL,
    pub(crate) net: Box<NetBuffers>,
    pub(crate) read_buf: BytesMut,
    pub(crate) _config: ConfigHolder,
}

unsafe impl<IO: Send> Send for TlsStream<IO> {}

impl<IO> Drop for TlsStream<IO> {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
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
    /// Fill `net_in` from the underlying futures::io transport.
    ///
    /// futures::io::AsyncRead::poll_read takes `&mut [u8]` (initialized).
    /// We use `chunk_mut()` to reach the spare BytesMut region without
    /// zero-initializing it — sound because we only advance_mut by the bytes
    /// poll_read confirms it wrote.
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.net.net_in.reserve(READ_CHUNK);
        let spare_len = self.net.net_in.spare_capacity_mut().len();

        // SAFETY: chunk_mut() points into uninitialized spare capacity.
        // We only expose the region to poll_read and advance by what it wrote.
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
                // SAFETY: poll_read wrote n bytes into the spare region.
                unsafe { self.net.net_in.advance_mut(n) };
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Flush `net_out` to the underlying futures::io transport.
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
                Poll::Ready(Ok(n)) => self.net.net_out.advance(n),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    /// futures::io returns the byte count directly; tokio returns () and uses ReadBuf.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;

        loop {
            if !this.read_buf.is_empty() {
                let n = buf.len().min(this.read_buf.len());
                buf[..n].copy_from_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(n));
            }

            // Only fill net_in when it's empty — if it already has bytes,
            // wolfSSL can proceed without waiting for more network data.
            if this.net.net_in.is_empty() {
                match this.fill_net_in(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
            }

            loop {
                let mut tmp = [0u8; 16385];
                let len = tmp.len().min(i32::MAX as usize) as i32;
                // SAFETY: ssl is valid; exclusive access via &mut self.
                let ret = unsafe {
                    wolfcrypt_sys::wolfSSL_read(
                        this.ssl,
                        tmp.as_mut_ptr() as *mut core::ffi::c_void,
                        len,
                    )
                };

                if ret > 0 {
                    this.read_buf.extend_from_slice(&tmp[..ret as usize]);
                    let _ = this.flush_net_out(cx);
                    continue;
                }
                if ret == 0 {
                    return Poll::Ready(Ok(0));
                }
                let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
                let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
                let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
                if err == want_read {
                    break;
                } else if err == want_write {
                    let _ = this.flush_net_out(cx);
                    break;
                } else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "wolfSSL_read error {err}: {}",
                            wolfssl_error_string(err)
                        ),
                    )));
                }
            }

            if !this.read_buf.is_empty() {
                let n = buf.len().min(this.read_buf.len());
                buf[..n].copy_from_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(n));
            }

            // Loop back to fill_net_in to re-register the waker and get more data.
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        let len = buf.len().min(i32::MAX as usize) as i32;
        // SAFETY: ssl is valid.
        let ret = unsafe {
            wolfcrypt_sys::wolfSSL_write(
                this.ssl,
                buf.as_ptr() as *const core::ffi::c_void,
                len,
            )
        };
        if ret > 0 {
            let _ = this.flush_net_out(cx);
            return Poll::Ready(Ok(ret as usize));
        }
        let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Other,
            format!("wolfSSL_write error {err}: {}", wolfssl_error_string(err)),
        )))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_net_out(cx)
    }

    /// futures::io uses `poll_close`; tokio uses `poll_shutdown`.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // SAFETY: ssl is valid.
        let ret = unsafe { wolfcrypt_sys::wolfSSL_shutdown(this.ssl) };

        match this.flush_net_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        if ret < 0 {
            let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("wolfSSL_shutdown error {err}: {}", wolfssl_error_string(err)),
            )));
        }

        Pin::new(&mut this.io).poll_close(cx)
    }
}

fn wolfssl_error_string(code: core::ffi::c_int) -> String {
    unsafe {
        let ptr = wolfcrypt_sys::wolfSSL_ERR_reason_error_string(
            (code as core::ffi::c_uint) as core::ffi::c_ulong,
        );
        if ptr.is_null() {
            return format!("unknown error {code}");
        }
        std::ffi::CStr::from_ptr(ptr)
            .to_str()
            .unwrap_or("unknown")
            .to_owned()
    }
}
