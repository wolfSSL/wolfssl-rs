// TlsStream<IO>: futures::io::AsyncRead + AsyncWrite over a wolfSSL session.
//
// Identical buffer architecture to wolfcrypt-tls-tokio::stream; only the
// async trait signatures differ:
//   poll_read:  buf is &mut [u8], returns Poll<io::Result<usize>>  (not ReadBuf / ())
//   poll_close: futures::io name for poll_shutdown

use std::io;
use std::pin::Pin;

use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use futures_io::{AsyncRead, AsyncWrite};

use wolfssl::{TlsClientConfig, TlsServerConfig};

use crate::bridge::NetBuffers;

/// Keeps the `WOLFSSL_CTX` alive for the lifetime of the WOLFSSL session.
///
/// `TlsClientConfig` / `TlsServerConfig` are already `Arc`-backed internally,
/// so cloning one is a cheap refcount bump.  No outer `Arc` wrapping needed.
#[allow(dead_code)]
pub(crate) enum ConfigHolder {
    Client(TlsClientConfig),
    Server(TlsServerConfig),
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
    /// True once wolfSSL_shutdown has been called in poll_close.
    /// Prevents sending duplicate close_notify alerts on re-polls.
    pub(crate) shutdown_sent: bool,
}

unsafe impl<IO: Send> Send for TlsStream<IO> {}
// Not Sync: WOLFSSL sessions require exclusive access (&mut self) for all
// I/O operations and are not internally synchronized.

impl<IO: std::fmt::Debug> std::fmt::Debug for TlsStream<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("ssl", &self.ssl)
            .field("negotiated_version", &self.negotiated_version())
            .field("shutdown_sent", &self.shutdown_sent)
            .finish_non_exhaustive()
    }
}

impl<IO> TlsStream<IO> {
    /// Return the TLS protocol version negotiated during the handshake.
    pub fn negotiated_version(&self) -> Option<wolfssl::ProtocolVersion> {
        // SAFETY: ssl is valid; wolfSSL_version does not mutate session state.
        let v = unsafe { wolfcrypt_sys::wolfSSL_version(self.ssl) } as u32;
        match v {
            wolfcrypt_sys::TLS1_2_VERSION => Some(wolfssl::ProtocolVersion::Tls12),
            wolfcrypt_sys::TLS1_3_VERSION => Some(wolfssl::ProtocolVersion::Tls13),
            _ => None,
        }
    }
}

impl<IO> Drop for TlsStream<IO> {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            // SAFETY: ssl created by wolfSSL_new, not yet freed.
            // Only call wolfSSL_shutdown if poll_close has not already done so;
            // a second call would send a duplicate close_notify into net_out.
            unsafe {
                if !self.shutdown_sent {
                    let _ = wolfcrypt_sys::wolfSSL_shutdown(self.ssl);
                }
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
    /// `futures::io::AsyncRead::poll_read` takes `&mut [u8]` — an initialized
    /// slice per the trait contract.  We use a zero-initialized stack buffer,
    /// call `poll_read` into it, then `extend_from_slice` only on success.
    /// This avoids leaving stale zero bytes in `net_in` if `poll_read` panics
    /// (unlike the resize+truncate approach which modifies `net_in` before the
    /// call and relies on cleanup code that never runs on unwind).
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut tmp = [0u8; READ_CHUNK];
        match Pin::new(&mut self.io).poll_read(cx, &mut tmp) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed the connection",
            ))),
            Poll::Ready(Ok(n)) => {
                // Only append the bytes that were actually written.
                self.net.net_in.extend_from_slice(&tmp[..n]);
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
                let net_in_before = this.net.net_in.len();

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
                    // Session-ticket or post-handshake record from wolfSSL;
                    // best-effort flush.
                    // Error discarded: the plaintext was already delivered to
                    // the caller.
                    let _ = this.flush_net_out(cx);
                    continue;
                }
                if ret == 0 {
                    // Deliver any buffered plaintext before signaling EOF.
                    if !this.read_buf.is_empty() {
                        let n = buf.len().min(this.read_buf.len());
                        buf[..n].copy_from_slice(&this.read_buf[..n]);
                        this.read_buf.advance(n);
                        return Poll::Ready(Ok(n));
                    }
                    return Poll::Ready(Ok(0));
                }
                let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
                let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
                let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
                if err == want_read {
                    let net_in_after = this.net.net_in.len();
                    // Only call fill_net_in immediately if net_in was non-empty
                    // but wolfSSL consumed nothing — genuine stall needing more
                    // ciphertext to complete a record.  If net_in was already
                    // empty, normal WANT_READ: break to outer loop.
                    if net_in_before > 0 && net_in_after == net_in_before {
                        match this.fill_net_in(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => continue,
                        }
                    }
                    break;
                } else if err == want_write {
                    // wolfSSL produced a handshake record and needs it sent
                    // before it can continue.  Flush properly to register a
                    // write waker if the transport is not yet ready.
                    match this.flush_net_out(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
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
        let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
        let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;

        // Loop to handle TLS renegotiation (WANT_READ/WANT_WRITE from wolfSSL_write).
        // In normal operation (TLS 1.3), wolfSSL_write succeeds or fails fatally on
        // the first call.  TLS 1.2 renegotiation may require servicing read/write events
        // before the write can proceed.
        loop {
            // SAFETY: ssl is valid.
            let ret = unsafe {
                wolfcrypt_sys::wolfSSL_write(
                    this.ssl,
                    buf.as_ptr() as *const core::ffi::c_void,
                    len,
                )
            };
            if ret > 0 {
                // Flush ciphertext best-effort. Per AsyncWrite contract, poll_write
                // only needs to buffer; callers must poll_flush for guaranteed
                // delivery.
                let _ = this.flush_net_out(cx);
                return Poll::Ready(Ok(ret as usize));
            }
            let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
            if err == want_write {
                // wolfSSL cannot proceed with the write yet; flush pending output.
                match this.flush_net_out(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                // Flush succeeded; retry wolfSSL_write.
                continue;
            }
            if err == want_read {
                // TLS renegotiation (TLS 1.2): wolfSSL needs inbound data before
                // it can encrypt.  Fill net_in; if data arrives immediately, retry
                // wolfSSL_write rather than returning Pending without a waker.
                match this.fill_net_in(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {} // data arrived; retry wolfSSL_write
                }
                continue;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("wolfSSL_write error {err}: {}", wolfssl_error_string(err)),
            )));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_net_out(cx)
    }

    /// futures::io uses `poll_close`; tokio uses `poll_shutdown`.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Only call wolfSSL_shutdown once — re-calling it on subsequent polls
        // would send duplicate close_notify records.
        if !this.shutdown_sent {
            // SAFETY: ssl is valid.
            let ret = unsafe { wolfcrypt_sys::wolfSSL_shutdown(this.ssl) };
            this.shutdown_sent = true;

            if ret < 0 {
                let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
                let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
                let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
                if err != want_read && err != want_write {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("wolfSSL_shutdown error {err}: {}", wolfssl_error_string(err)),
                    )));
                }
                // WANT_READ or WANT_WRITE: close_notify is pending on a
                // non-blocking transport; fall through to flush_net_out.
            }
        }

        match this.flush_net_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        Pin::new(&mut this.io).poll_close(cx)
    }
}

fn wolfssl_error_string(code: core::ffi::c_int) -> &'static str {
    wolfssl::error_string(code)
}
