// TlsStream<IO>: tokio::io::AsyncRead + AsyncWrite over a wolfSSL session.
//
// Three network-side buffers:
//   net_in   — encrypted bytes from network, waiting for wolfSSL recv callback
//   net_out  — encrypted bytes wolfSSL produced, waiting to flush to network
//   read_buf — decrypted application data ready for the caller's poll_read
//
// wolfSSL's recv/send callbacks (bridge.rs IOCallbacks impl) operate
// synchronously on net_in/net_out.  All real async network I/O happens here
// in poll_read / poll_write around wolfSSL calls.

use std::io;
use std::pin::Pin;

use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use wolfssl::{TlsClientConfig, TlsServerConfig};

use crate::bridge::NetBuffers;

/// Keeps the `WOLFSSL_CTX` alive for the entire lifetime of the WOLFSSL session.
///
/// `TlsClientConfig` / `TlsServerConfig` are already `Arc`-backed internally,
/// so cloning one is a cheap refcount bump.  No outer `Arc` wrapping needed.
#[allow(dead_code)]
pub(crate) enum ConfigHolder {
    Client(TlsClientConfig),
    Server(TlsServerConfig),
}

/// An established TLS connection over an async transport.
///
/// Implements `tokio::io::AsyncRead + AsyncWrite`.  Obtain via
/// `TlsConnector::connect` or `TlsAcceptor::accept`.
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    /// Owned wolfSSL session; freed on drop.
    pub(crate) ssl: *mut wolfcrypt_sys::WOLFSSL,
    /// Network-side buffers; Box gives a stable address for wolfSSL's ctx ptr.
    pub(crate) net: Box<NetBuffers>,
    /// Decrypted plaintext waiting to be returned to the caller.
    pub(crate) read_buf: BytesMut,
    /// Keeps the WOLFSSL_CTX alive.
    pub(crate) _config: ConfigHolder,
    /// True once wolfSSL_shutdown has been called in poll_shutdown.
    /// Prevents calling wolfSSL_shutdown again on re-polls, which would
    /// send duplicate close_notify alerts.
    pub(crate) shutdown_sent: bool,
}

// SAFETY: accessed only via &mut self; WOLFSSL sessions are not Sync.
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
    ///
    /// Returns `None` if the session has not completed its handshake yet or
    /// if the version is not recognised.
    pub fn negotiated_version(&self) -> Option<wolfssl::ProtocolVersion> {
        // SAFETY: ssl is valid; wolfSSL_version takes *mut WOLFSSL but does
        // not mutate the session state.
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
            // wolfSSL_free quiesces callback use before returning, so it is
            // safe to drop self.net immediately after.
            //
            // Call wolfSSL_shutdown only if poll_shutdown has not already done
            // so.  Calling it twice would send duplicate close_notify records
            // into net_out (which cannot be flushed from Drop anyway).
            // For a clean bidirectional shutdown call shutdown().await first.
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
    /// Fill `net_in` from the underlying IO.  Returns Ready once ≥1 byte
    /// arrives, Pending if no data yet, or Err on EOF/IO error.
    pub(crate) fn fill_net_in(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.net.net_in.reserve(READ_CHUNK);
        let spare = self.net.net_in.spare_capacity_mut();
        let mut read_buf = ReadBuf::uninit(spare);
        match Pin::new(&mut self.io).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed the connection",
                    )));
                }
                // SAFETY: poll_read filled exactly n bytes.
                unsafe { self.net.net_in.advance_mut(n) };
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Flush `net_out` to the underlying IO.  Loops until empty or Pending.
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
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // 1. If we have decrypted data buffered, hand it to the caller.
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 2. Refill net_in from the network — but only if it's empty.
            // If net_in already has bytes, wolfSSL can make progress without
            // blocking on the network.  Calling fill_net_in when net_in is
            // non-empty would unnecessarily wait for more data to arrive.
            if this.net.net_in.is_empty() {
                match this.fill_net_in(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
            }

            // 3. Drive wolfSSL_read; it pulls from net_in via recv callback.
            // Track net_in length before each call to detect whether wolfSSL
            // made progress (consumed bytes).  If WANT_READ is returned with
            // no bytes consumed, wolfSSL is stalled waiting for more ciphertext;
            // call fill_net_in to get it (and re-register the waker).
            loop {
                let net_in_before = this.net.net_in.len();

                // Use a stack buffer to receive decrypted records.
                // 16 KB + 1 is the maximum TLS record plaintext size.
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
                    // Keep looping — there may be more records buffered.
                    continue;
                }

                if ret == 0 {
                    // Clean close_notify from peer. Deliver any buffered
                    // plaintext first before signaling EOF.
                    if !this.read_buf.is_empty() {
                        let n = buf.remaining().min(this.read_buf.len());
                        buf.put_slice(&this.read_buf[..n]);
                        this.read_buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Ok(()));
                }

                // ret < 0 — check the error code.
                // wolfSSL_get_error returns WOLFSSL_ERROR_WANT_READ (2) /
                // WOLFSSL_ERROR_WANT_WRITE (3) — the positive OpenSSL compat
                // values — even for wolfSSL_read.  The negative enum variants
                // (WANT_READ_E = -2) are what the recv/send callbacks return
                // to wolfSSL internally; they do not surface from get_error.
                // SAFETY: ssl is valid.
                let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(this.ssl, ret) };
                let want_read = wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as i32;
                let want_write = wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as i32;
                if err == want_read {
                    let net_in_after = this.net.net_in.len();
                    // Only call fill_net_in immediately if net_in was non-empty
                    // before but wolfSSL consumed nothing (genuine stall).
                    // If net_in was already empty (net_in_before == 0), wolfSSL
                    // correctly returned WANT_READ — normal operation; the outer
                    // loop will call fill_net_in on the next iteration.
                    if net_in_before > 0 && net_in_after == net_in_before {
                        // No progress despite having bytes: wolfSSL needs more
                        // to complete a record.  Get more and retry.
                        match this.fill_net_in(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => continue,
                        }
                    }
                    // Normal WANT_READ: break to outer loop to fill net_in.
                    break;
                } else if err == want_write {
                    // wolfSSL produced output (e.g. renegotiation handshake
                    // record) and needs it sent before it can continue.
                    // Flush properly: if the write side is not ready, register
                    // a write waker and return Pending so we're re-woken when
                    // the transport becomes writable.
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

            // 4. Return any plaintext we gathered this round.
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // wolfSSL consumed net_in but produced no app data (e.g. a session
            // ticket or alert).  Loop back to step 2 to fill net_in again —
            // this also re-registers the waker so we get woken when the peer
            // sends more.  If no data is available yet, fill_net_in returns
            // Pending.
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
            // wolfSSL_write encrypts buf and deposits ciphertext into net_out via
            // send callback.  This is synchronous — it always accepts the full
            // application record (wolfSSL buffers internally per record).
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
                // If the transport isn't ready, return Pending (write waker registered).
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
                // it can encrypt.  Fill net_in; if data is immediately available,
                // retry wolfSSL_write rather than returning Pending without a waker.
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Only call wolfSSL_shutdown once.  On re-polls (when flush_net_out
        // or the underlying poll_shutdown returned Pending), skip straight to
        // flushing — calling it again would send a duplicate close_notify.
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
            // ret == 0 (WOLFSSL_SHUTDOWN_NOT_DONE), 1 (SUCCESS), or WANT_*:
            // flush what wolfSSL put in net_out (our close_notify record) and
            // close the underlying IO.  We do not wait for the peer's
            // close_notify — doing so would require another async read cycle.
        }

        // Flush the close_notify record to the wire.
        match this.flush_net_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        // Shut down the underlying IO layer.
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// Delegate to `wolfssl::error_string` for a human-readable error description.
fn wolfssl_error_string(code: core::ffi::c_int) -> &'static str {
    wolfssl::error_string(code)
}
