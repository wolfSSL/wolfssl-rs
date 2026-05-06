// Async IO bridge for wolfcrypt-tls-tokio.
//
// NetBuffers implements wolfssl::IOCallbacks so it can be passed directly to
// TlsClientConfig::new_ssl_with_io_callbacks / TlsServerConfig::new_ssl_with_io_callbacks.
// wolfcrypt-tls generates the extern "C" shims and registers them with wolfSSL;
// this crate only needs to implement the safe Rust IOCallbacks trait.
//
// recv() — called by wolfSSL to read encrypted bytes:
//   drain from net_in (filled asynchronously by fill_net_in in stream.rs)
//   return WouldBlock when net_in is empty
//
// send() — called by wolfSSL to write encrypted bytes:
//   append to net_out (drained asynchronously by flush_net_out in stream.rs)
//   always succeeds immediately (unbounded buffer)

use bytes::{Buf, BufMut, BytesMut};
use wolfssl::{IOCallbackResult, IOCallbacks};

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL IO callbacks.
///
/// Heap-allocated via `Box::new`; passed to `new_session_with_io` which
/// stores the pointer inside wolfSSL via `wolfSSL_SetIOReadCtx` /
/// `wolfSSL_SetIOWriteCtx`.
pub(crate) struct NetBuffers {
    /// Encrypted bytes read from the network, waiting for wolfSSL to consume.
    pub net_in: BytesMut,
    /// Encrypted bytes wolfSSL has produced, waiting to be flushed to the network.
    pub net_out: BytesMut,
}

impl NetBuffers {
    pub(crate) fn new() -> Self {
        NetBuffers {
            net_in: BytesMut::new(),
            net_out: BytesMut::new(),
        }
    }
}

impl IOCallbacks for NetBuffers {
    /// Drain bytes from `net_in` into wolfSSL's buffer.
    ///
    /// Returns `WouldBlock` when `net_in` is empty — wolfSSL interprets this
    /// as CBIO_ERR_WANT_READ and will retry after the async driver calls
    /// `fill_net_in` to top up the buffer from the network.
    ///
    /// We copy the lesser of what wolfSSL asked for (`buf.len()`) and what
    /// is available (`net_in.len()`), then advance `net_in` to consume those
    /// bytes.  wolfSSL will call `recv` again if it needs more.
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        if self.net_in.is_empty() {
            return IOCallbackResult::WouldBlock;
        }
        let n = buf.len().min(self.net_in.len());
        buf[..n].copy_from_slice(&self.net_in[..n]);
        self.net_in.advance(n);
        IOCallbackResult::Ok(n)
    }

    /// Append wolfSSL's encrypted output bytes into `net_out`.
    ///
    /// Always succeeds immediately — `BytesMut` grows as needed and there is
    /// no meaningful bound on buffered ciphertext (wolfSSL records are at most
    /// ~16 KB each, and the async driver flushes `net_out` on every
    /// `poll_write` / `poll_flush` call).  Returning `WouldBlock` here would
    /// stall the wolfSSL state machine with no way to recover.
    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.net_out.put_slice(buf);
        IOCallbackResult::Ok(buf.len())
    }
}
