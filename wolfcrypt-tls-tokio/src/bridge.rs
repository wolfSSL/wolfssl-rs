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

// Return codes exposed for use in stream.rs handshake loops.
pub(crate) const CBIO_ERR_WANT_READ: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_WANT_WRITE: std::ffi::c_int = -2;

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL IO callbacks.
///
/// Heap-allocated via `Box::new`; the pointer is passed as `io_ctx` to
/// `new_ssl_with_io_callbacks` and stored inside the wolfSSL session via
/// `wolfSSL_SetIOReadCtx` / `wolfSSL_SetIOWriteCtx`.
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
    /// Returns `WouldBlock` when `net_in` is empty so wolfSSL retries after
    /// the async driver refills it via `fill_net_in`.
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        todo!("drain net_in into buf; return Ok(n) or WouldBlock")
    }

    /// Append wolfSSL's output bytes into `net_out`.
    /// Always succeeds immediately — bytes are flushed to the network
    /// asynchronously by `flush_net_out`.
    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        todo!("append buf into net_out; return Ok(buf.len())")
    }
}
