// Async IO bridge for wolfcrypt-tls-futures-io.
//
// Identical architecture to wolfcrypt-tls-tokio::bridge — NetBuffers
// implements wolfssl::IOCallbacks; wolfcrypt-tls generates the extern "C"
// shims and registers them with wolfSSL.
//
// The only difference from the tokio crate is the async driver (stream.rs)
// which uses futures::io::AsyncRead/AsyncWrite instead of tokio's variants.
//
// SISTER FILE: wolfcrypt-tls-tokio/src/bridge.rs holds a byte-for-byte
// identical NetBuffers struct + IOCallbacks impl.  This duplication is
// intentional: consolidating into wolfcrypt-tls would force the base crate
// to take a `bytes` dependency that blocking-only users do not need.  Any
// change to the recv/send semantics here MUST be mirrored in the tokio copy.

use bytes::{Buf, BufMut, BytesMut};
use wolfssl::{IOCallbackResult, IOCallbacks};

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL IO callbacks.
pub(crate) struct NetBuffers {
    pub net_in: BytesMut,
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
    /// Returns `WouldBlock` when empty; the async driver refills via `fill_net_in`.
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        if self.net_in.is_empty() {
            return IOCallbackResult::WouldBlock;
        }
        let n = buf.len().min(self.net_in.len());
        buf[..n].copy_from_slice(&self.net_in[..n]);
        self.net_in.advance(n);
        IOCallbackResult::Ok(n)
    }

    /// Append wolfSSL's encrypted output into `net_out`.
    /// Always succeeds — `net_out` is unbounded and flushed asynchronously.
    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.net_out.put_slice(buf);
        IOCallbackResult::Ok(buf.len())
    }
}
