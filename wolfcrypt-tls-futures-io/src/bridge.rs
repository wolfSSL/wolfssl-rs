// Async IO bridge for wolfcrypt-tls-futures-io.
//
// Identical architecture to wolfcrypt-tls-tokio::bridge — NetBuffers
// implements wolfssl::IOCallbacks; wolfcrypt-tls generates the extern "C"
// shims and registers them with wolfSSL.
//
// The only difference from the tokio crate is the async driver (stream.rs)
// which uses futures::io::AsyncRead/AsyncWrite instead of tokio's variants.

use bytes::{Buf, BufMut, BytesMut};
use wolfssl::{IOCallbackResult, IOCallbacks};

pub(crate) const CBIO_ERR_WANT_READ: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_WANT_WRITE: std::ffi::c_int = -2;

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
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        todo!("drain net_in into buf; return Ok(n) or WouldBlock")
    }

    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        todo!("append buf into net_out; return Ok(buf.len())")
    }
}
