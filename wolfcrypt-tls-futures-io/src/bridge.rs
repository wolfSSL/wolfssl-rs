// wolfSSL custom IO callback shims — futures::io edition.
//
// Identical buffer architecture to wolfcrypt-tls-tokio::bridge.
// The callbacks are byte-for-byte the same C ABI functions; only the
// async driver (stream.rs) differs — it calls futures::io::AsyncRead/Write
// instead of tokio::io::AsyncRead/Write.
//
// Registration is done via TlsClientConfig::new_ssl_with_io_callbacks /
// TlsServerConfig::new_ssl_with_io_callbacks (wolfcrypt-tls option-3 API).
//
// Safety invariant: NetBuffers is heap-allocated and lives for the entire
// lifetime of the WOLFSSL session.  The raw pointer stored inside wolfSSL
// via wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx remains valid as long as
// the TlsStream that owns the Box<NetBuffers> is alive.

use bytes::{Buf, BufMut, BytesMut};
use wolfcrypt_sys::WOLFSSL;

// Return codes expected by wolfSSL custom IO callbacks.
pub(crate) const CBIO_ERR_WANT_READ: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_WANT_WRITE: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_GENERAL: std::ffi::c_int = -1;

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL custom IO callbacks.
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

/// Custom recv callback: drain bytes from `net_in` into wolfSSL's buffer.
///
/// Returns the number of bytes copied, or `CBIO_ERR_WANT_READ` if `net_in`
/// is empty (wolfSSL will retry after the async layer refills it).
///
/// # Safety
/// Called from wolfSSL C code. `ctx` is a `*mut NetBuffers` cast to
/// `*mut c_void`, installed via `wolfSSL_SetIOReadCtx`.
pub(crate) unsafe extern "C" fn recv_cb(
    _ssl: *mut WOLFSSL,
    buf: *mut std::ffi::c_char,
    sz: std::ffi::c_int,
    ctx: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    todo!("drain net_in into buf; return byte count or CBIO_ERR_WANT_READ")
}

/// Custom send callback: append wolfSSL's output bytes into `net_out`.
///
/// Always succeeds immediately — bytes are buffered in `net_out` and
/// flushed to the network asynchronously by the poll_write driver.
///
/// # Safety
/// Called from wolfSSL C code. `ctx` is a `*mut NetBuffers` cast to
/// `*mut c_void`, installed via `wolfSSL_SetIOWriteCtx`.
pub(crate) unsafe extern "C" fn send_cb(
    _ssl: *mut WOLFSSL,
    buf: *mut std::ffi::c_char,
    sz: std::ffi::c_int,
    ctx: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    todo!("append buf into net_out; return sz")
}

/// The recv callback as a `CallbackIORecv` option value.
pub(crate) const RECV_CB: wolfssl::CallbackIORecv = Some(recv_cb);

/// The send callback as a `CallbackIOSend` option value.
pub(crate) const SEND_CB: wolfssl::CallbackIOSend = Some(send_cb);
