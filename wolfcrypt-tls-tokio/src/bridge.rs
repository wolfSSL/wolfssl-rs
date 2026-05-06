// wolfSSL custom IO callback shims.
//
// The recv/send callbacks draw from / append to the in-memory network buffers
// (net_in / net_out) held by TlsStream, completely decoupling wolfSSL's
// synchronous C calls from the async executor.
//
// Registration is done via TlsClientConfig::new_ssl_with_io_callbacks /
// TlsServerConfig::new_ssl_with_io_callbacks (wolfcrypt-tls option-3 API),
// not by calling wolfSSL_CTX_SetIORecv directly from this crate.
//
// Safety invariant: the callbacks receive a raw pointer to a `NetBuffers`
// value that is heap-allocated and lives for the entire lifetime of the
// WOLFSSL session.  The pointer is passed as `io_ctx` to
// new_ssl_with_io_callbacks and installed via wolfSSL_SetIOReadCtx /
// wolfSSL_SetIOWriteCtx by wolfcrypt-tls.

use bytes::{Buf, BufMut, BytesMut};
use wolfcrypt_sys::WOLFSSL;

// Return codes expected by wolfSSL custom IO callbacks.
pub(crate) const CBIO_ERR_WANT_READ: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_WANT_WRITE: std::ffi::c_int = -2;
pub(crate) const CBIO_ERR_GENERAL: std::ffi::c_int = -1;

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL custom IO callbacks.
///
/// Heap-allocated via `Box::new`; the raw pointer is passed as `io_ctx` to
/// `new_ssl_with_io_callbacks` and stored inside the wolfSSL session.
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
/// Always succeeds immediately — the bytes are buffered in `net_out` and
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

/// The recv callback as a `CallbackIORecv` option value for passing to
/// `new_ssl_with_io_callbacks`.
pub(crate) const RECV_CB: wolfssl::CallbackIORecv = Some(recv_cb);

/// The send callback as a `CallbackIOSend` option value for passing to
/// `new_ssl_with_io_callbacks`.
pub(crate) const SEND_CB: wolfssl::CallbackIOSend = Some(send_cb);
