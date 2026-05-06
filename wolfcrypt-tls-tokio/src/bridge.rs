// wolfSSL custom IO callback registration and shims.
//
// wolfSSL_CTX_SetIORecv / wolfSSL_CTX_SetIOSend are registered here.
// The callbacks draw from / append to the in-memory network buffers
// (net_in / net_out) held by TlsStream, completely decoupling wolfSSL's
// synchronous C calls from the async executor.
//
// Safety invariant: the callbacks receive a raw pointer to a `Buffers`
// value that is pinned for the lifetime of the WOLFSSL session.  The
// pointer is set via wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx.

use bytes::{Buf, BufMut, BytesMut};
use wolfcrypt_sys::{WOLFSSL, WOLFSSL_CTX};

// Return codes expected by wolfSSL custom IO callbacks.
const WOLFSSL_CBIO_ERR_WANT_READ: std::ffi::c_int = -2;
const WOLFSSL_CBIO_ERR_WANT_WRITE: std::ffi::c_int = -2;
const WOLFSSL_CBIO_ERR_GENERAL: std::ffi::c_int = -1;

/// The pair of network-side byte buffers shared between the async driver
/// and the wolfSSL custom IO callbacks.
///
/// This struct is heap-allocated and pinned; the raw pointer is stored in
/// the wolfSSL session context via `wolfSSL_SetIOReadCtx` /
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

/// Register the custom recv/send callbacks on a WOLFSSL_CTX.
///
/// # Safety
/// `ctx` must be a valid, non-null WOLFSSL_CTX pointer for its entire lifetime.
pub(crate) unsafe fn register_callbacks(ctx: *mut WOLFSSL_CTX) {
    todo!("wolfSSL_CTX_SetIORecv / wolfSSL_CTX_SetIOSend registration")
}

/// Install the NetBuffers pointer as the IO context for a WOLFSSL session.
///
/// # Safety
/// `ssl` must be valid and `buffers` must outlive the session.
pub(crate) unsafe fn set_io_ctx(ssl: *mut WOLFSSL, buffers: *mut NetBuffers) {
    todo!("wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx")
}

/// Custom recv callback: copy bytes from `net_in` into wolfSSL's buffer.
///
/// # Safety
/// Called from wolfSSL C code; `ctx` is a `*mut NetBuffers` cast to `*mut c_void`.
unsafe extern "C" fn recv_cb(
    _ssl: *mut WOLFSSL,
    buf: *mut std::ffi::c_char,
    sz: std::ffi::c_int,
    ctx: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    todo!("drain net_in into buf")
}

/// Custom send callback: append wolfSSL's output bytes to `net_out`.
///
/// # Safety
/// Called from wolfSSL C code; `ctx` is a `*mut NetBuffers` cast to `*mut c_void`.
unsafe extern "C" fn send_cb(
    _ssl: *mut WOLFSSL,
    buf: *mut std::ffi::c_char,
    sz: std::ffi::c_int,
    ctx: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    todo!("append buf into net_out")
}
