// IOCallbacks trait — the primary IO abstraction for wolfcrypt-tls.
//
// Modelled on ExpressVPN's wolfssl-rs IOCallbacks pattern.
// All TLS sessions (blocking and async) are driven through this trait;
// wolfSSL_set_fd is never used.  This makes the crate transport-agnostic:
// TcpStream, UnixStream, in-memory buffers, UDP datagrams, and tokio/smol
// async bridges all implement the same interface.

use std::io;

/// The result of a single IO callback invocation.
#[derive(Debug)]
pub enum IOCallbackResult<T> {
    /// The operation completed successfully.
    Ok(T),
    /// The operation would block; wolfSSL should retry after more data arrives.
    /// Surfaces as `WOLFSSL_CBIO_ERR_WANT_READ` or `WOLFSSL_CBIO_ERR_WANT_WRITE`
    /// to wolfSSL.
    WouldBlock,
    /// Any other IO error.
    Err(io::Error),
}

/// Transport abstraction for a wolfSSL session.
///
/// Implement this trait on your transport type to use it with
/// [`TlsClient`] and [`TlsServer`] without handing wolfSSL a raw file
/// descriptor.  The callbacks are invoked synchronously from within
/// wolfSSL C code during handshake and data transfer.
///
/// # Blanket impl
/// Any `T: std::io::Read + std::io::Write` automatically implements
/// `IOCallbacks`, so `TcpStream`, `UnixStream`, in-memory `Cursor`, etc.
/// all work out of the box.
///
/// # Async
/// For async runtimes, implement `IOCallbacks` on a type that holds
/// `net_in` / `net_out` byte buffers (as in `wolfcrypt-tls-tokio` and
/// `wolfcrypt-tls-futures-io`).  The async driver fills `net_in` and
/// drains `net_out`; these callbacks operate synchronously on the buffers.
pub trait IOCallbacks {
    /// Called when wolfSSL wants to receive bytes.
    ///
    /// Copy as many bytes as available into `buf`.  Return the number of
    /// bytes placed in `buf`.  If no bytes are available yet, return
    /// [`IOCallbackResult::WouldBlock`].
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize>;

    /// Called when wolfSSL wants to send bytes.
    ///
    /// Consume as many bytes from `buf` as possible.  Return the number
    /// of bytes consumed.  If the sink is full, return
    /// [`IOCallbackResult::WouldBlock`].
    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize>;
}

/// Blanket impl: any `Read + Write` type is automatically an `IOCallbacks`.
///
/// This means `TcpStream`, `UnixStream`, `std::io::Cursor<Vec<u8>>`, etc.
/// all work with `TlsClient::new` and `TlsAcceptor::accept` with no
/// changes to call sites.
impl<T: io::Read + io::Write> IOCallbacks for T {
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        match self.read(buf) {
            Ok(n) => IOCallbackResult::Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => IOCallbackResult::WouldBlock,
            Err(e) => IOCallbackResult::Err(e),
        }
    }

    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.write(buf) {
            Ok(n) => IOCallbackResult::Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => IOCallbackResult::WouldBlock,
            Err(e) => IOCallbackResult::Err(e),
        }
    }
}

/// Convert an `io::ErrorKind` into the appropriate wolfSSL CBIO error code.
///
/// `would_block_code` is either `WOLFSSL_CBIO_ERR_WANT_READ` or
/// `WOLFSSL_CBIO_ERR_WANT_WRITE` depending on which callback is calling.
/// Generic `extern "C"` recv shim for any `IOCB: IOCallbacks`.
///
/// Used by `TlsClientConfig::new_session_with_io` and
/// `TlsServerConfig::new_session_with_io` to register a type-specific
/// callback without the caller having to write `unsafe` code.
///
/// # Safety
/// `ctx` must be a valid `*mut IOCB` for the lifetime of the WOLFSSL session.
pub(crate) unsafe extern "C" fn io_recv_shim<IOCB: IOCallbacks>(
    _ssl: *mut wolfcrypt_sys::WOLFSSL,
    buf: *mut core::ffi::c_char,
    sz: core::ffi::c_int,
    ctx: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    use wolfcrypt_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ;
    debug_assert!(!ctx.is_null());
    let io = unsafe { &mut *(ctx as *mut IOCB) };
    let buf = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, sz as usize) };
    match io.recv(buf) {
        IOCallbackResult::Ok(n) => n as core::ffi::c_int,
        IOCallbackResult::WouldBlock => IOerrors_WOLFSSL_CBIO_ERR_WANT_READ,
        IOCallbackResult::Err(e) => errorkind_to_cbio(e.kind(), IOerrors_WOLFSSL_CBIO_ERR_WANT_READ),
    }
}

/// Generic `extern "C"` send shim for any `IOCB: IOCallbacks`.
///
/// # Safety
/// `ctx` must be a valid `*mut IOCB` for the lifetime of the WOLFSSL session.
pub(crate) unsafe extern "C" fn io_send_shim<IOCB: IOCallbacks>(
    _ssl: *mut wolfcrypt_sys::WOLFSSL,
    buf: *mut core::ffi::c_char,
    sz: core::ffi::c_int,
    ctx: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    use wolfcrypt_sys::{IOerrors_WOLFSSL_CBIO_ERR_WANT_WRITE};
    debug_assert!(!ctx.is_null());
    let io = unsafe { &mut *(ctx as *mut IOCB) };
    let buf = unsafe { std::slice::from_raw_parts(buf as *const u8, sz as usize) };
    match io.send(buf) {
        IOCallbackResult::Ok(n) => n as core::ffi::c_int,
        IOCallbackResult::WouldBlock => IOerrors_WOLFSSL_CBIO_ERR_WANT_WRITE,
        IOCallbackResult::Err(e) => errorkind_to_cbio(e.kind(), IOerrors_WOLFSSL_CBIO_ERR_WANT_WRITE),
    }
}

pub(crate) fn errorkind_to_cbio(
    kind: io::ErrorKind,
    would_block_code: core::ffi::c_int,
) -> core::ffi::c_int {
    use io::ErrorKind::*;
    use wolfcrypt_sys::{
        IOerrors_WOLFSSL_CBIO_ERR_CONN_CLOSE, IOerrors_WOLFSSL_CBIO_ERR_CONN_RST,
        IOerrors_WOLFSSL_CBIO_ERR_GENERAL, IOerrors_WOLFSSL_CBIO_ERR_ISR,
        IOerrors_WOLFSSL_CBIO_ERR_TIMEOUT,
    };
    match kind {
        WouldBlock => would_block_code,
        TimedOut => IOerrors_WOLFSSL_CBIO_ERR_TIMEOUT,
        ConnectionReset => IOerrors_WOLFSSL_CBIO_ERR_CONN_RST,
        Interrupted => IOerrors_WOLFSSL_CBIO_ERR_ISR,
        ConnectionAborted => IOerrors_WOLFSSL_CBIO_ERR_CONN_CLOSE,
        _ => IOerrors_WOLFSSL_CBIO_ERR_GENERAL,
    }
}
