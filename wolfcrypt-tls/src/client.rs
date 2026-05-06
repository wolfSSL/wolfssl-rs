use std::ffi::c_void;
use std::io::{Read, Write};

use wolfcrypt_sys::*;

use crate::callback::{io_recv_shim, io_send_shim, IOCallbacks};
use crate::config::TlsClientConfig;
use crate::error::{Result, TlsError};
use crate::SslGuard;

/// A TLS client connection wrapping an IO transport.
///
/// Implements [`Read`] and [`Write`] for encrypted I/O over the underlying
/// transport.
///
/// The transport `IOCB` must implement [`IOCallbacks`], which is
/// automatically satisfied by any `Read + Write` type (e.g.
/// [`std::net::TcpStream`]).
///
/// **Drop behavior**: dropping a `TlsClient` sends a TLS `close_notify`
/// via `wolfSSL_shutdown`, which may block on the underlying transport.
pub struct TlsClient<IOCB: IOCallbacks> {
    ssl: *mut WOLFSSL,
    /// Boxed for a stable heap address. The raw pointer to io is stored
    /// inside wolfSSL via wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx.
    /// wolfSSL_free (called in Drop) quiesces all callback use before io
    /// is dropped, so the pointer is always valid when callbacks fire.
    #[allow(dead_code)]
    io: Box<IOCB>,
    /// Kept alive so the `WOLFSSL_CTX` (owned by `Arc<CtxInner>`) outlives
    /// the `WOLFSSL` session.
    #[allow(dead_code)]
    config: TlsClientConfig,
}

impl<IOCB: IOCallbacks> std::fmt::Debug for TlsClient<IOCB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient").field("ssl", &self.ssl).finish()
    }
}

// SAFETY: WOLFSSL is not internally synchronized, but we require &mut self
// for Read/Write, which provides exclusive access.
unsafe impl<IOCB: IOCallbacks + Send> Send for TlsClient<IOCB> {}

impl<IOCB: IOCallbacks> TlsClient<IOCB> {
    /// Create a new TLS client connection over the given transport.
    ///
    /// Performs the TLS handshake immediately. On success, the connection
    /// is ready for reading and writing.
    pub fn new(config: TlsClientConfig, server_name: &str, io: IOCB) -> Result<Self> {
        if server_name.len() > u16::MAX as usize {
            return Err(TlsError::InvalidConfig(
                "server name exceeds maximum SNI length",
            ));
        }

        // SAFETY: config.inner.ctx is owned by Arc<CtxInner> and not freed
        // while we hold a reference to it.
        let ssl = unsafe { wolfSSL_new(config.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
        }
        let guard = SslGuard(ssl);

        if !server_name.is_empty() {
            // SAFETY: ssl was returned by wolfSSL_new above and has not been freed.
            let ret = unsafe {
                wolfSSL_UseSNI(
                    guard.as_ptr(),
                    WOLFSSL_SNI_HOST_NAME as core::ffi::c_uchar,
                    server_name.as_ptr() as *const core::ffi::c_void,
                    server_name.len() as u16,
                )
            };
            if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
                return Err(TlsError::Ffi {
                    code: ret,
                    func: "wolfSSL_UseSNI",
                });
            }
        }

        // Box io now for a stable address before registering callbacks.
        let mut io = Box::new(io);

        // Register the custom IO callbacks and context pointer.
        // Uses the generic shims from callback.rs to avoid duplication.
        // SAFETY: shims are 'static; io is behind a Box so the address is
        // stable; wolfSSL_free (called in Drop) quiesces callbacks before
        // io is dropped.
        unsafe {
            wolfSSL_SSLSetIORecv(guard.as_ptr(), Some(io_recv_shim::<IOCB>));
            wolfSSL_SSLSetIOSend(guard.as_ptr(), Some(io_send_shim::<IOCB>));
            let ctx = &mut *io as *mut IOCB as *mut c_void;
            wolfSSL_SetIOReadCtx(guard.as_ptr(), ctx);
            wolfSSL_SetIOWriteCtx(guard.as_ptr(), ctx);
        }

        // Perform the TLS handshake.
        // SAFETY: ssl has not been freed; callbacks and ctx are registered above.
        let ret = unsafe { wolfSSL_connect(guard.as_ptr()) };
        if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
            let (err, verify_result) = unsafe {
                let e = wolfSSL_get_error(guard.as_ptr(), ret);
                let v = wolfSSL_get_verify_result(guard.as_ptr());
                (e, v)
            };
            drop(guard);
            if verify_result != X509_V_OK as core::ffi::c_long {
                let reason = crate::error::verify_error_string(verify_result);
                return Err(TlsError::CertificateVerification(format!(
                    "{reason} (X509 error {verify_result})"
                )));
            }
            return Err(TlsError::Ffi {
                code: err,
                func: "wolfSSL_connect",
            });
        }

        Ok(TlsClient {
            ssl: guard.into_raw(),
            io,
            config,
        })
    }

    /// Return the underlying `WOLFSSL` session pointer.
    ///
    /// Valid for as long as this `TlsClient` is alive. Do not free it.
    ///
    /// # Safety
    /// Must not be freed or used after this `TlsClient` is dropped.
    pub unsafe fn as_raw_ssl(&self) -> *mut WOLFSSL {
        self.ssl
    }

}

impl<IOCB: IOCallbacks> Read for TlsClient<IOCB> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(core::ffi::c_int::MAX as usize) as core::ffi::c_int;
        // SAFETY: ssl is valid.
        let ret = unsafe {
            wolfSSL_read(self.ssl, buf.as_mut_ptr() as *mut core::ffi::c_void, len)
        };
        if ret > 0 {
            Ok(ret as usize)
        } else if ret == 0 {
            Ok(0)
        } else {
            // SAFETY: ssl is valid.
            let err = unsafe { wolfSSL_get_error(self.ssl, ret) };
            match err {
                wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E
                | wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E => {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "wolfSSL_read: {} (error {err})",
                        crate::error::error_string(err)
                    ),
                )),
            }
        }
    }
}

impl<IOCB: IOCallbacks> Write for TlsClient<IOCB> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(core::ffi::c_int::MAX as usize) as core::ffi::c_int;
        // SAFETY: ssl is valid.
        let ret = unsafe {
            wolfSSL_write(self.ssl, buf.as_ptr() as *const core::ffi::c_void, len)
        };
        if ret > 0 {
            Ok(ret as usize)
        } else {
            let err = unsafe { wolfSSL_get_error(self.ssl, ret) };
            match err {
                wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E
                | wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E => {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "wolfSSL_write: {} (error {err})",
                        crate::error::error_string(err)
                    ),
                )),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<IOCB: IOCallbacks> Drop for TlsClient<IOCB> {
    fn drop(&mut self) {
        // wolfSSL_free quiesces all callback use before returning, so it
        // is safe to drop self.io after this point.
        unsafe {
            let _ = wolfSSL_shutdown(self.ssl);
            wolfSSL_free(self.ssl);
        }
    }
}
