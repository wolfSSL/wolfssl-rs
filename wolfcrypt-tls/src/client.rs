use std::io::{Read, Write};

use wolfcrypt_sys::*;

use crate::config::TlsClientConfig;
use crate::error::{self, Result, TlsError};
use crate::{SslGuard, TlsSocket};

/// A TLS client connection wrapping a stream.
///
/// Implements [`Read`] and [`Write`] for encrypted I/O over the underlying
/// transport.
///
/// The stream `S` must implement [`TlsSocket`], which is automatically
/// provided for any type implementing `AsRawFd` (Unix) or `AsRawSocket`
/// (Windows) — e.g. [`std::net::TcpStream`].
///
/// **Drop behavior**: dropping a `TlsClient` sends a TLS `close_notify`
/// via `wolfSSL_shutdown`, which may block on the underlying transport.
/// For non-blocking or timeout-controlled shutdown, configure the
/// underlying transport before dropping.
pub struct TlsClient<S> {
    ssl: *mut WOLFSSL,
    /// Kept alive so the underlying fd remains valid for wolfSSL I/O.
    #[allow(dead_code)]
    stream: S,
    /// Kept alive so the `WOLFSSL_CTX` (owned by `Arc<CtxInner>`) outlives
    /// the `WOLFSSL` session.
    #[allow(dead_code)]
    config: TlsClientConfig,
}

impl<S> std::fmt::Debug for TlsClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient").field("ssl", &self.ssl).finish()
    }
}

// SAFETY: WOLFSSL is not internally synchronized, but we require &mut self
// for Read/Write, which provides exclusive access. Send is safe because
// the WOLFSSL pointer can be moved to another thread.
unsafe impl<S: Send> Send for TlsClient<S> {}

impl<S: Read + Write + TlsSocket> TlsClient<S> {
    /// Create a new TLS client connection over the given stream.
    ///
    /// Performs the TLS handshake immediately. On success, the connection
    /// is ready for reading and writing.
    pub fn new(config: TlsClientConfig, server_name: &str, stream: S) -> Result<Self> {
        // Validate SNI length before allocating the ssl object.
        if server_name.len() > u16::MAX as usize {
            return Err(TlsError::InvalidConfig(
                "server name exceeds maximum SNI length",
            ));
        }

        // SAFETY: config.inner.ctx is owned by Arc<CtxInner> and not freed
        // while we hold a reference to it.
        let ssl = unsafe { wolfSSL_new(config.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed {
                func: "wolfSSL_new",
            });
        }
        let guard = SslGuard(ssl);

        // Set SNI (Server Name Indication).
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

        // Set the file descriptor for I/O.
        let fd = stream.tls_raw_fd();
        // SAFETY: ssl has not been freed; fd is a valid descriptor from tls_raw_fd.
        let ret = unsafe { wolfSSL_set_fd(guard.as_ptr(), fd) };
        if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
            return Err(TlsError::Ffi {
                code: ret,
                func: "wolfSSL_set_fd",
            });
        }

        // Perform the TLS handshake.
        // SAFETY: ssl has not been freed, and fd was set above.
        let ret = unsafe { wolfSSL_connect(guard.as_ptr()) };
        if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
            // SAFETY: ssl has not been freed; all three calls require a valid ssl.
            let (err, verify_result) = unsafe {
                let e = wolfSSL_get_error(guard.as_ptr(), ret);
                let v = wolfSSL_get_verify_result(guard.as_ptr());
                (e, v)
            };
            // guard drops here, freeing ssl
            drop(guard);
            if verify_result != X509_V_OK as core::ffi::c_long {
                let reason = error::verify_error_string(verify_result);
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
            stream,
            config,
        })
    }
}

crate::impl_tls_io!(TlsClient);
