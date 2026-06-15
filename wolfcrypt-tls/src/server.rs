use std::ffi::c_void;
use std::io::{Read, Write};
use std::sync::Arc;

use wolfcrypt_sys::*;

use crate::callback::{io_recv_shim, io_send_shim, IOCallbacks};
use crate::certificate::{Certificate, PrivateKey, RootCertStore};
use crate::config::CtxInner;
use crate::error::{expect_wolfssl_success, len_as_c_int, Result, TlsError};
use crate::protocol::{self, ProtocolVersion};
use crate::{ensure_init, SslGuard};

/// Configuration for TLS server connections.
///
/// Immutable after construction; can be shared across threads via cloning
/// (internally `Arc`-wrapped).
#[derive(Clone)]
pub struct TlsServerConfig {
    pub(crate) inner: Arc<CtxInner>,
}

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerConfig").finish_non_exhaustive()
    }
}

/// Builder for [`TlsServerConfig`].
#[must_use = "builder does nothing unless .build() is called"]
pub struct TlsServerConfigBuilder {
    protocol_versions: Option<Vec<ProtocolVersion>>,
    cert: Option<Certificate>,
    key: Option<PrivateKey>,
    /// When `Some`, client certificate authentication (mTLS) is enabled
    /// and client certs are verified against these CAs.
    client_ca_store: Option<RootCertStore>,
}

impl TlsServerConfig {
    /// Start building a new TLS server configuration.
    pub fn builder() -> TlsServerConfigBuilder {
        TlsServerConfigBuilder {
            protocol_versions: None,
            cert: None,
            key: None,
            client_ca_store: None,
        }
    }

    /// Return the underlying `WOLFSSL_CTX` pointer.
    ///
    /// Valid for as long as this `TlsServerConfig` (or any clone) is alive.
    /// Callers must not call `wolfSSL_CTX_free` on it.
    ///
    /// # Safety
    /// Must not be freed or used after all clones of this config are dropped.
    pub unsafe fn as_raw_ctx(&self) -> *mut wolfcrypt_sys::WOLFSSL_CTX {
        self.inner.ctx
    }

    /// Allocate a new `WOLFSSL` session from this config with a typed
    /// [`IOCallbacks`] implementation.
    ///
    /// The server-side equivalent of `TlsClientConfig::new_session_with_io`.
    ///
    /// # Errors
    /// Returns `TlsError` if `wolfSSL_new` fails.
    ///
    /// # Safety
    ///
    /// Same contract as `TlsClientConfig::new_session_with_io`:
    /// `io` must remain valid at its current address for the entire lifetime
    /// of the returned `*mut WOLFSSL`, and `wolfSSL_free` must be called
    /// before `io` is dropped.
    pub unsafe fn new_session_with_io<IOCB: crate::callback::IOCallbacks>(
        &self,
        io: &mut IOCB,
    ) -> crate::error::Result<*mut wolfcrypt_sys::WOLFSSL> {
        use crate::error::TlsError;

        let ssl = unsafe { wolfSSL_new(self.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
        }
        let guard = crate::SslGuard(ssl);

        // SAFETY: shims are 'static; io ptr is valid for caller-guaranteed lifetime.
        unsafe {
            wolfSSL_SSLSetIORecv(guard.as_ptr(), Some(io_recv_shim::<IOCB>));
            wolfSSL_SSLSetIOSend(guard.as_ptr(), Some(io_send_shim::<IOCB>));
            let ctx = io as *mut IOCB as *mut c_void;
            wolfSSL_SetIOReadCtx(guard.as_ptr(), ctx);
            wolfSSL_SetIOWriteCtx(guard.as_ptr(), ctx);
        }

        Ok(guard.into_raw())
    }

    /// Allocate a new `WOLFSSL` session from this config with raw custom IO
    /// callbacks — the server-side counterpart of
    /// [`TlsClientConfig::new_ssl_with_io_callbacks`].
    ///
    /// Use this when you need hand-rolled `extern "C"` callbacks that cannot
    /// be expressed through the [`IOCallbacks`] trait (e.g. DTLS with
    /// datagram-aware chunking, or a non-standard async runtime).  For the
    /// common case, prefer [`TlsServerConfig::new_session_with_io`] which is
    /// typed and requires no `unsafe` at the call site.
    ///
    /// # Safety
    /// `recv_cb` and `send_cb` must be valid for the lifetime of the returned
    /// session. `io_ctx` must be valid and of the type the callbacks expect.
    pub unsafe fn new_ssl_with_io_callbacks(
        &self,
        recv_cb: wolfcrypt_sys::CallbackIORecv,
        send_cb: wolfcrypt_sys::CallbackIOSend,
        io_ctx: *mut core::ffi::c_void,
    ) -> crate::error::Result<*mut wolfcrypt_sys::WOLFSSL> {
        // SAFETY: caller guarantees that `recv_cb`, `send_cb`, and `io_ctx`
        // are valid for the lifetime of the returned WOLFSSL session, and that
        // `self.inner.ctx` is a valid, initialized WOLFSSL_CTX.
        unsafe {
            let ssl = wolfSSL_new(self.inner.ctx);
            if ssl.is_null() {
                return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
            }
            let guard = crate::SslGuard(ssl);
            wolfSSL_SSLSetIORecv(guard.as_ptr(), recv_cb);
            wolfSSL_SSLSetIOSend(guard.as_ptr(), send_cb);
            wolfSSL_SetIOReadCtx(guard.as_ptr(), io_ctx);
            wolfSSL_SetIOWriteCtx(guard.as_ptr(), io_ctx);
            Ok(guard.into_raw())
        }
    }
}

impl TlsServerConfigBuilder {
    /// Set the allowed TLS protocol versions.
    ///
    /// Accepts any iterable of `ProtocolVersion`:
    /// - `[ProtocolVersion::Tls13]` (fixed-size array)
    /// - `[ProtocolVersion::Tls12, ProtocolVersion::Tls13]`
    /// - `vec![ProtocolVersion::Tls12]`
    /// - any `Iterator<Item = ProtocolVersion>`
    pub fn with_protocol_versions(
        mut self,
        versions: impl IntoIterator<Item = ProtocolVersion>,
    ) -> Self {
        self.protocol_versions = Some(versions.into_iter().collect());
        self
    }

    /// Set the server certificate chain and private key.
    pub fn with_certificate_chain(mut self, cert: Certificate, key: PrivateKey) -> Self {
        self.cert = Some(cert);
        self.key = Some(key);
        self
    }

    /// No client certificate authentication required (default, no-op).
    pub fn with_no_client_auth(self) -> Self {
        self
    }

    /// Require client certificate authentication (mTLS).
    pub fn with_client_auth(mut self, client_ca_store: RootCertStore) -> Self {
        self.client_ca_store = Some(client_ca_store);
        self
    }

    /// Build the configuration.
    #[must_use = "discarding the built config has no effect"]
    pub fn build(self) -> Result<TlsServerConfig> {
        ensure_init();

        let cert = self
            .cert
            .ok_or(TlsError::InvalidConfig("server certificate is required"))?;
        let key = self
            .key
            .ok_or(TlsError::InvalidConfig("server private key is required"))?;

        // SAFETY: wolfSSL_Init has been called via ensure_init().
        let method = unsafe {
            protocol::resolve_method(protocol::Side::Server, self.protocol_versions.as_deref())?
        };

        // SAFETY: method was returned by resolve_method above.
        let ctx = unsafe { wolfSSL_CTX_new(method) };
        if ctx.is_null() {
            return Err(TlsError::AllocFailed {
                func: "wolfSSL_CTX_new",
            });
        }

        let inner = Arc::new(CtxInner { ctx });

        // Enforce TLS 1.2 minimum; this is a no-op for pinned-version methods
        // (wolfTLSv1_2/1_3) but prevents TLS 1.0/1.1 negotiation when using
        // wolfSSLv23 (flexible version negotiation).
        let ret = unsafe {
            wolfSSL_CTX_SetMinVersion(inner.ctx, WOLFSSL_TLSV1_2 as core::ffi::c_int)
        };
        expect_wolfssl_success(ret, "wolfSSL_CTX_SetMinVersion")?;

        let ret = unsafe {
            wolfSSL_CTX_use_certificate_buffer(
                inner.ctx,
                cert.data().as_ptr(),
                len_as_c_int(cert.data().len()) as core::ffi::c_long,
                cert.format().as_c_int(),
            )
        };
        expect_wolfssl_success(ret, "wolfSSL_CTX_use_certificate_buffer")?;

        let ret = unsafe {
            wolfSSL_CTX_use_PrivateKey_buffer(
                inner.ctx,
                key.data().as_ptr(),
                len_as_c_int(key.data().len()) as core::ffi::c_long,
                key.format().as_c_int(),
            )
        };
        expect_wolfssl_success(ret, "wolfSSL_CTX_use_PrivateKey_buffer")?;

        if let Some(ref ca_store) = self.client_ca_store {
            for (cert_data, format) in ca_store.iter() {
                let ret = unsafe {
                    wolfSSL_CTX_load_verify_buffer(
                        inner.ctx,
                        cert_data.as_ptr(),
                        len_as_c_int(cert_data.len()) as core::ffi::c_long,
                        format.as_c_int(),
                    )
                };
                expect_wolfssl_success(ret, "wolfSSL_CTX_load_verify_buffer")?;
            }
            unsafe {
                wolfSSL_CTX_set_verify(
                    inner.ctx,
                    (WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT) as core::ffi::c_int,
                    None,
                );
            }
        }

        Ok(TlsServerConfig { inner })
    }
}

/// Accepts TLS connections using a [`TlsServerConfig`].
///
/// Cheap to clone; the configuration is `Arc`-backed.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: TlsServerConfig,
}

impl TlsAcceptor {
    /// Create a new acceptor with the given server configuration.
    pub fn new(config: TlsServerConfig) -> Self {
        TlsAcceptor { config }
    }

    /// Accept a TLS connection on the given transport.
    ///
    /// `io` must implement [`IOCallbacks`], which is automatically satisfied
    /// by any `Read + Write` type (e.g. [`std::net::TcpStream`]).
    pub fn accept<IOCB: IOCallbacks>(&self, io: IOCB) -> Result<TlsServer<IOCB>> {
        // SAFETY: config.inner.ctx is owned by Arc<CtxInner> and not freed
        // while we hold a reference to it.
        let ssl = unsafe { wolfSSL_new(self.config.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
        }
        let guard = SslGuard(ssl);

        let mut io = Box::new(io);

        // Use the generic shims from callback.rs (same as TlsClient and config path).
        // SAFETY: shims are 'static; io is behind a Box (stable address);
        // wolfSSL_free quiesces callbacks before io is dropped.
        unsafe {
            wolfSSL_SSLSetIORecv(guard.as_ptr(), Some(io_recv_shim::<IOCB>));
            wolfSSL_SSLSetIOSend(guard.as_ptr(), Some(io_send_shim::<IOCB>));
            let ctx = &mut *io as *mut IOCB as *mut c_void;
            wolfSSL_SetIOReadCtx(guard.as_ptr(), ctx);
            wolfSSL_SetIOWriteCtx(guard.as_ptr(), ctx);
        }

        // Perform the TLS handshake (server side).
        let ret = unsafe { wolfSSL_accept(guard.as_ptr()) };
        if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
            let err = unsafe { wolfSSL_get_error(guard.as_ptr(), ret) };
            return Err(TlsError::Ffi {
                code: err,
                func: "wolfSSL_accept",
            });
        }

        Ok(TlsServer {
            ssl: guard.into_raw(),
            io,
            config: self.config.clone(),
        })
    }
}

/// A TLS server connection wrapping an IO transport.
///
/// Implements [`Read`] and [`Write`] for encrypted I/O.
///
/// **Drop behavior**: dropping a `TlsServer` sends a TLS `close_notify`
/// via `wolfSSL_shutdown`, which may block on the underlying transport.
pub struct TlsServer<IOCB: IOCallbacks> {
    ssl: *mut WOLFSSL,
    /// Boxed for a stable heap address used by the IO callbacks.
    /// Held for its Drop side-effect — the Box must outlive `ssl`.
    #[expect(dead_code)]
    io: Box<IOCB>,
    /// Keeps the WOLFSSL_CTX alive for the lifetime of this session.
    #[expect(dead_code)]
    config: TlsServerConfig,
}

impl<IOCB: IOCallbacks> std::fmt::Debug for TlsServer<IOCB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer").field("ssl", &self.ssl).finish()
    }
}

// SAFETY: exclusive &mut self for I/O; WOLFSSL pointer can be moved across threads.
unsafe impl<IOCB: IOCallbacks + Send> Send for TlsServer<IOCB> {}
// Not Sync: same reasoning as TlsClient.

impl<IOCB: IOCallbacks> TlsServer<IOCB> {
    /// Return the underlying `WOLFSSL` session pointer.
    ///
    /// Valid for as long as this `TlsServer` is alive. Do not free it.
    ///
    /// # Safety
    /// Must not be freed or used after this `TlsServer` is dropped.
    pub unsafe fn as_raw_ssl(&self) -> *mut WOLFSSL {
        self.ssl
    }

}

// wolfSSL_get_error returns the OpenSSL-compatible positive values (2, 3),
// not the negative internal _E callback codes. Define consts for use in match.
const WANT_READ: core::ffi::c_int = WOLFSSL_ERROR_WANT_READ as core::ffi::c_int;
const WANT_WRITE: core::ffi::c_int = WOLFSSL_ERROR_WANT_WRITE as core::ffi::c_int;

impl<IOCB: IOCallbacks> Read for TlsServer<IOCB> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(core::ffi::c_int::MAX as usize) as core::ffi::c_int;
        let ret = unsafe {
            wolfSSL_read(self.ssl, buf.as_mut_ptr() as *mut core::ffi::c_void, len)
        };
        if ret > 0 {
            Ok(ret as usize)
        } else if ret == 0 {
            Ok(0)
        } else {
            let err = unsafe { wolfSSL_get_error(self.ssl, ret) };
            match err {
                WANT_READ | WANT_WRITE => {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
                _ => Err(std::io::Error::other(format!(
                    "wolfSSL_read: {} (error {err})",
                    crate::error::error_string(err)
                ))),
            }
        }
    }
}

impl<IOCB: IOCallbacks> Write for TlsServer<IOCB> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(core::ffi::c_int::MAX as usize) as core::ffi::c_int;
        let ret = unsafe {
            wolfSSL_write(self.ssl, buf.as_ptr() as *const core::ffi::c_void, len)
        };
        if ret > 0 {
            Ok(ret as usize)
        } else if ret == 0 {
            // wolfSSL_write returning 0 is not documented as a normal condition.
            // Return WouldBlock so the caller can retry.
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        } else {
            let err = unsafe { wolfSSL_get_error(self.ssl, ret) };
            match err {
                WANT_READ | WANT_WRITE => {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                }
                _ => Err(std::io::Error::other(format!(
                    "wolfSSL_write: {} (error {err})",
                    crate::error::error_string(err)
                ))),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // wolfSSL flushes its internal record buffer on every write call.
        // The underlying transport is accessed only through IOCallbacks, which
        // does not expose a flush operation.  There is no buffering layer here
        // to flush — wolfSSL writes directly to the transport on each call.
        Ok(())
    }
}

impl<IOCB: IOCallbacks> Drop for TlsServer<IOCB> {
    fn drop(&mut self) {
        unsafe {
            let _ = wolfSSL_shutdown(self.ssl);
            wolfSSL_free(self.ssl);
        }
    }
}
