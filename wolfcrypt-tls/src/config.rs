use std::sync::Arc;

use wolfcrypt_sys::*;

use crate::certificate::{Certificate, PrivateKey, RootCertStore};
use crate::ensure_init;
use crate::error::{expect_wolfssl_success, Result, TlsError};
use crate::protocol::{self, ProtocolVersion};

/// Shared inner state for a TLS client configuration.
///
/// Wraps a `WOLFSSL_CTX` pointer. The pointer is freed on drop.
/// `WOLFSSL_CTX` is internally reference-counted and thread-safe in wolfSSL,
/// so sharing via `Arc` is safe.
pub(crate) struct CtxInner {
    pub(crate) ctx: *mut WOLFSSL_CTX,
}

// SAFETY: WOLFSSL_CTX uses internal locking for thread safety.
unsafe impl Send for CtxInner {}
unsafe impl Sync for CtxInner {}

impl Drop for CtxInner {
    fn drop(&mut self) {
        // SAFETY: ctx was created by wolfSSL_CTX_new and has not been freed.
        unsafe {
            wolfSSL_CTX_free(self.ctx);
        }
    }
}

/// Configuration for TLS client connections.
///
/// Immutable after construction; can be shared across threads via cloning
/// (internally `Arc`-wrapped).
#[derive(Clone)]
pub struct TlsClientConfig {
    pub(crate) inner: Arc<CtxInner>,
}

/// Builder for [`TlsClientConfig`].
pub struct TlsClientConfigBuilder {
    protocol_versions: Option<Vec<ProtocolVersion>>,
    root_store: Option<RootCertStore>,
    client_cert: Option<Certificate>,
    client_key: Option<PrivateKey>,
}

impl TlsClientConfig {
    /// Start building a new TLS client configuration.
    pub fn builder() -> TlsClientConfigBuilder {
        TlsClientConfigBuilder {
            protocol_versions: None,
            root_store: None,
            client_cert: None,
            client_key: None,
        }
    }

    /// Allocate a new `WOLFSSL` session from this config with a typed
    /// [`IOCallbacks`] implementation.
    ///
    /// This is the preferred entry point for async layers that manage their
    /// own transport buffers (e.g. `wolfcrypt-tls-tokio`'s `NetBuffers`).
    /// The caller passes a `&mut IOCB`; wolfcrypt-tls registers the shims
    /// and returns the raw session pointer.
    ///
    /// Optionally sets SNI if `server_name` is non-empty.
    ///
    /// # Errors
    /// Returns `TlsError` if `wolfSSL_new` or `wolfSSL_UseSNI` fails.
    ///
    /// # Safety
    ///
    /// The caller is responsible for ensuring:
    ///
    /// 1. `io` must remain valid and at its current address for the entire
    ///    lifetime of the returned `*mut WOLFSSL` session.  The pointer to
    ///    `io` is stored inside wolfSSL; wolfSSL will call back into `io`
    ///    on every read/write/handshake operation.  Moving or dropping `io`
    ///    before the session is freed is undefined behavior.
    ///
    /// 2. The caller must call `wolfSSL_free` on the returned pointer before
    ///    dropping `io`.  `wolfSSL_free` quiesces all callback use before
    ///    returning, so it is safe to drop `io` immediately after.
    ///
    /// 3. The `WOLFSSL_CTX` backing this config must remain alive for the
    ///    session's lifetime (keep a clone of this `TlsClientConfig`).
    pub unsafe fn new_session_with_io<IOCB: crate::callback::IOCallbacks>(
        &self,
        server_name: &str,
        io: &mut IOCB,
    ) -> crate::error::Result<*mut wolfcrypt_sys::WOLFSSL> {
        use crate::callback::{io_recv_shim, io_send_shim};
        use crate::error::TlsError;
        use wolfcrypt_sys::*;

        if server_name.len() > u16::MAX as usize {
            return Err(TlsError::InvalidConfig("server name exceeds maximum SNI length"));
        }

        let ssl = unsafe { wolfSSL_new(self.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
        }
        let guard = crate::SslGuard(ssl);

        if !server_name.is_empty() {
            let ret = unsafe {
                wolfSSL_UseSNI(
                    guard.as_ptr(),
                    WOLFSSL_SNI_HOST_NAME as core::ffi::c_uchar,
                    server_name.as_ptr() as *const core::ffi::c_void,
                    server_name.len() as u16,
                )
            };
            if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
                return Err(TlsError::Ffi { code: ret, func: "wolfSSL_UseSNI" });
            }
        }

        // SAFETY: shims are 'static; io ptr is valid for the caller-guaranteed lifetime.
        unsafe {
            wolfSSL_SSLSetIORecv(guard.as_ptr(), Some(io_recv_shim::<IOCB>));
            wolfSSL_SSLSetIOSend(guard.as_ptr(), Some(io_send_shim::<IOCB>));
            let ctx = io as *mut IOCB as *mut core::ffi::c_void;
            wolfSSL_SetIOReadCtx(guard.as_ptr(), ctx);
            wolfSSL_SetIOWriteCtx(guard.as_ptr(), ctx);
        }

        Ok(guard.into_raw())
    }

    /// Return the underlying `WOLFSSL_CTX` pointer.
    ///
    /// The pointer is valid for as long as this `TlsClientConfig` (or any
    /// clone of it) is alive. The `Arc` inside keeps the `WOLFSSL_CTX` alive;
    /// callers must not call `wolfSSL_CTX_free` on the returned pointer.
    ///
    /// # Safety
    /// The caller must not free the pointer or use it after this config and
    /// all of its clones have been dropped.
    pub unsafe fn as_raw_ctx(&self) -> *mut wolfcrypt_sys::WOLFSSL_CTX {
        self.inner.ctx
    }

    /// Allocate a new `WOLFSSL` session from this config with raw custom IO
    /// callbacks.
    ///
    /// Prefer [`TlsClient::new`] with an [`IOCallbacks`] implementation.
    /// This lower-level method exists for async layers that manage their own
    /// callback types.
    ///
    /// Optionally sets SNI if `server_name` is non-empty.
    ///
    /// The caller takes ownership of the returned `*mut WOLFSSL` and is
    /// responsible for calling `wolfSSL_free` when done.  The `WOLFSSL_CTX`
    /// backing this config must remain alive for the entire lifetime of the
    /// returned session — keeping a clone of this `TlsClientConfig` alongside
    /// the session is the simplest way to ensure that.
    ///
    /// # Errors
    /// Returns `TlsError` if `wolfSSL_new` or `wolfSSL_UseSNI` fails.
    ///
    /// # Safety
    /// - `recv_cb` and `send_cb` must be valid function pointers for the
    ///   lifetime of the returned session.
    /// - `io_ctx` must be valid for the lifetime of the returned session and
    ///   must be the type that the callbacks expect to receive.
    pub unsafe fn new_ssl_with_io_callbacks(
        &self,
        server_name: &str,
        recv_cb: wolfcrypt_sys::CallbackIORecv,
        send_cb: wolfcrypt_sys::CallbackIOSend,
        io_ctx: *mut core::ffi::c_void,
    ) -> crate::error::Result<*mut wolfcrypt_sys::WOLFSSL> {
        use crate::error::TlsError;
        use wolfcrypt_sys::*;

        let ssl = wolfSSL_new(self.inner.ctx);
        if ssl.is_null() {
            return Err(TlsError::AllocFailed { func: "wolfSSL_new" });
        }
        let guard = crate::SslGuard(ssl);

        // Register the custom IO callbacks on this session.
        wolfSSL_SSLSetIORecv(guard.as_ptr(), recv_cb);
        wolfSSL_SSLSetIOSend(guard.as_ptr(), send_cb);
        wolfSSL_SetIOReadCtx(guard.as_ptr(), io_ctx);
        wolfSSL_SetIOWriteCtx(guard.as_ptr(), io_ctx);

        // Set SNI if provided.
        if !server_name.is_empty() {
            if server_name.len() > u16::MAX as usize {
                return Err(TlsError::InvalidConfig("server name exceeds maximum SNI length"));
            }
            let ret = wolfSSL_UseSNI(
                guard.as_ptr(),
                WOLFSSL_SNI_HOST_NAME as core::ffi::c_uchar,
                server_name.as_ptr() as *const core::ffi::c_void,
                server_name.len() as u16,
            );
            if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
                return Err(TlsError::Ffi { code: ret, func: "wolfSSL_UseSNI" });
            }
        }

        Ok(guard.into_raw())
    }
}

impl TlsClientConfigBuilder {
    /// Set the allowed TLS protocol versions.
    ///
    /// If not called, defaults to TLS 1.2 and 1.3.
    pub fn with_protocol_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.protocol_versions = Some(versions.to_vec());
        self
    }

    /// Set the trusted root CA certificates.
    pub fn with_root_certificates(mut self, store: RootCertStore) -> Self {
        self.root_store = Some(store);
        self
    }

    /// No client certificate authentication.
    ///
    /// This is the default and a no-op — it exists so that the builder chain
    /// reads explicitly (`.with_no_client_auth()` vs silently omitting the call).
    pub fn with_no_client_auth(self) -> Self {
        self
    }

    /// Use client certificate authentication (mTLS).
    pub fn with_client_auth(mut self, cert: Certificate, key: PrivateKey) -> Self {
        self.client_cert = Some(cert);
        self.client_key = Some(key);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<TlsClientConfig> {
        ensure_init();

        let root_store = self
            .root_store
            .ok_or(TlsError::InvalidConfig("root certificates are required"))?;

        // SAFETY: wolfSSL_Init has been called via ensure_init().
        let method = unsafe {
            protocol::resolve_method(protocol::Side::Client, self.protocol_versions.as_deref())?
        };

        // SAFETY: method is a valid pointer from wolf*_method().
        let ctx = unsafe { wolfSSL_CTX_new(method) };
        if ctx.is_null() {
            return Err(TlsError::AllocFailed {
                func: "wolfSSL_CTX_new",
            });
        }

        // Wrap immediately so Drop frees the CTX if any subsequent call fails.
        let inner = Arc::new(CtxInner { ctx });

        // Load root certificates.
        for (cert_data, format) in root_store.iter() {
            // SAFETY: inner.ctx is valid (created above, freed by CtxInner::drop).
            let ret = unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    inner.ctx,
                    cert_data.as_ptr(),
                    // Certificate/key data is bounded by practical PKI limits (< 1 MB); no runtime clamp needed.
                    cert_data.len() as core::ffi::c_long,
                    format.as_c_int(),
                )
            };
            expect_wolfssl_success(ret, "wolfSSL_CTX_load_verify_buffer")?;
        }

        // Enable peer verification.
        // SAFETY: inner.ctx was created by wolfSSL_CTX_new above and is
        // owned by CtxInner (freed on drop, which has not run yet).
        unsafe {
            wolfSSL_CTX_set_verify(inner.ctx, WOLFSSL_VERIFY_PEER as core::ffi::c_int, None);
        }

        // Load client certificate and key for mTLS.
        if let (Some(cert), Some(key)) = (self.client_cert.as_ref(), self.client_key.as_ref()) {
            // SAFETY: inner.ctx is owned by CtxInner and has not been freed.
            let ret = unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    inner.ctx,
                    cert.data().as_ptr(),
                    // Certificate/key data is bounded by practical PKI limits (< 1 MB); no runtime clamp needed.
                    cert.data().len() as core::ffi::c_long,
                    cert.format().as_c_int(),
                )
            };
            expect_wolfssl_success(ret, "wolfSSL_CTX_use_certificate_buffer")?;

            // SAFETY: inner.ctx is owned by CtxInner and has not been freed.
            let ret = unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    inner.ctx,
                    key.data().as_ptr(),
                    // Certificate/key data is bounded by practical PKI limits (< 1 MB); no runtime clamp needed.
                    key.data().len() as core::ffi::c_long,
                    key.format().as_c_int(),
                )
            };
            expect_wolfssl_success(ret, "wolfSSL_CTX_use_PrivateKey_buffer")?;
        }

        Ok(TlsClientConfig { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_without_root_certs_fails() {
        let result = TlsClientConfig::builder().with_no_client_auth().build();
        assert!(result.is_err());
    }
}
