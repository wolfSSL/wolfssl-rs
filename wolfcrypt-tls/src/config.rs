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
