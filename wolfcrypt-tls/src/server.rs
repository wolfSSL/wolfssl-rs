use std::io::{Read, Write};
use std::sync::Arc;

use wolfcrypt_sys::*;

use crate::certificate::{Certificate, PrivateKey, RootCertStore};
use crate::config::CtxInner;
use crate::error::{expect_wolfssl_success, Result, TlsError};
use crate::protocol::{self, ProtocolVersion};
use crate::{ensure_init, SslGuard, TlsSocket};

/// Configuration for TLS server connections.
///
/// Immutable after construction; can be shared across threads via cloning
/// (internally `Arc`-wrapped).
#[derive(Clone)]
pub struct TlsServerConfig {
    pub(crate) inner: Arc<CtxInner>,
}

/// Builder for [`TlsServerConfig`].
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
}

impl TlsServerConfigBuilder {
    /// Set the allowed TLS protocol versions.
    pub fn with_protocol_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.protocol_versions = Some(versions.to_vec());
        self
    }

    /// Set the server certificate chain and private key.
    pub fn with_certificate_chain(mut self, cert: Certificate, key: PrivateKey) -> Self {
        self.cert = Some(cert);
        self.key = Some(key);
        self
    }

    /// No client certificate authentication required.
    ///
    /// This is the default and a no-op — it exists so that the builder chain
    /// reads explicitly (`.with_no_client_auth()` vs silently omitting the call).
    pub fn with_no_client_auth(self) -> Self {
        self
    }

    /// Require client certificate authentication (mTLS).
    ///
    /// The `client_ca_store` contains trusted CA certificates against which
    /// client certificates will be verified during the handshake.
    pub fn with_client_auth(mut self, client_ca_store: RootCertStore) -> Self {
        self.client_ca_store = Some(client_ca_store);
        self
    }

    /// Build the configuration.
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

        // Wrap immediately so Drop frees the CTX if any subsequent call fails.
        let inner = Arc::new(CtxInner { ctx });

        // Load server certificate.
        // SAFETY: inner.ctx is valid (created above, freed by CtxInner::drop).
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

        // Load server private key.
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

        // Configure client certificate authentication (mTLS) if a CA store
        // was provided via with_client_auth().
        if let Some(ref ca_store) = self.client_ca_store {
            for (cert_data, format) in ca_store.iter() {
                // SAFETY: inner.ctx is owned by CtxInner and has not been freed.
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

            // SAFETY: inner.ctx is owned by CtxInner and has not been freed.
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
pub struct TlsAcceptor {
    config: TlsServerConfig,
}

impl TlsAcceptor {
    /// Create a new acceptor with the given server configuration.
    pub fn new(config: TlsServerConfig) -> Self {
        TlsAcceptor { config }
    }

    /// Accept a TLS connection on the given stream.
    ///
    /// Performs the TLS handshake. On success, returns a [`TlsServer`] that
    /// implements [`Read`] and [`Write`].
    ///
    /// The stream must implement [`TlsSocket`], which is automatically
    /// provided for `TcpStream` and any type implementing `AsRawFd` (Unix)
    /// or `AsRawSocket` (Windows).
    pub fn accept<S: Read + Write + TlsSocket>(&self, stream: S) -> Result<TlsServer<S>> {
        // SAFETY: config.inner.ctx is owned by Arc<CtxInner> and not freed
        // while we hold a reference to it.
        let ssl = unsafe { wolfSSL_new(self.config.inner.ctx) };
        if ssl.is_null() {
            return Err(TlsError::AllocFailed {
                func: "wolfSSL_new",
            });
        }
        // Guard ensures wolfSSL_free is called on every error path.
        let guard = SslGuard(ssl);

        let fd = stream.tls_raw_fd();
        // SAFETY: ssl was returned by wolfSSL_new above and has not been freed.
        let ret = unsafe { wolfSSL_set_fd(guard.as_ptr(), fd) };
        if ret != WOLFSSL_SUCCESS as core::ffi::c_int {
            return Err(TlsError::Ffi {
                code: ret,
                func: "wolfSSL_set_fd",
            });
        }

        // Perform the TLS handshake (server side).
        // SAFETY: ssl has not been freed, and fd was set above.
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
            stream,
            // Clone is cheap (Arc::clone) — keeps the WOLFSSL_CTX alive
            // for the lifetime of this WOLFSSL session.
            config: self.config.clone(),
        })
    }
}

/// A TLS server connection wrapping a stream.
///
/// Implements [`Read`] and [`Write`] for encrypted I/O.
///
/// The stream `S` must implement [`TlsSocket`], which is automatically
/// provided for any type implementing `AsRawFd` (Unix) or `AsRawSocket`
/// (Windows) — e.g. [`std::net::TcpStream`].
///
/// **Drop behavior**: dropping a `TlsServer` sends a TLS `close_notify`
/// via `wolfSSL_shutdown`, which may block on the underlying transport.
pub struct TlsServer<S> {
    ssl: *mut WOLFSSL,
    /// Kept alive so the underlying fd remains valid for wolfSSL I/O.
    #[allow(dead_code)]
    stream: S,
    /// Kept alive so the `WOLFSSL_CTX` (owned by `Arc<CtxInner>`) outlives
    /// the `WOLFSSL` session.
    #[allow(dead_code)]
    config: TlsServerConfig,
}

impl<S> std::fmt::Debug for TlsServer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer").field("ssl", &self.ssl).finish()
    }
}

// SAFETY: Same reasoning as TlsClient — exclusive &mut self for I/O,
// and the WOLFSSL pointer can be moved across threads.
unsafe impl<S: Send> Send for TlsServer<S> {}

crate::impl_tls_io!(TlsServer);
