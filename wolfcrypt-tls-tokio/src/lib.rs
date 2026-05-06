// wolfcrypt-tls-tokio — async TLS backed by wolfSSL.
//
// Exports a tokio-rustls-compatible surface:
//
//   TlsConnector  — client-side, wraps TlsClientConfig
//   TlsAcceptor   — server-side, wraps TlsServerConfig
//   TlsStream<IO> — implements AsyncRead + AsyncWrite
//
// Config and certificate types are re-exported from wolfcrypt-tls (the
// wolfssl crate) so callers share one config-building API across both the
// blocking and async layers.

pub mod acceptor;
pub mod bridge;
pub mod connector;
pub mod error;
pub mod stream;

pub use acceptor::{Accept, TlsAcceptor};
pub use connector::{Connect, TlsConnector};
pub use error::{Error, Result};
pub use stream::TlsStream;

// Re-exports from wolfcrypt-tls — no duplication of cert/key loading logic.
pub use wolfssl::{
    Certificate, PrivateKey, ProtocolVersion, RootCertStore, TlsClientConfig,
    TlsClientConfigBuilder, TlsError, TlsServerConfig, TlsServerConfigBuilder,
};
// Re-export ensure_init so callers don't need to depend on wolfcrypt-tls directly.
pub use wolfssl::ensure_init;
