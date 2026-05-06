// wolfcrypt-tls-futures-io — async TLS backed by wolfSSL.
//
// Targets futures::io::AsyncRead + AsyncWrite — the native IO traits for
// the smol / async-io / async-std ecosystem.
//
// Exports a futures-rustls-compatible surface:
//
//   TlsConnector  — client-side, wraps TlsClientConfig
//   TlsAcceptor   — server-side, wraps TlsServerConfig
//   TlsStream<IO> — implements futures::io::AsyncRead + AsyncWrite
//
// Config and certificate types are re-exported from wolfcrypt-tls so callers
// share one config-building API across the blocking, tokio, and smol layers.
//
// Tokio users: use wolfcrypt-tls-tokio instead.  If you need to bridge
// between the two trait families, tokio-util's Compat wrapper works well.

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
pub use wolfssl::ensure_init;
