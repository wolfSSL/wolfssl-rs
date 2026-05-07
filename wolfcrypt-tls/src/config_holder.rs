// Cross-crate helper for the async layers.
//
// `wolfcrypt-tls-tokio` and `wolfcrypt-tls-futures-io` both need to keep
// the `WOLFSSL_CTX` alive for the entire lifetime of a `WOLFSSL` session.
// The cleanest way to do that is to hold the originating
// `TlsClientConfig` or `TlsServerConfig` inside the stream, since both
// of those types are `Arc`-backed and a clone is just a refcount bump.
//
// Defining this enum once in `wolfcrypt-tls` (rather than once per async
// crate) keeps the two async crates byte-for-byte aligned without any
// extra dependency in the base crate.

use crate::{TlsClientConfig, TlsServerConfig};

/// Keeps a client- or server-side `WOLFSSL_CTX` alive for the lifetime
/// of the session that uses it.
///
/// `TlsClientConfig` / `TlsServerConfig` are already `Arc`-backed
/// internally, so cloning one is a cheap refcount bump.  No outer
/// `Arc` wrapping is needed.
///
/// This type is exposed only so that `wolfcrypt-tls-tokio` and
/// `wolfcrypt-tls-futures-io` (which are independent crates) can both
/// use it.  End-user code should never need to construct or match on
/// `ConfigHolder` directly.
#[doc(hidden)]
pub enum ConfigHolder {
    Client(TlsClientConfig),
    Server(TlsServerConfig),
}
