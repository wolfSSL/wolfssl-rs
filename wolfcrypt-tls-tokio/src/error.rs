// Async-specific error types for wolfcrypt-tls-tokio.
// Wraps errors from wolfcrypt-tls and adds IO/async context.

use std::io;

/// Errors that can occur during async TLS operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error from the underlying wolfSSL session (propagated from wolfcrypt-tls).
    Tls(wolfssl::TlsError),
    /// An IO error from the underlying async transport.
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Tls(e) => Some(e),
            Error::Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<wolfssl::TlsError> for Error {
    fn from(e: wolfssl::TlsError) -> Self {
        Error::Tls(e)
    }
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, Error>;
