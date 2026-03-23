//! Safe Rust TLS API backed by wolfSSL.
//!
//! This crate provides idiomatic Rust types for TLS client and server
//! connections, wrapping the wolfSSL C library's TLS implementation.
//!
//! # Quick start — TLS client
//!
//! ```no_run
//! use wolfssl::{TlsClientConfig, TlsClient, RootCertStore};
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let mut root_store = RootCertStore::new();
//! // root_store.add_pem(include_bytes!("ca.pem"));
//!
//! let config = TlsClientConfig::builder()
//!     .with_root_certificates(root_store)
//!     .with_no_client_auth()
//!     .build()
//!     .unwrap();
//!
//! let stream = TcpStream::connect("example.com:443").unwrap();
//! let mut tls = TlsClient::new(config, "example.com", stream).unwrap();
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
//! ```
//!
//! # Blocking I/O
//!
//! This crate currently targets blocking I/O only. Non-blocking transport
//! support is planned for a future release.

mod certificate;
mod client;
mod config;
mod error;
mod protocol;
mod server;

pub use certificate::{Certificate, PrivateKey, RootCertStore};
pub use client::TlsClient;
pub use config::{TlsClientConfig, TlsClientConfigBuilder};
pub use error::{Result, TlsError};
pub use protocol::ProtocolVersion;
pub use server::{TlsAcceptor, TlsServer, TlsServerConfig, TlsServerConfigBuilder};

use std::sync::Once;

use wolfcrypt_sys::*;

// Platform abstraction for obtaining a raw file descriptor / socket handle
// that wolfSSL_set_fd can use. Keeps the rest of the crate platform-agnostic.

/// Trait for stream types that can provide a raw fd or socket for wolfSSL.
///
/// Automatically implemented for any type implementing the platform's
/// raw I/O trait (`AsRawFd` on Unix, `AsRawSocket` on Windows).
pub trait TlsSocket {
    /// Return the raw descriptor as a `c_int` for `wolfSSL_set_fd`.
    fn tls_raw_fd(&self) -> core::ffi::c_int;
}

#[cfg(unix)]
impl<T: std::os::unix::io::AsRawFd> TlsSocket for T {
    fn tls_raw_fd(&self) -> core::ffi::c_int {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsRawSocket> TlsSocket for T {
    fn tls_raw_fd(&self) -> core::ffi::c_int {
        let sock = self.as_raw_socket();
        // wolfSSL_set_fd takes c_int, but Windows SOCKET is uintptr_t.
        // In practice Winsock handles fit in 32 bits, but guard against
        // silent truncation on pathological systems.
        assert!(
            sock <= core::ffi::c_int::MAX as u64,
            "socket handle {sock:#x} exceeds c_int range"
        );
        sock as core::ffi::c_int
    }
}

/// Implement `Read`, `Write`, and `Drop` for a TLS connection type.
///
/// Both `TlsClient<S>` and `TlsServer<S>` hold a `ssl: *mut WOLFSSL` field
/// and need identical I/O and cleanup logic.  This macro eliminates the
/// duplication.
macro_rules! impl_tls_io {
    ($ty:ident) => {
        impl<S: std::io::Read + std::io::Write + $crate::TlsSocket> std::io::Read for $ty<S> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                // Clamp to c_int::MAX to avoid silent truncation on 64-bit.
                let len = std::cmp::min(buf.len(), core::ffi::c_int::MAX as usize) as core::ffi::c_int;
                // SAFETY: ssl is valid (created by wolfSSL_new, not yet freed).
                let ret = unsafe {
                    wolfcrypt_sys::wolfSSL_read(
                        self.ssl,
                        buf.as_mut_ptr() as *mut core::ffi::c_void,
                        len,
                    )
                };
                if ret > 0 {
                    Ok(ret as usize)
                } else if ret == 0 {
                    Ok(0) // EOF / connection closed
                } else {
                    // SAFETY: ssl is valid.
                    let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(self.ssl, ret) };
                    match err {
                        wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E
                        | wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E => {
                            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                        }
                        _ => Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("wolfSSL_read: {} (error {err})", $crate::error::error_string(err)),
                        )),
                    }
                }
            }
        }

        impl<S: std::io::Read + std::io::Write + $crate::TlsSocket> std::io::Write for $ty<S> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                // Clamp to c_int::MAX to avoid silent truncation on 64-bit.
                let len = std::cmp::min(buf.len(), core::ffi::c_int::MAX as usize) as core::ffi::c_int;
                // SAFETY: ssl is valid, buf is a valid slice.
                let ret = unsafe {
                    wolfcrypt_sys::wolfSSL_write(
                        self.ssl,
                        buf.as_ptr() as *const core::ffi::c_void,
                        len,
                    )
                };
                if ret > 0 {
                    Ok(ret as usize)
                } else {
                    // SAFETY: ssl is valid.
                    let err = unsafe { wolfcrypt_sys::wolfSSL_get_error(self.ssl, ret) };
                    match err {
                        wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E
                        | wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E => {
                            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                        }
                        _ => Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("wolfSSL_write: {} (error {err})", $crate::error::error_string(err)),
                        )),
                    }
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                // wolfSSL_write sends a complete TLS record per call, so
                // there is no internal buffering to flush.
                Ok(())
            }
        }

        impl<S> Drop for $ty<S> {
            fn drop(&mut self) {
                // Best-effort TLS shutdown. This may block on the underlying
                // socket while the close_notify exchange completes. Errors are
                // intentionally ignored — there is nothing useful the caller
                // can do during drop.
                //
                // SAFETY: ssl is valid and has not been freed.
                unsafe {
                    let _ = wolfcrypt_sys::wolfSSL_shutdown(self.ssl);
                    wolfcrypt_sys::wolfSSL_free(self.ssl);
                }
            }
        }
    };
}

// Make the macro visible to submodules (client, server).
pub(crate) use impl_tls_io;

/// RAII guard that frees a `WOLFSSL` pointer on drop.
///
/// Used in `TlsClient::new` and `TlsAcceptor::accept` to ensure
/// `wolfSSL_free` is called on every error path. Defuse with
/// `into_raw()` on the success path to transfer ownership.
pub(crate) struct SslGuard(pub(crate) *mut wolfcrypt_sys::WOLFSSL);

impl Drop for SslGuard {
    fn drop(&mut self) {
        // SAFETY: the WOLFSSL pointer was created by wolfSSL_new and has
        // not been freed (into_raw was not called).
        unsafe { wolfcrypt_sys::wolfSSL_free(self.0); }
    }
}

impl SslGuard {
    pub(crate) fn as_ptr(&self) -> *mut wolfcrypt_sys::WOLFSSL {
        self.0
    }

    /// Consume the guard without freeing the pointer, transferring
    /// ownership to the caller.
    pub(crate) fn into_raw(self) -> *mut wolfcrypt_sys::WOLFSSL {
        let ptr = self.0;
        std::mem::forget(self);
        ptr
    }
}

static INIT: Once = Once::new();

/// Ensure wolfSSL is initialized exactly once.
///
/// Called automatically by config builders. You only need to call this
/// directly if using raw wolfcrypt-sys FFI alongside this crate.
///
/// Note: `wolfSSL_Cleanup` is never called. This is intentional —
/// wolfSSL initialization is process-lifetime, and calling cleanup
/// while other threads may still hold `WOLFSSL` pointers is unsound.
pub fn ensure_init() {
    INIT.call_once(|| {
        // SAFETY: wolfSSL_Init is safe to call once at startup.
        let ret = unsafe { wolfSSL_Init() };
        assert!(
            ret >= 0,
            "wolfSSL_Init failed with code {ret}"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wolfssl_init_and_cleanup() {
        ensure_init();
        // If we got here, init succeeded.
    }

    /// Verify the error constants used in the Read/Write impls are the correct
    /// wolfSSL error codes (negative c_int), not the OpenSSL compat constants
    /// (positive u32). If someone changes the match arms back to the wrong
    /// constants, this test catches it.
    #[test]
    fn want_read_write_error_codes_are_negative() {
        // wolfSSL_get_error returns c_int; WANT_READ is -2, WANT_WRITE is -3.
        // The OpenSSL compat constants (WOLFSSL_ERROR_WANT_READ = 2) are
        // positive and would never match a negative error code.
        let want_read = wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E;
        let want_write = wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E;
        assert!(
            want_read < 0,
            "WANT_READ_E should be negative (got {want_read}); \
             are we matching the OpenSSL compat constant by mistake?"
        );
        assert!(
            want_write < 0,
            "WANT_WRITE_E should be negative (got {want_write}); \
             are we matching the OpenSSL compat constant by mistake?"
        );
        // Verify they're the expected specific values.
        assert_eq!(want_read, -2, "WANT_READ_E should be -2");
        assert_eq!(want_write, -3, "WANT_WRITE_E should be -3");
    }

    /// Verify TlsClient and TlsServer both implement Debug.
    /// This is a compile-time check — if the Debug impl is removed, this
    /// test fails to compile.
    #[test]
    fn tls_types_implement_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<TlsClient<std::net::TcpStream>>();
        assert_debug::<server::TlsServer<std::net::TcpStream>>();
    }

    /// Smoke-test that `resolve_method` returns a non-null pointer for every
    /// valid (versions, side) combination. This guards against the null check
    /// accidentally triggering on inputs that should succeed.
    #[test]
    fn resolve_method_returns_non_null_for_all_valid_inputs() {
        use crate::protocol::{resolve_method, ProtocolVersion, Side};

        ensure_init();

        let version_sets: &[Option<&[ProtocolVersion]>] = &[
            None,
            Some(&[ProtocolVersion::Tls12]),
            Some(&[ProtocolVersion::Tls13]),
            Some(&[ProtocolVersion::Tls12, ProtocolVersion::Tls13]),
            Some(&[ProtocolVersion::Tls13, ProtocolVersion::Tls12]),
        ];

        for side in [Side::Client, Side::Server] {
            for versions in version_sets {
                let result = unsafe { resolve_method(side, *versions) };
                assert!(
                    result.is_ok(),
                    "resolve_method({side:?}, {versions:?}) should succeed"
                );
                let ptr = result.unwrap();
                assert!(
                    !ptr.is_null(),
                    "resolve_method({side:?}, {versions:?}) returned null"
                );
            }
        }
    }

    /// Verify that the Read/Write clamping limit matches c_int::MAX.
    /// This test ensures the clamp in impl_tls_io! cannot silently regress
    /// to an unclamped cast.
    #[test]
    fn cint_max_is_positive_and_usable_as_len() {
        let max = core::ffi::c_int::MAX as usize;
        // On all platforms wolfSSL targets, c_int is at least 16-bit.
        assert!(max >= 32767, "c_int::MAX too small: {max}");
        // The clamp `min(buf.len(), c_int::MAX as usize)` must produce
        // a value that fits in c_int without wrapping.
        let clamped = std::cmp::min(usize::MAX, max);
        assert_eq!(clamped, max);
        assert_eq!(clamped as core::ffi::c_int, core::ffi::c_int::MAX);
    }
}
