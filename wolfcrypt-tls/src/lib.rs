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
//! # IO model
//!
//! All TLS sessions use wolfSSL's custom IO callback mechanism rather than
//! `wolfSSL_set_fd`.  Any `std::io::Read + Write` type (e.g. `TcpStream`)
//! automatically satisfies the [`IOCallbacks`] trait.  Async runtimes supply
//! their own `IOCallbacks` implementation backed by in-memory byte buffers.

mod callback;
mod certificate;
mod client;
mod config;
#[doc(hidden)]
pub mod config_holder;
mod error;
mod protocol;
mod server;

pub use callback::{IOCallbackResult, IOCallbacks};
pub use certificate::{Certificate, PrivateKey, RootCertStore};
pub use client::TlsClient;
pub use config::{TlsClientConfig, TlsClientConfigBuilder};
#[doc(hidden)]
pub use config_holder::ConfigHolder;
pub use error::{error_string, Result, TlsError};
pub use protocol::ProtocolVersion;
pub use server::{TlsAcceptor, TlsServer, TlsServerConfig, TlsServerConfigBuilder};
// Raw callback type aliases from wolfcrypt-sys, re-exported so callers of
// new_ssl_with_io_callbacks don't need to depend on wolfcrypt-sys directly.
pub use wolfcrypt_sys::{CallbackIORecv, CallbackIOSend};

use std::sync::Once;

use wolfcrypt_sys::*;

/// RAII guard that frees a `WOLFSSL` pointer on drop.
///
/// Used during session construction to ensure `wolfSSL_free` is called on
/// every error path. Defuse with `into_raw()` on the success path to
/// transfer ownership to the caller.
pub(crate) struct SslGuard(pub(crate) *mut wolfcrypt_sys::WOLFSSL);

impl std::fmt::Debug for SslGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SslGuard").field(&self.0).finish()
    }
}

impl Drop for SslGuard {
    fn drop(&mut self) {
        // SAFETY: the WOLFSSL pointer was created by wolfSSL_new and has
        // not been freed (into_raw was not called).
        unsafe {
            wolfcrypt_sys::wolfSSL_free(self.0);
        }
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
pub fn ensure_init() {
    INIT.call_once(|| {
        // SAFETY: wolfSSL_Init is safe to call once at startup.
        let ret = unsafe { wolfSSL_Init() };
        // wolfSSL_Init returns WOLFSSL_SUCCESS (1) on success; 0 is not documented
        // as a success value, so check for equality rather than >= 0.
        assert!(
            ret == WOLFSSL_SUCCESS as core::ffi::c_int,
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
    }

    #[test]
    fn want_read_write_internal_codes_are_negative() {
        // NOTE: these are INTERNAL callback return codes used by wolfSSL's
        // custom IO callback mechanism, NOT the values that wolfSSL_get_error()
        // returns. Do not use these in match arms on wolfSSL_get_error output.
        let want_read = wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_READ_E;
        let want_write = wolfcrypt_sys::wolfSSL_ErrorCodes_WOLFSSL_ERROR_WANT_WRITE_E;
        assert!(want_read < 0, "WANT_READ_E should be negative (got {want_read})");
        assert!(want_write < 0, "WANT_WRITE_E should be negative (got {want_write})");
        assert_eq!(want_read, -2, "WANT_READ_E should be -2");
        assert_eq!(want_write, -3, "WANT_WRITE_E should be -3");
    }

    #[test]
    fn wolfssl_get_error_codes_are_positive() {
        // wolfSSL_get_error() returns the OpenSSL-compatible positive values,
        // not the negative _E internal callback codes.
        assert_eq!(
            wolfcrypt_sys::WOLFSSL_ERROR_WANT_READ as core::ffi::c_int,
            2,
            "WOLFSSL_ERROR_WANT_READ should be 2"
        );
        assert_eq!(
            wolfcrypt_sys::WOLFSSL_ERROR_WANT_WRITE as core::ffi::c_int,
            3,
            "WOLFSSL_ERROR_WANT_WRITE should be 3"
        );
    }

    #[test]
    fn tls_types_implement_debug() {
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<TlsClient<std::net::TcpStream>>();
        assert_debug::<server::TlsServer<std::net::TcpStream>>();
    }

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
                assert!(result.is_ok(), "resolve_method({side:?}, {versions:?}) should succeed");
                assert!(!result.unwrap().is_null(), "resolve_method({side:?}, {versions:?}) returned null");
            }
        }
    }

    #[test]
    fn cint_max_is_positive_and_usable_as_len() {
        let max = core::ffi::c_int::MAX as usize;
        assert!(max >= 32767, "c_int::MAX too small: {max}");
        let clamped = std::cmp::min(usize::MAX, max);
        assert_eq!(clamped, max);
        assert_eq!(clamped as core::ffi::c_int, core::ffi::c_int::MAX);
    }

    /// Verify IOCallbacks blanket impl works for TcpStream.
    /// Compile-time check only.
    #[test]
    fn tcpstream_satisfies_iocallbacks() {
        fn assert_iocb<T: IOCallbacks>() {}
        assert_iocb::<std::net::TcpStream>();
    }
}
