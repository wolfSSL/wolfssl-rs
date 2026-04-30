use std::ffi::CStr;
use std::fmt;
use std::io;

use wolfcrypt_sys::*;

/// Result type alias for TLS operations.
pub type Result<T> = std::result::Result<T, TlsError>;

/// Errors that can occur during TLS operations.
///
/// The `Ffi` and `AllocFailed` variants mirror `WolfCryptError` in the
/// `wolfcrypt` crate so that error handling is consistent across the
/// workspace.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError {
    /// Builder was not given required configuration (e.g. missing root
    /// certificates or server certificate/key).
    InvalidConfig(&'static str),
    /// Certificate verification failed.
    CertificateVerification(String),
    /// I/O error from the underlying transport.
    Io(io::Error),
    /// A wolfSSL allocation or initialization function returned NULL.
    AllocFailed { func: &'static str },
    /// A wolfSSL FFI call returned a non-success error code.
    Ffi { code: i32, func: &'static str },
    /// Connection has been shut down.
    Closed,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::InvalidConfig(msg) => write!(f, "invalid TLS config: {msg}"),
            TlsError::CertificateVerification(msg) => {
                write!(f, "certificate verification failed: {msg}")
            }
            TlsError::AllocFailed { func } => {
                write!(f, "{func} returned NULL (allocation failed)")
            }
            TlsError::Io(err) => write!(f, "I/O error: {err}"),
            TlsError::Ffi { code, func } => {
                let reason = error_string(*code);
                write!(f, "{func} failed: {reason} (wolfSSL error {code})")
            }
            TlsError::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        TlsError::Io(err)
    }
}

/// Look up the human-readable description for a wolfSSL / wolfCrypt error code.
///
/// Uses `wolfSSL_ERR_reason_error_string` which covers both SSL-level errors
/// (handshake failures, alert codes) and wolfCrypt-level errors, making it
/// the correct choice for codes returned by `wolfSSL_get_error`.
///
/// Falls back to `wc_GetErrorString` for wolfCrypt-only codes, and finally
/// to `"unknown error"` if neither function recognises the code.
pub(crate) fn error_string(code: core::ffi::c_int) -> &'static str {
    // Try the SSL-level lookup first — it handles the full error range.
    // Cast through c_uint first to zero-extend (not sign-extend) negative
    // codes into c_ulong. On LP64 platforms c_ulong is 64-bit; a direct
    // `code as c_ulong` sign-extends -308 to 0xFFFF_FFFF_FFFF_FECC which
    // may not match wolfSSL's internal lookup tables.
    // SAFETY: wolfSSL_ERR_reason_error_string returns a static string pointer.
    let ptr = unsafe {
        wolfSSL_ERR_reason_error_string((code as core::ffi::c_uint) as core::ffi::c_ulong)
    };
    if !ptr.is_null() {
        if let Ok(s) = unsafe { CStr::from_ptr(ptr) }.to_str() {
            if !s.is_empty() {
                return s;
            }
        }
    }

    // Fall back to the wolfCrypt-level lookup for low-level crypto errors.
    // SAFETY: wc_GetErrorString returns a static string pointer.
    let ptr = unsafe { wc_GetErrorString(code) };
    if !ptr.is_null() {
        if let Ok(s) = unsafe { CStr::from_ptr(ptr) }.to_str() {
            if !s.is_empty() {
                return s;
            }
        }
    }

    "unknown error"
}

/// Look up the human-readable description for an X509 verification error code.
///
/// Uses `wolfSSL_X509_verify_cert_error_string` which returns strings like
/// `"certificate has expired"` or `"unable to get local issuer certificate"`.
pub(crate) fn verify_error_string(code: core::ffi::c_long) -> &'static str {
    // SAFETY: wolfSSL_X509_verify_cert_error_string returns a static string pointer.
    let ptr = unsafe { wolfSSL_X509_verify_cert_error_string(code) };
    if !ptr.is_null() {
        if let Ok(s) = unsafe { CStr::from_ptr(ptr) }.to_str() {
            if !s.is_empty() {
                return s;
            }
        }
    }
    "unknown verification error"
}

/// Assert that a wolfSSL FFI call returned `WOLFSSL_SUCCESS`.
///
/// Only for functions whose success value is `WOLFSSL_SUCCESS` (1), not for
/// functions that return byte counts or other positive values on success.
pub(crate) fn expect_wolfssl_success(
    ret: core::ffi::c_int,
    func: &'static str,
) -> Result<core::ffi::c_int> {
    if ret == WOLFSSL_SUCCESS as core::ffi::c_int {
        Ok(ret)
    } else {
        Err(TlsError::Ffi { code: ret, func })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_produces_useful_messages() {
        let err = TlsError::Ffi {
            code: -308,
            func: "wolfSSL_connect",
        };
        let msg = format!("{err}");
        assert!(msg.contains("wolfSSL_connect"));
        assert!(msg.contains("-308"));

        let err = TlsError::CertificateVerification("expired".into());
        assert!(format!("{err}").contains("expired"));

        let err = TlsError::Closed;
        assert!(format!("{err}").contains("closed"));
    }

    #[test]
    fn ffi_error_includes_human_readable_reason() {
        // -188 is ASN_NO_SIGNER_E ("ASN no signer to confirm failure")
        // in wolfSSL. The exact string may vary across versions, but
        // the Display impl must include *something* beyond just the
        // numeric code — that's the whole point of wc_GetErrorString.
        let err = TlsError::Ffi {
            code: -188,
            func: "wolfSSL_connect",
        };
        let msg = format!("{err}");
        assert!(msg.contains("-188"), "should contain the error code");
        assert!(
            msg.contains("wolfSSL_connect"),
            "should contain the function name"
        );
        // The reason string must be non-empty and not just "unknown error".
        // wc_GetErrorString(-188) returns something like "ASN no signer..."
        let reason = error_string(-188);
        assert!(
            !reason.is_empty() && reason != "unknown error",
            "error_string(-188) should return a known error, got: {reason:?}"
        );
        assert!(
            msg.contains(reason),
            "Display should include the reason string '{reason}', got: {msg}"
        );
    }

    #[test]
    fn error_string_returns_nonempty_for_known_codes() {
        // Spot-check a few well-known wolfSSL error codes.
        for code in [-155, -188, -245, -313] {
            let s = error_string(code);
            assert!(
                !s.is_empty() && s != "unknown error",
                "error_string({code}) should return a known error, got: {s:?}"
            );
        }
    }

    #[test]
    fn verify_error_string_returns_useful_text() {
        // X509_V_OK (0) should return something indicating success.
        let ok_str = verify_error_string(0);
        assert!(
            !ok_str.is_empty() && ok_str != "unknown verification error",
            "verify_error_string(0) should be recognised, got: {ok_str:?}"
        );

        // A non-zero code should also produce a non-empty reason.
        // 20 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY in OpenSSL/wolfSSL.
        let err_str = verify_error_string(20);
        assert!(
            !err_str.is_empty() && err_str != "unknown verification error",
            "verify_error_string(20) should be recognised, got: {err_str:?}"
        );
    }

    /// Verify that `error_string` zero-extends (not sign-extends) negative
    /// error codes when casting to `c_ulong`. On LP64 platforms, a direct
    /// `i32 as u64` sign-extends -308 to `0xFFFF_FFFF_FFFF_FECC`, which
    /// may break wolfSSL's internal lookup. The cast must go through
    /// `c_uint` first to produce `0x0000_0000_FFFF_FECC`.
    #[test]
    fn error_code_cast_zero_extends_not_sign_extends() {
        let code: core::ffi::c_int = -308;
        // This is the cast used in error_string(). Verify it zero-extends.
        let as_culong = (code as core::ffi::c_uint) as core::ffi::c_ulong;
        // The high 32 bits must be zero — sign-extension would set them to 0xFFFF_FFFF.
        assert_eq!(
            as_culong >> 32,
            0,
            "error code should be zero-extended, not sign-extended; \
             got {as_culong:#018x}"
        );
        // The low 32 bits must match the unsigned reinterpretation.
        assert_eq!(as_culong as u32, code as u32);

        // And the actual lookup must still work — a wrong cast would
        // cause wolfSSL_ERR_reason_error_string to miss the code.
        let s = error_string(code);
        assert!(
            s != "unknown error",
            "error_string({code}) returned 'unknown error'; \
             the zero-extension cast may be wrong"
        );
    }

    #[test]
    fn alloc_failed_display_says_allocation_failed() {
        let err = TlsError::AllocFailed {
            func: "wolfSSL_CTX_new",
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("allocation failed"),
            "AllocFailed should say 'allocation failed', got: {msg}"
        );
        assert!(
            !msg.contains("out of memory"),
            "AllocFailed should not say 'out of memory', got: {msg}"
        );
        assert!(msg.contains("wolfSSL_CTX_new"));
    }

    #[test]
    fn from_io_error_roundtrips() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let tls_err = TlsError::from(io_err);
        match &tls_err {
            TlsError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
            other => panic!("expected Io variant, got: {other:?}"),
        }
        // source() returns the io::Error
        assert!(std::error::Error::source(&tls_err).is_some());
    }
}
