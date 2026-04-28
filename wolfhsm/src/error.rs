use core::fmt;

/// Inclusive lower bound of the wolfHSM WH_ERROR_* code range.
pub(crate) const WH_ERROR_MIN: i32 = -2302;
/// Inclusive upper bound of the wolfHSM WH_ERROR_* code range (WH_ERROR_BADARGS).
pub(crate) const WH_ERROR_MAX: i32 = -2000;

/// Error type for wolfHSM operations.
///
/// Distinguishes between errors originating from the wolfHSM C library
/// (WH_ERROR_* range `WH_ERROR_MIN`..=`WH_ERROR_MAX`) and errors from
/// lower-level wolfSSL/wolfCrypt FFI calls.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A wolfHSM error code (WH_ERROR_* range -2302 to -2000).
    Wh {
        /// The wolfHSM error code (negative integer in the WH_ERROR_* range).
        code: i32,
    },
    /// A wolfSSL/wolfCrypt error code (any other nonzero return).
    ///
    /// `func` is the C function name (e.g. `"wh_Client_Connect"`) so
    /// error messages identify the failing call without grepping headers.
    Ffi {
        /// The wolfSSL/wolfCrypt error code (typically negative).
        code: i32,
        /// Name of the C function that returned the error.
        func: &'static str,
    },
    /// A CryptoCb device is already registered for this process.
    ///
    /// Only one [`crate::CryptoCbGuard`] can exist at a time.  Drop the
    /// existing guard before registering again.
    AlreadyRegistered,
    /// A caller-supplied argument failed validation before any FFI call was made.
    ///
    /// `msg` is a `'static` description of what the caller passed and what is
    /// required (e.g. `"key must be 16, 24, or 32 bytes"`).
    BadArgs {
        /// Human-readable description of the invalid argument.
        msg: &'static str,
    },
    /// An NVM delete succeeded but the subsequent add failed.
    ///
    /// The NVM object with `id` was deleted from the server before the add
    /// was attempted, so the original data is permanently lost.  The caller
    /// should check whether `id` still needs to be recreated.
    DataLost {
        /// The NVM object ID that was deleted before the add failed.
        id: u16,
    },
    /// The server returned a well-formed response that is logically impossible.
    ///
    /// Examples: a key ID of zero after successful key generation, or a
    /// negative key size after a successful `get_size` call.  The FFI call
    /// returned `0` (success), but the response payload is invalid.
    ///
    /// `msg` describes the specific anomaly.
    ProtocolError {
        /// Human-readable description of the impossible server response.
        msg: &'static str,
    },
    /// A cryptographic verification completed but the signature or MAC was invalid.
    ///
    /// Distinct from [`Ffi`][Error::Ffi] (transport/FFI failure) and
    /// [`ProtocolError`][Error::ProtocolError] (impossible response).
    /// Here the HSM ran the check to completion and determined the material
    /// does not match.
    InvalidSignature,
}

impl Error {
    /// Map a wolfHSM C return code to a `Result`.
    ///
    /// - `0` → `Ok(())`
    /// - WH_ERROR_* range (`WH_ERROR_MIN..=WH_ERROR_MAX`) → `Err(Error::Wh { code })`
    /// - Any other nonzero value → `Err(Error::Ffi { code, func })`
    ///
    /// `func` is the C function name, included in `Ffi` errors for diagnostics.
    #[inline]
    pub fn check(rc: i32, func: &'static str) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else if (WH_ERROR_MIN..=WH_ERROR_MAX).contains(&rc) {
            Err(Error::Wh { code: rc })
        } else {
            Err(Error::Ffi { code: rc, func })
        }
    }
}

/// Return the symbolic name for a WH_ERROR_* code, or `None` if unknown.
///
/// Covers the most common codes from `wolfhsm/wh_error.h`.  For the full
/// list, consult that header directly.
fn wh_error_name(code: i32) -> Option<&'static str> {
    match code {
        -2000 => Some("WH_ERROR_BADARGS"),
        -2001 => Some("WH_ERROR_ABORTED"),
        -2002 => Some("WH_ERROR_NOTREADY"),
        -2003 => Some("WH_ERROR_CANCEL"),
        -2004 => Some("WH_ERROR_ACCESS"),
        -2005 => Some("WH_ERROR_NOTVERIFIED"),
        -2006 => Some("WH_ERROR_NOTIMPL"),
        -2007 => Some("WH_ERROR_LOCKED"),
        -2008 => Some("WH_ERROR_SEQUENCE"),
        -2009 => Some("WH_ERROR_MEMORY"),
        -2010 => Some("WH_ERROR_NOSPC"),
        -2011 => Some("WH_ERROR_SIZE"),
        -2012 => Some("WH_ERROR_NOHANDLER"),
        -2013 => Some("WH_ERROR_NOTFOUND"),
        -2014 => Some("WH_ERROR_TIMEOUT"),
        -2015 => Some("WH_ERROR_BUSY"),
        _ => None,
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wh { code } => {
                if let Some(name) = wh_error_name(*code) {
                    write!(f, "wolfHSM error {code} ({name})")
                } else {
                    write!(f, "wolfHSM error {code} (see wolfhsm/wh_error.h)")
                }
            }
            Error::Ffi { code, func } => {
                write!(f, "{func} failed: wolfSSL FFI error {code}")
            }
            Error::AlreadyRegistered => {
                write!(
                    f,
                    "wolfHSM CryptoCb already registered; drop the existing guard first"
                )
            }
            Error::BadArgs { msg } => write!(f, "invalid argument: {msg}"),
            Error::DataLost { id } => {
                write!(
                    f,
                    "wolfHSM NVM object {id} deleted but add failed; original data lost"
                )
            }
            Error::ProtocolError { msg } => {
                write!(f, "wolfHSM protocol error: {msg}")
            }
            Error::InvalidSignature => {
                write!(f, "wolfHSM: signature or MAC verification failed")
            }
        }
    }
}

impl core::error::Error for Error {}
