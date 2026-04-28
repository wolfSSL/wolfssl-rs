use core::fmt;

/// Inclusive lower bound of the wolfHSM WH_ERROR_* code range.
pub(crate) const WH_ERROR_MIN: i32 = -2302;
/// Inclusive upper bound of the wolfHSM WH_ERROR_* code range (WH_ERROR_BADARGS).
pub(crate) const WH_ERROR_MAX: i32 = -2000;

/// Error type for wolfHSM operations.
///
/// Distinguishes between errors originating from the wolfHSM C library
/// (WH_ERROR_* range [`WH_ERROR_MIN`]..=[`WH_ERROR_MAX`]) and errors from
/// lower-level wolfSSL/wolfCrypt FFI calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WolfHsmError {
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
    /// Distinct from [`Ffi`][WolfHsmError::Ffi] (transport/FFI failure) and
    /// [`ProtocolError`][WolfHsmError::ProtocolError] (impossible response).
    /// Here the HSM ran the check to completion and determined the material
    /// does not match.
    InvalidSignature,
}

impl WolfHsmError {
    /// Map a wolfHSM C return code to a `Result`.
    ///
    /// - `0` → `Ok(())`
    /// - WH_ERROR_* range (`WH_ERROR_MIN..=WH_ERROR_MAX`) → `Err(WolfHsmError::Wh { code })`
    /// - Any other nonzero value → `Err(WolfHsmError::Ffi { code, func })`
    ///
    /// `func` is the C function name, included in `Ffi` errors for diagnostics.
    #[inline]
    pub fn check(rc: i32, func: &'static str) -> Result<(), WolfHsmError> {
        if rc == 0 {
            Ok(())
        } else if (WH_ERROR_MIN..=WH_ERROR_MAX).contains(&rc) {
            Err(WolfHsmError::Wh { code: rc })
        } else {
            Err(WolfHsmError::Ffi { code: rc, func })
        }
    }
}

impl fmt::Display for WolfHsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WolfHsmError::Wh { code } => write!(f, "wolfHSM error {code}"),
            WolfHsmError::Ffi { code, func } => {
                write!(f, "{func} failed: wolfSSL FFI error {code}")
            }
            WolfHsmError::AlreadyRegistered => {
                write!(
                    f,
                    "wolfHSM CryptoCb already registered; drop the existing guard first"
                )
            }
            WolfHsmError::BadArgs { msg } => write!(f, "invalid argument: {msg}"),
            WolfHsmError::DataLost { id } => {
                write!(
                    f,
                    "wolfHSM NVM object {id} deleted but add failed; original data lost"
                )
            }
            WolfHsmError::ProtocolError { msg } => {
                write!(f, "wolfHSM protocol error: {msg}")
            }
            WolfHsmError::InvalidSignature => {
                write!(f, "wolfHSM: signature or MAC verification failed")
            }
        }
    }
}

impl core::error::Error for WolfHsmError {}
