use core::fmt;

/// Error type for wolfHSM operations.
///
/// Distinguishes between errors originating from the wolfHSM C library
/// (WH_ERROR_* range -2000 to -2302) and errors from lower-level
/// wolfSSL/wolfCrypt FFI calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WolfHsmError {
    /// A wolfHSM error code (WH_ERROR_* range -2000 to -2302).
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
}

impl WolfHsmError {
    /// Map a wolfHSM C return code to a `Result`.
    ///
    /// - `0` → `Ok(())`
    /// - WH_ERROR_* range (`-2302..=-2000`) → `Err(WolfHsmError::Wh { code })`
    /// - Any other nonzero value → `Err(WolfHsmError::Ffi { code, func })`
    ///
    /// `func` is the C function name, included in `Ffi` errors for diagnostics.
    #[inline]
    pub fn check(rc: i32, func: &'static str) -> Result<(), WolfHsmError> {
        if rc == 0 {
            Ok(())
        } else if (-2302..=-2000).contains(&rc) {
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
            WolfHsmError::Ffi { code, func } => write!(f, "{func} failed: wolfSSL FFI error {code}"),
        }
    }
}

impl core::error::Error for WolfHsmError {}
