use core::fmt;

/// Error type for wolfCrypt operations.
///
/// Distinguishes between errors originating from the wolfCrypt C library
/// (which carry a negative integer error code) and errors detected on the
/// Rust side before calling into C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WolfCryptError {
    /// A wolfCrypt FFI call returned a non-zero error code.
    ///
    /// `func` is the C function name (e.g. `"wc_AesGcmEncrypt"`) so
    /// error messages identify the failing call without grepping headers.
    Ffi {
        /// The wolfCrypt error code (typically negative).
        code: i32,
        /// Name of the C function that returned the error.
        func: &'static str,
    },
    /// A wolfCrypt allocation or initialization function returned NULL.
    AllocFailed,
    /// Caller-supplied input has the wrong length or format.
    InvalidInput,
    /// Signature verification completed without error but the signature did
    /// not verify (bad signature, wrong key, or tampered data).
    SigInvalid,
}

impl WolfCryptError {
    /// Alias for [`WolfCryptError::AllocFailed`].
    pub const ALLOC_FAILED: Self = Self::AllocFailed;
    /// Alias for [`WolfCryptError::InvalidInput`].
    pub const INVALID_INPUT: Self = Self::InvalidInput;
}

impl fmt::Display for WolfCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AllocFailed => write!(f, "wolfCrypt allocation failed"),
            Self::InvalidInput => write!(f, "invalid input length or format"),
            Self::SigInvalid => write!(f, "signature verification failed"),
            Self::Ffi { code, func } => write!(f, "{func} failed: wolfCrypt error {code}"),
        }
    }
}

/// Check a wolfCrypt return code; 0 = success, negative = error.
///
/// `func` is the C function name, included in the error for diagnostics.
#[inline]
pub(crate) fn check(rc: i32, func: &'static str) -> Result<(), WolfCryptError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(WolfCryptError::Ffi { code: rc, func })
    }
}

/// Cast a `usize` length to `u32` for wolfCrypt FFI calls.
///
/// # Panics
///
/// Panics if the value exceeds `u32::MAX` (~4 GB).
/// See the "Buffer size limit" section in the crate-level docs.
#[inline(always)]
pub(crate) fn len_as_u32(n: usize) -> u32 {
    assert!(
        n <= u32::MAX as usize,
        "buffer length {n} exceeds u32::MAX; wolfCrypt FFI would truncate",
    );
    n as u32
}

/// Cast a `usize` length to `c_int` for wolfCrypt FFI calls.
///
/// # Panics
///
/// Panics if the value exceeds `c_int::MAX` (~2 GB).
/// See the "Buffer size limit" section in the crate-level docs.
#[inline(always)]
pub(crate) fn len_as_c_int(n: usize) -> core::ffi::c_int {
    assert!(
        n <= core::ffi::c_int::MAX as usize,
        "buffer length {n} exceeds c_int::MAX; wolfCrypt FFI would truncate",
    );
    n as core::ffi::c_int
}
