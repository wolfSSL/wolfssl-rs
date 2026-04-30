use core::fmt;

/// A raw TPM return code as returned by wolfTPM2_* functions.
///
/// A value of `0` means success. Any other value is an error. The lower bits
/// encode the error class and specific error; use [`tpm_rc_name`] to map a
/// value to its symbolic name.
///
/// # Error spaces
///
/// wolfTPM uses two distinct error spaces:
/// - **TPM2-spec codes** (`0x0000_0001`–`0x0000_0FFF`): defined by the TPM2
///   specification (TCG TPM2 Part 2 §6.6).
/// - **wolfTPM internal codes**: negative `i32` values cast to `u32` (e.g.
///   `BAD_FUNC_ARG = -173` → `0xFFFF_FF53`). These are not TPM spec codes;
///   they originate inside the wolfTPM library itself.
///
/// [`fmt::Display`] formats both spaces correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TpmRc(u32);

impl TpmRc {
    /// Returns `true` if this code represents success (`TPM_RC_SUCCESS == 0`).
    #[inline]
    pub fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Returns the raw u32 value of this return code.
    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Construct a `TpmRc` from a raw u32 value.
    ///
    /// For use only within this crate; external callers receive `TpmRc` via
    /// [`Error::check`] or from `Error::Tpm { rc }` pattern matches.
    #[inline]
    pub(crate) fn from_raw(rc: u32) -> Self {
        TpmRc(rc)
    }
}

impl fmt::Display for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = wolftpm_sys::tpm_rc::tpm_rc_name(self.0) {
            write!(f, "0x{:08x} ({name})", self.0)
        } else {
            write!(f, "0x{:08x}", self.0)
        }
    }
}

/// Error type for wolfTPM operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// A wolfTPM / TPM2 error code (nonzero return from a wolfTPM2_* function).
    Tpm {
        /// The raw TPM return code.
        rc: TpmRc,
    },
    /// A caller-supplied argument failed validation before any FFI call.
    ///
    /// `msg` is a `'static` description of what was invalid.  Used for
    /// programmer errors whose values are not meaningful to inspect at runtime
    /// (e.g. a null byte in a host string).  For errors where the caller
    /// needs the actual value, use the structured variants below.
    InvalidArg(&'static str),
    /// A PCR index was outside the valid range (0–23).
    InvalidPcrIndex(u8),
    /// A hash buffer was not exactly 32 bytes (required for SHA-256 operations).
    InvalidHashLen {
        /// The actual length supplied by the caller.
        got: usize,
    },
    /// An ECDSA signature was structurally valid but did not verify against the
    /// supplied key and hash.  This is a normal cryptographic outcome, not an
    /// error in the TPM or the library.
    SignatureInvalid,
    /// The buffer supplied to receive a response was too small.
    BufferTooSmall,
    /// The TPM returned a response that violates protocol expectations.
    UnexpectedResponse,
}

impl Error {
    /// Map a wolfTPM C return code to a `Result`.
    ///
    /// - `0` → `Ok(())`
    /// - Any other value → `Err(Error::Tpm { rc: TpmRc(rc as u32) })`
    ///
    /// Negative wolfTPM internal codes (e.g. `BAD_FUNC_ARG = -173`) are
    /// preserved via the bitwise-identical `u32` cast and will display as
    /// `wolfTPM internal` codes rather than TPM2-spec codes.
    #[inline]
    pub fn check(rc: i32) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::Tpm {
                // Negative wolfTPM internal codes become values >= 0x8000_0000.
                rc: TpmRc(rc as u32),
            })
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tpm { rc } => {
                // Values >= 0x8000_0000 are negative i32 wolfTPM internal codes,
                // not TPM2-spec codes.  Label them differently so callers do not
                // mistake them for TPM2 Part 2 §6.6 return codes.
                if rc.0 >= 0x8000_0000 {
                    write!(f, "wolfTPM internal error {rc}")
                } else {
                    write!(f, "TPM error {rc}")
                }
            }
            Error::InvalidArg(msg) => write!(f, "invalid argument: {msg}"),
            Error::InvalidPcrIndex(n) => {
                write!(f, "PCR index {n} is out of range (valid range: 0–23)")
            }
            Error::InvalidHashLen { got } => {
                write!(f, "hash must be exactly 32 bytes, got {got}")
            }
            Error::SignatureInvalid => write!(f, "signature verification failed"),
            Error::BufferTooSmall => write!(f, "response buffer too small"),
            Error::UnexpectedResponse => write!(f, "TPM returned unexpected response"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_success() {
        assert_eq!(Error::check(0), Ok(()));
    }

    #[test]
    fn test_check_failure() {
        assert_eq!(
            Error::check(1),
            Err(Error::Tpm { rc: TpmRc(1) })
        );
    }

    #[test]
    fn test_display_known() {
        // TPM_RC_FAILURE == 257 == 0x00000101
        let e = Error::Tpm { rc: TpmRc(257) };
        let s = e.to_string();
        assert!(
            s.contains("TPM_RC_FAILURE"),
            "expected symbolic name in display, got: {s}"
        );
    }

    #[test]
    fn test_display_unknown() {
        let e = Error::Tpm {
            rc: TpmRc(0xdeadbeef),
        };
        let s = e.to_string();
        assert!(
            s.contains("0xdeadbeef"),
            "expected hex code in display, got: {s}"
        );
    }

    #[test]
    fn test_display_structured_variants() {
        let e = Error::InvalidPcrIndex(25);
        assert!(
            e.to_string().contains("25"),
            "InvalidPcrIndex display missing index: {e}"
        );

        let e = Error::InvalidHashLen { got: 16 };
        assert!(
            e.to_string().contains("16"),
            "InvalidHashLen display missing length: {e}"
        );

        assert!(!Error::SignatureInvalid.to_string().is_empty());
    }
}
