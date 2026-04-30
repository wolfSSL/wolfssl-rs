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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmRc(u32);

impl TpmRc {
    /// Returns `true` if this code represents success (`TPM_RC_SUCCESS == 0`).
    #[inline]
    pub fn is_success(&self) -> bool {
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
        if let Some(name) = tpm_rc_name(self.0) {
            write!(f, "0x{:08x} ({name})", self.0)
        } else {
            write!(f, "0x{:08x}", self.0)
        }
    }
}

/// Error type for wolfTPM operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A wolfTPM / TPM2 error code (nonzero return from a wolfTPM2_* function).
    Tpm {
        /// The raw TPM return code.
        rc: TpmRc,
    },
    /// A caller-supplied argument failed validation before any FFI call.
    ///
    /// `msg` is a `'static` description of what was invalid.
    InvalidArg(&'static str),
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

/// Return the symbolic name for a `TPM_RC_*` code, or `None` if unknown.
///
/// Covers:
/// - TPM2-spec codes from `wolftpm/tpm_types.h` (`TPM_RC_T` enum).
/// - wolfTPM internal codes (negative `i32` cast to `u32`; values >= `0x8000_0000`).
///
/// Pure modifier flags (`TPM_RC_H`, `TPM_RC_P`, `TPM_RC_S`, `TPM_RC_1`–`TPM_RC_F`,
/// `TPM_RC_N_MASK`) and boundary markers (`RC_VER1`, `RC_FMT1`, `RC_WARN`,
/// `RC_MAX_FM0`, `RC_MAX_FMT1`, `RC_MAX_WARN`, `TPM_RC_NOT_USED`) are omitted
/// because they are not returned as standalone error codes.
fn tpm_rc_name(rc: u32) -> Option<&'static str> {
    match rc {
        // Success
        0x0000 => Some("TPM_RC_SUCCESS"),
        // Misc codes below the VER1 range
        0x001e => Some("TPM_RC_BAD_TAG"),
        // VER1 (format-zero) errors  0x0100–0x017f  (RC_VER1 = 0x0100)
        0x0100 => Some("TPM_RC_INITIALIZE"),
        0x0101 => Some("TPM_RC_FAILURE"),
        0x0103 => Some("TPM_RC_SEQUENCE"),
        0x010b => Some("TPM_RC_PRIVATE"),
        0x0119 => Some("TPM_RC_HMAC"),
        0x0120 => Some("TPM_RC_DISABLED"),
        0x0121 => Some("TPM_RC_EXCLUSIVE"),
        0x0124 => Some("TPM_RC_AUTH_TYPE"),
        0x0125 => Some("TPM_RC_AUTH_MISSING"),
        0x0126 => Some("TPM_RC_POLICY"),
        0x0127 => Some("TPM_RC_PCR"),
        0x0128 => Some("TPM_RC_PCR_CHANGED"),
        0x012d => Some("TPM_RC_UPGRADE"),
        0x012e => Some("TPM_RC_TOO_MANY_CONTEXTS"),
        0x012f => Some("TPM_RC_AUTH_UNAVAILABLE"),
        0x0130 => Some("TPM_RC_REBOOT"),
        0x0131 => Some("TPM_RC_UNBALANCED"),
        0x0142 => Some("TPM_RC_COMMAND_SIZE"),
        0x0143 => Some("TPM_RC_COMMAND_CODE"),
        0x0144 => Some("TPM_RC_AUTHSIZE"),
        0x0145 => Some("TPM_RC_AUTH_CONTEXT"),
        0x0146 => Some("TPM_RC_NV_RANGE"),
        0x0147 => Some("TPM_RC_NV_SIZE"),
        0x0148 => Some("TPM_RC_NV_LOCKED"),
        0x0149 => Some("TPM_RC_NV_AUTHORIZATION"),
        0x014a => Some("TPM_RC_NV_UNINITIALIZED"),
        0x014b => Some("TPM_RC_NV_SPACE"),
        0x014c => Some("TPM_RC_NV_DEFINED"),
        0x0150 => Some("TPM_RC_BAD_CONTEXT"),
        0x0151 => Some("TPM_RC_CPHASH"),
        0x0152 => Some("TPM_RC_PARENT"),
        0x0153 => Some("TPM_RC_NEEDS_TEST"),
        0x0154 => Some("TPM_RC_NO_RESULT"),
        0x0155 => Some("TPM_RC_SENSITIVE"),
        // FMT1 (format-one) errors  0x0081–0x00bf  (RC_FMT1 = 0x0080)
        0x0081 => Some("TPM_RC_ASYMMETRIC"),
        0x0082 => Some("TPM_RC_ATTRIBUTES"),
        0x0083 => Some("TPM_RC_HASH"),
        0x0084 => Some("TPM_RC_VALUE"),
        0x0085 => Some("TPM_RC_HIERARCHY"),
        0x0087 => Some("TPM_RC_KEY_SIZE"),
        0x0088 => Some("TPM_RC_MGF"),
        0x0089 => Some("TPM_RC_MODE"),
        0x008a => Some("TPM_RC_TYPE"),
        0x008b => Some("TPM_RC_HANDLE"),
        0x008c => Some("TPM_RC_KDF"),
        0x008d => Some("TPM_RC_RANGE"),
        0x008e => Some("TPM_RC_AUTH_FAIL"),
        0x008f => Some("TPM_RC_NONCE"),
        0x0090 => Some("TPM_RC_PP"),
        0x0092 => Some("TPM_RC_SCHEME"),
        0x0095 => Some("TPM_RC_SIZE"),
        0x0096 => Some("TPM_RC_SYMMETRIC"),
        0x0097 => Some("TPM_RC_TAG"),
        0x0098 => Some("TPM_RC_SELECTOR"),
        0x009a => Some("TPM_RC_INSUFFICIENT"),
        0x009b => Some("TPM_RC_SIGNATURE"),
        0x009c => Some("TPM_RC_KEY"),
        0x009d => Some("TPM_RC_POLICY_FAIL"),
        0x009f => Some("TPM_RC_INTEGRITY"),
        0x00a0 => Some("TPM_RC_TICKET"),
        0x00a1 => Some("TPM_RC_RESERVED_BITS"),
        0x00a2 => Some("TPM_RC_BAD_AUTH"),
        0x00a3 => Some("TPM_RC_EXPIRED"),
        0x00a4 => Some("TPM_RC_POLICY_CC"),
        0x00a5 => Some("TPM_RC_BINDING"),
        0x00a6 => Some("TPM_RC_CURVE"),
        0x00a7 => Some("TPM_RC_ECC_POINT"),
        0x00aa => Some("TPM_RC_PARMS"),
        // WARN errors  0x0901–0x093f  (RC_WARN = 0x0900)
        0x0901 => Some("TPM_RC_CONTEXT_GAP"),
        0x0902 => Some("TPM_RC_OBJECT_MEMORY"),
        0x0903 => Some("TPM_RC_SESSION_MEMORY"),
        0x0904 => Some("TPM_RC_MEMORY"),
        0x0905 => Some("TPM_RC_SESSION_HANDLES"),
        0x0906 => Some("TPM_RC_OBJECT_HANDLES"),
        0x0907 => Some("TPM_RC_LOCALITY"),
        0x0908 => Some("TPM_RC_YIELDED"),
        0x0909 => Some("TPM_RC_CANCELED"),
        0x090a => Some("TPM_RC_TESTING"),
        0x0910 => Some("TPM_RC_REFERENCE_H0"),
        0x0911 => Some("TPM_RC_REFERENCE_H1"),
        0x0912 => Some("TPM_RC_REFERENCE_H2"),
        0x0913 => Some("TPM_RC_REFERENCE_H3"),
        0x0914 => Some("TPM_RC_REFERENCE_H4"),
        0x0915 => Some("TPM_RC_REFERENCE_H5"),
        0x0916 => Some("TPM_RC_REFERENCE_H6"),
        0x0918 => Some("TPM_RC_REFERENCE_S0"),
        0x0919 => Some("TPM_RC_REFERENCE_S1"),
        0x091a => Some("TPM_RC_REFERENCE_S2"),
        0x091b => Some("TPM_RC_REFERENCE_S3"),
        0x091c => Some("TPM_RC_REFERENCE_S4"),
        0x091d => Some("TPM_RC_REFERENCE_S5"),
        0x091e => Some("TPM_RC_REFERENCE_S6"),
        0x0920 => Some("TPM_RC_NV_RATE"),
        0x0921 => Some("TPM_RC_LOCKOUT"),
        0x0922 => Some("TPM_RC_RETRY"),
        0x0923 => Some("TPM_RC_NV_UNAVAILABLE"),
        // wolfTPM-internal codes: negative i32 values cast to u32.
        // These are NOT TPM2-spec codes; they originate in the wolfTPM library
        // (wolftpm/src/tpm2.c and wolfssl error.h).  The decimal values are the
        // negated wolfTPM/wolfSSL error constants.
        0xffffff9c => Some("wolfTPM:TIMEOUT(-100)"),          // WC_TIMEOUT_E
        0xffffff53 => Some("wolfTPM:BAD_FUNC_ARG(-173)"),     // BAD_FUNC_ARG
        0xffffff57 => Some("wolfTPM:BAD_STATE_E(-169)"),      // BAD_STATE_E
        0xffffff8d => Some("wolfTPM:BUFFER_E(-115)"),         // BUFFER_E
        0xffffffa2 => Some("wolfTPM:LENGTH_ONLY_E(-94)"),     // LENGTH_ONLY_E
        0xffffff4a => Some("wolfTPM:NOT_COMPILED_IN(-182)"),  // NOT_COMPILED_IN
        _ => None,
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
}
