use core::fmt;

/// A raw TPM return code as returned by wolfTPM2_* functions.
///
/// A value of `0` means success. Any other value is an error. The lower bits
/// encode the error class and specific error; use [`tpm_rc_name`] to map a
/// value to its symbolic name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmRc(pub u32);

impl TpmRc {
    /// Returns `true` if this code represents success (`TPM_RC_SUCCESS == 0`).
    #[inline]
    pub fn is_success(&self) -> bool {
        self.0 == 0
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
    #[inline]
    pub fn check(rc: i32) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::Tpm {
                rc: TpmRc(rc as u32),
            })
        }
    }
}

/// Return the symbolic name for a `TPM_RC_*` code, or `None` if unknown.
///
/// Covers the named constants from `wolftpm/tpm_types.h` (the `TPM_RC_T` enum).
/// Pure modifier flags (`TPM_RC_H`, `TPM_RC_P`, `TPM_RC_S`, `TPM_RC_1`–`TPM_RC_F`,
/// `TPM_RC_N_MASK`) and boundary markers (`RC_VER1`, `RC_FMT1`, `RC_WARN`,
/// `RC_MAX_FM0`, `RC_MAX_FMT1`, `RC_MAX_WARN`, `TPM_RC_NOT_USED`) are omitted
/// because they are not returned as standalone error codes.
fn tpm_rc_name(rc: u32) -> Option<&'static str> {
    match rc {
        // Success
        0 => Some("TPM_RC_SUCCESS"),
        // Misc codes below the VER1 range
        30 => Some("TPM_RC_BAD_TAG"),
        // VER1 (format-zero) errors  0x100–0x17f
        256 => Some("TPM_RC_INITIALIZE"),
        257 => Some("TPM_RC_FAILURE"),
        259 => Some("TPM_RC_SEQUENCE"),
        267 => Some("TPM_RC_PRIVATE"),
        281 => Some("TPM_RC_HMAC"),
        288 => Some("TPM_RC_DISABLED"),
        289 => Some("TPM_RC_EXCLUSIVE"),
        292 => Some("TPM_RC_AUTH_TYPE"),
        293 => Some("TPM_RC_AUTH_MISSING"),
        294 => Some("TPM_RC_POLICY"),
        295 => Some("TPM_RC_PCR"),
        296 => Some("TPM_RC_PCR_CHANGED"),
        301 => Some("TPM_RC_UPGRADE"),
        302 => Some("TPM_RC_TOO_MANY_CONTEXTS"),
        303 => Some("TPM_RC_AUTH_UNAVAILABLE"),
        304 => Some("TPM_RC_REBOOT"),
        305 => Some("TPM_RC_UNBALANCED"),
        322 => Some("TPM_RC_COMMAND_SIZE"),
        323 => Some("TPM_RC_COMMAND_CODE"),
        324 => Some("TPM_RC_AUTHSIZE"),
        325 => Some("TPM_RC_AUTH_CONTEXT"),
        326 => Some("TPM_RC_NV_RANGE"),
        327 => Some("TPM_RC_NV_SIZE"),
        328 => Some("TPM_RC_NV_LOCKED"),
        329 => Some("TPM_RC_NV_AUTHORIZATION"),
        330 => Some("TPM_RC_NV_UNINITIALIZED"),
        331 => Some("TPM_RC_NV_SPACE"),
        332 => Some("TPM_RC_NV_DEFINED"),
        336 => Some("TPM_RC_BAD_CONTEXT"),
        337 => Some("TPM_RC_CPHASH"),
        338 => Some("TPM_RC_PARENT"),
        339 => Some("TPM_RC_NEEDS_TEST"),
        340 => Some("TPM_RC_NO_RESULT"),
        341 => Some("TPM_RC_SENSITIVE"),
        // FMT1 (format-one) errors  0x080–0x0bf
        129 => Some("TPM_RC_ASYMMETRIC"),
        130 => Some("TPM_RC_ATTRIBUTES"),
        131 => Some("TPM_RC_HASH"),
        132 => Some("TPM_RC_VALUE"),
        133 => Some("TPM_RC_HIERARCHY"),
        135 => Some("TPM_RC_KEY_SIZE"),
        136 => Some("TPM_RC_MGF"),
        137 => Some("TPM_RC_MODE"),
        138 => Some("TPM_RC_TYPE"),
        139 => Some("TPM_RC_HANDLE"),
        140 => Some("TPM_RC_KDF"),
        141 => Some("TPM_RC_RANGE"),
        142 => Some("TPM_RC_AUTH_FAIL"),
        143 => Some("TPM_RC_NONCE"),
        144 => Some("TPM_RC_PP"),
        146 => Some("TPM_RC_SCHEME"),
        149 => Some("TPM_RC_SIZE"),
        150 => Some("TPM_RC_SYMMETRIC"),
        151 => Some("TPM_RC_TAG"),
        152 => Some("TPM_RC_SELECTOR"),
        154 => Some("TPM_RC_INSUFFICIENT"),
        155 => Some("TPM_RC_SIGNATURE"),
        156 => Some("TPM_RC_KEY"),
        157 => Some("TPM_RC_POLICY_FAIL"),
        159 => Some("TPM_RC_INTEGRITY"),
        160 => Some("TPM_RC_TICKET"),
        161 => Some("TPM_RC_RESERVED_BITS"),
        162 => Some("TPM_RC_BAD_AUTH"),
        163 => Some("TPM_RC_EXPIRED"),
        164 => Some("TPM_RC_POLICY_CC"),
        165 => Some("TPM_RC_BINDING"),
        166 => Some("TPM_RC_CURVE"),
        167 => Some("TPM_RC_ECC_POINT"),
        170 => Some("TPM_RC_PARMS"),
        // WARN errors  0x900–0x93f
        2305 => Some("TPM_RC_CONTEXT_GAP"),
        2306 => Some("TPM_RC_OBJECT_MEMORY"),
        2307 => Some("TPM_RC_SESSION_MEMORY"),
        2308 => Some("TPM_RC_MEMORY"),
        2309 => Some("TPM_RC_SESSION_HANDLES"),
        2310 => Some("TPM_RC_OBJECT_HANDLES"),
        2311 => Some("TPM_RC_LOCALITY"),
        2312 => Some("TPM_RC_YIELDED"),
        2313 => Some("TPM_RC_CANCELED"),
        2314 => Some("TPM_RC_TESTING"),
        2320 => Some("TPM_RC_REFERENCE_H0"),
        2321 => Some("TPM_RC_REFERENCE_H1"),
        2322 => Some("TPM_RC_REFERENCE_H2"),
        2323 => Some("TPM_RC_REFERENCE_H3"),
        2324 => Some("TPM_RC_REFERENCE_H4"),
        2325 => Some("TPM_RC_REFERENCE_H5"),
        2326 => Some("TPM_RC_REFERENCE_H6"),
        2328 => Some("TPM_RC_REFERENCE_S0"),
        2329 => Some("TPM_RC_REFERENCE_S1"),
        2330 => Some("TPM_RC_REFERENCE_S2"),
        2331 => Some("TPM_RC_REFERENCE_S3"),
        2332 => Some("TPM_RC_REFERENCE_S4"),
        2333 => Some("TPM_RC_REFERENCE_S5"),
        2334 => Some("TPM_RC_REFERENCE_S6"),
        2336 => Some("TPM_RC_NV_RATE"),
        2337 => Some("TPM_RC_LOCKOUT"),
        2338 => Some("TPM_RC_RETRY"),
        2339 => Some("TPM_RC_NV_UNAVAILABLE"),
        // wolfTPM-specific: -100i32 cast to u32
        0xffffff9c => Some("TPM_RC_TIMEOUT"),
        _ => None,
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tpm { rc } => {
                if let Some(name) = tpm_rc_name(rc.0) {
                    write!(f, "TPM error 0x{:08x} ({name})", rc.0)
                } else {
                    write!(f, "TPM error 0x{:08x}", rc.0)
                }
            }
            Error::InvalidArg(msg) => write!(f, "invalid argument: {msg}"),
            Error::BufferTooSmall => write!(f, "response buffer too small"),
            Error::UnexpectedResponse => write!(f, "TPM returned unexpected response"),
        }
    }
}

impl core::error::Error for Error {}

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
