/// Return the symbolic name for a `TPM_RC_*` code, or `None` if unknown.
///
/// Covers:
/// - TPM2-spec codes from `wolftpm/tpm_types.h` (`TPM_RC_T` enum).
/// - wolfTPM internal codes (negative `i32` cast to `u32`; values >= `0x8000_0000`).
/// - FMT1-qualified codes: if the exact code is not found and it looks like a
///   FMT1 code (bit 7 set, bits 15:12 clear), the modifier bits are stripped
///   (P-flag bit 6, subject-number bits 11:8) and the base code is looked up.
///   For example, `TPM_RC_SIGNATURE | param_1` (`0x01DB`) resolves to
///   `"TPM_RC_SIGNATURE"`.
///
/// Pure modifier flags (`TPM_RC_H`, `TPM_RC_P`, `TPM_RC_S`, `TPM_RC_1`–`TPM_RC_F`,
/// `TPM_RC_N_MASK`) and boundary markers (`RC_VER1`, `RC_FMT1`, `RC_WARN`,
/// `RC_MAX_FM0`, `RC_MAX_FMT1`, `RC_MAX_WARN`, `TPM_RC_NOT_USED`) are omitted
/// because they are not returned as standalone error codes.
pub fn tpm_rc_name(rc: u32) -> Option<&'static str> {
    tpm_rc_name_exact(rc).or_else(|| {
        let base = fmt1_base(rc);
        if base != rc { tpm_rc_name_exact(base) } else { None }
    })
}

/// Strip FMT1 modifier bits from `rc` if it is a FMT1 code; otherwise return `rc` unchanged.
///
/// FMT1 codes (TPM2 Part 2 §6.6.3) have bit 7 set and bits 15:12 clear.
/// The modifier bits are P-flag (bit 6 = 0x0040) and subject number (bits 11:8 = 0x0F00).
/// wolfTPM internal codes have values >= 0x8000_0000, so bits 15:12 are always set
/// and they are never mis-identified as FMT1.
fn fmt1_base(rc: u32) -> u32 {
    const FMT1_MODIFIER_MASK: u32 = 0x0F40;
    if (rc & 0x80) != 0 && (rc & 0xF000) == 0 {
        rc & !FMT1_MODIFIER_MASK
    } else {
        rc
    }
}

fn tpm_rc_name_exact(rc: u32) -> Option<&'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_codes_resolve() {
        assert_eq!(tpm_rc_name(0x0000), Some("TPM_RC_SUCCESS"));
        assert_eq!(tpm_rc_name(0x009b), Some("TPM_RC_SIGNATURE"));
        assert_eq!(tpm_rc_name(0x0082), Some("TPM_RC_ATTRIBUTES"));
        assert_eq!(tpm_rc_name(0x0101), Some("TPM_RC_FAILURE"));
    }

    #[test]
    fn fmt1_qualified_codes_resolve() {
        // TPM_RC_SIGNATURE (0x009B) | P-flag (0x040) | param_1 (0x100) = 0x01DB
        assert_eq!(tpm_rc_name(0x01db), Some("TPM_RC_SIGNATURE"));
        // TPM_RC_ATTRIBUTES (0x0082) | session_1 (0x200) = 0x0282
        assert_eq!(tpm_rc_name(0x0282), Some("TPM_RC_ATTRIBUTES"));
        // TPM_RC_VALUE (0x0084) | P-flag (0x040) | param_2 (0x200) = 0x02C4
        assert_eq!(tpm_rc_name(0x02c4), Some("TPM_RC_VALUE"));
    }

    #[test]
    fn wolftpm_internal_codes_resolve() {
        assert_eq!(tpm_rc_name(0xffffff53), Some("wolfTPM:BAD_FUNC_ARG(-173)"));
        // Internal codes are not mis-identified as FMT1 (bits 15:12 are set).
        assert_eq!(tpm_rc_name(0xffffff00), None);
    }

    #[test]
    fn unknown_code_returns_none() {
        assert_eq!(tpm_rc_name(0xdeadbeef), None);
    }
}
