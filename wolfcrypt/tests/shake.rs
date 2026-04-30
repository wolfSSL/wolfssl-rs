//! SHAKE128 and SHAKE256 XOF tests with NIST FIPS 202 known-answer vectors.
//!
//! Test vectors sourced from NIST FIPS 202 (SHA-3 Standard), Section A.
//! Specifically:
//!   - SHAKE128, empty message, 256-bit output (Example A.1 / NIST CAVP)
//!   - SHAKE256, empty message, 256-bit output (Example A.2 / NIST CAVP)
//!
//! Reference: <https://csrc.nist.gov/publications/detail/fips/202/final>

#![cfg(all(feature = "shake", wolfssl_shake128))]

use wolfcrypt::shake::Shake128;

/// NIST FIPS 202 — SHAKE128("", 256 bits).
///
/// Expected output (hex):
/// 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
#[test]
fn shake128_empty_nist_vector() {
    let mut xof = Shake128::new().expect("Shake128::new failed");
    let mut out = [0u8; 32];
    xof.finalize(&mut out).expect("finalize failed");

    let expected =
        hex_literal::hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    assert_eq!(out, expected, "SHAKE128 empty-input NIST vector mismatch");
}

/// Incremental update must produce the same result as a single-call update.
///
/// Feeds "Hello, SHAKE!" in two pieces and compares with a one-shot call.
#[test]
fn shake128_incremental_matches_oneshot() {
    // One-shot
    let mut xof1 = Shake128::new().expect("Shake128::new failed");
    xof1.update(b"Hello, SHAKE!").expect("update failed");
    let mut out1 = [0u8; 64];
    xof1.finalize(&mut out1).expect("finalize failed");

    // Incremental (split at an arbitrary point)
    let mut xof2 = Shake128::new().expect("Shake128::new failed");
    xof2.update(b"Hello, ").expect("update failed");
    xof2.update(b"SHAKE!").expect("update failed");
    let mut out2 = [0u8; 64];
    xof2.finalize(&mut out2).expect("finalize failed");

    assert_eq!(out1, out2, "incremental update should match one-shot");
}

/// SHAKE128 squeeze_blocks must reject non-block-aligned output lengths.
#[test]
fn shake128_squeeze_blocks_rejects_unaligned() {
    let mut xof = Shake128::new().expect("Shake128::new failed");
    xof.absorb(b"test").expect("absorb failed");
    let mut bad = [0u8; 100]; // 100 is not a multiple of 168
    let result = xof.squeeze_blocks(&mut bad);
    assert!(
        result.is_err(),
        "squeeze_blocks should reject non-block-aligned length"
    );
}

/// SHAKE128 squeeze_blocks with a valid block-aligned buffer.
#[test]
fn shake128_squeeze_blocks_valid() {
    let mut xof = Shake128::new().expect("Shake128::new failed");
    xof.absorb(b"").expect("absorb failed");
    let mut out = [0u8; Shake128::BLOCK_SIZE];
    xof.squeeze_blocks(&mut out).expect("squeeze_blocks failed");
    // Output should be non-trivial (not all zeros after hashing).
    assert!(
        !out.iter().all(|&b| b == 0),
        "squeeze output should not be all zeros"
    );
}

// ---------- SHAKE256 tests ----------

// Only compile SHAKE256 tests if wolfssl_shake256 is also enabled.
#[cfg(wolfssl_shake256)]
mod shake256_tests {
    use wolfcrypt::shake::Shake256;

    /// NIST FIPS 202 — SHAKE256("", 256 bits).
    ///
    /// Expected output (hex):
    /// 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
    #[test]
    fn shake256_empty_nist_vector() {
        let mut xof = Shake256::new().expect("Shake256::new failed");
        let mut out = [0u8; 32];
        xof.finalize(&mut out).expect("finalize failed");

        let expected =
            hex_literal::hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
        assert_eq!(out, expected, "SHAKE256 empty-input NIST vector mismatch");
    }

    /// Incremental update must produce the same result as a single-call update.
    #[test]
    fn shake256_incremental_matches_oneshot() {
        // One-shot
        let mut xof1 = Shake256::new().expect("Shake256::new failed");
        xof1.update(b"Hello, SHAKE!").expect("update failed");
        let mut out1 = [0u8; 64];
        xof1.finalize(&mut out1).expect("finalize failed");

        // Incremental
        let mut xof2 = Shake256::new().expect("Shake256::new failed");
        xof2.update(b"Hello, ").expect("update failed");
        xof2.update(b"SHAKE!").expect("update failed");
        let mut out2 = [0u8; 64];
        xof2.finalize(&mut out2).expect("finalize failed");

        assert_eq!(out1, out2, "incremental update should match one-shot");
    }

    /// SHAKE256 squeeze_blocks must reject non-block-aligned output lengths.
    #[test]
    fn shake256_squeeze_blocks_rejects_unaligned() {
        let mut xof = Shake256::new().expect("Shake256::new failed");
        xof.absorb(b"test").expect("absorb failed");
        let mut bad = [0u8; 100]; // 100 is not a multiple of 136
        let result = xof.squeeze_blocks(&mut bad);
        assert!(
            result.is_err(),
            "squeeze_blocks should reject non-block-aligned length"
        );
    }

    /// SHAKE256 squeeze_blocks with a valid block-aligned buffer.
    #[test]
    fn shake256_squeeze_blocks_valid() {
        let mut xof = Shake256::new().expect("Shake256::new failed");
        xof.absorb(b"").expect("absorb failed");
        let mut out = [0u8; Shake256::BLOCK_SIZE];
        xof.squeeze_blocks(&mut out).expect("squeeze_blocks failed");
        assert!(
            !out.iter().all(|&b| b == 0),
            "squeeze output should not be all zeros"
        );
    }
}
