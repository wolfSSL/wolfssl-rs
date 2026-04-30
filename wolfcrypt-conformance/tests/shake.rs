//! SHAKE128 and SHAKE256 conformance tests.
//!
//! Test vectors from NIST CAVP (SHAVS):
//!   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

// SHAKE is only available when wolfSSL was compiled with WOLFSSL_SHAKE*.
// The cfg flags are emitted by wolfcrypt-sys's build.rs.

#[cfg(wolfssl_shake256)]
mod shake256_tests {
    use hex_literal::hex;
    use wolfcrypt::shake::Shake256;

    // NIST CAVP ShortMsg vector: Len = 0, output 256 bits (32 bytes)
    #[test]
    fn empty_input_32_bytes() {
        let mut xof = Shake256::new().unwrap();
        xof.update(b"").unwrap();
        let mut out = [0u8; 32];
        xof.finalize(&mut out).unwrap();
        // SHAKE256("") first 32 bytes — NIST CAVP
        assert_eq!(
            out,
            hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
        );
    }

    // Same input, but request 64 bytes of output (XOF property)
    #[test]
    fn empty_input_64_bytes() {
        let mut xof = Shake256::new().unwrap();
        xof.update(b"").unwrap();
        let mut out = [0u8; 64];
        xof.finalize(&mut out).unwrap();
        assert_eq!(
            out,
            hex!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            ),
        );
    }

    // NIST CAVP ShortMsg: "abc" (3 bytes)
    #[test]
    fn abc_32_bytes() {
        let mut xof = Shake256::new().unwrap();
        xof.update(b"abc").unwrap();
        let mut out = [0u8; 32];
        xof.finalize(&mut out).unwrap();
        assert_eq!(
            out,
            hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
        );
    }

    // Incremental update produces same result as single-shot
    #[test]
    fn incremental_matches_oneshot() {
        // Single-shot
        let mut xof1 = Shake256::new().unwrap();
        xof1.update(b"hello world").unwrap();
        let mut out1 = [0u8; 64];
        xof1.finalize(&mut out1).unwrap();

        // Incremental
        let mut xof2 = Shake256::new().unwrap();
        xof2.update(b"hello").unwrap();
        xof2.update(b" ").unwrap();
        xof2.update(b"world").unwrap();
        let mut out2 = [0u8; 64];
        xof2.finalize(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    // Block-level squeeze: output must be a multiple of BLOCK_SIZE
    #[test]
    fn squeeze_blocks_produces_output() {
        let mut xof = Shake256::new().unwrap();
        xof.absorb(b"test data").unwrap();
        let mut out = [0u8; Shake256::BLOCK_SIZE * 2];
        xof.squeeze_blocks(&mut out).unwrap();
        // Output should not be all zeros (statistical check)
        assert!(
            out.iter().any(|&b| b != 0),
            "squeeze output must not be all zeros"
        );
    }

    // squeeze_blocks rejects non-block-aligned lengths
    #[test]
    fn squeeze_blocks_rejects_unaligned() {
        let mut xof = Shake256::new().unwrap();
        xof.absorb(b"test").unwrap();
        let mut out = [0u8; Shake256::BLOCK_SIZE + 1];
        assert!(xof.squeeze_blocks(&mut out).is_err());
    }

    // Variable output length: 1 byte
    #[test]
    fn single_byte_output() {
        let mut xof = Shake256::new().unwrap();
        xof.update(b"").unwrap();
        let mut out = [0u8; 1];
        xof.finalize(&mut out).unwrap();
        // First byte of SHAKE256("")
        assert_eq!(out[0], 0x46);
    }
}

#[cfg(wolfssl_shake128)]
mod shake128_tests {
    use hex_literal::hex;
    use wolfcrypt::shake::Shake128;

    // NIST CAVP: SHAKE128("") first 32 bytes
    #[test]
    fn empty_input_32_bytes() {
        let mut xof = Shake128::new().unwrap();
        xof.update(b"").unwrap();
        let mut out = [0u8; 32];
        xof.finalize(&mut out).unwrap();
        assert_eq!(
            out,
            hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
        );
    }

    // Incremental matches one-shot
    #[test]
    fn incremental_matches_oneshot() {
        let msg = b"The quick brown fox jumps over the lazy dog";

        let mut xof1 = Shake128::new().unwrap();
        xof1.update(msg).unwrap();
        let mut out1 = [0u8; 48];
        xof1.finalize(&mut out1).unwrap();

        let mut xof2 = Shake128::new().unwrap();
        for byte in msg.iter() {
            xof2.update(core::slice::from_ref(byte)).unwrap();
        }
        let mut out2 = [0u8; 48];
        xof2.finalize(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    // Block-level squeeze
    #[test]
    fn squeeze_blocks() {
        let mut xof = Shake128::new().unwrap();
        xof.absorb(b"data").unwrap();
        let mut out = [0u8; Shake128::BLOCK_SIZE * 3];
        xof.squeeze_blocks(&mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }
}
