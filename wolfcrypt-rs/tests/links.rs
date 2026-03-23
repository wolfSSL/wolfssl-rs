// tests/links.rs
//
// Validates that wolfcrypt-rs correctly links to wolfSSL and that
// the core cryptographic primitives produce correct output.

/// SHA-256("abc") must match NIST FIPS 180-4, Appendix B.1.
/// Expected digest: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
#[test]
fn sha256_round_trip() {
    let input = b"abc";
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];

    let mut output = [0u8; 32];
    unsafe {
        let ret = wolfcrypt_rs::SHA256(input.as_ptr(), input.len(), output.as_mut_ptr());
        assert!(!ret.is_null(), "SHA256 returned null");
    }
    assert_eq!(output, expected, "SHA-256 digest does not match NIST FIPS 180-4 B.1");
}

/// Verify ML-KEM NID constants are in sync between Rust (lib.rs) and C (compat_shim.c).
#[test]
fn mlkem_nid_constants_sync() {
    unsafe {
        assert_eq!(wolfcrypt_rs::NID_MLKEM512, wolfcrypt_rs::get_NID_MLKEM512(),
            "NID_MLKEM512 mismatch between Rust and C");
        assert_eq!(wolfcrypt_rs::NID_MLKEM768, wolfcrypt_rs::get_NID_MLKEM768(),
            "NID_MLKEM768 mismatch between Rust and C");
        assert_eq!(wolfcrypt_rs::NID_MLKEM1024, wolfcrypt_rs::get_NID_MLKEM1024(),
            "NID_MLKEM1024 mismatch between Rust and C");
        assert_eq!(wolfcrypt_rs::EVP_PKEY_KEM, wolfcrypt_rs::get_EVP_PKEY_KEM_TYPE(),
            "EVP_PKEY_KEM type mismatch between Rust and C");
    }
}

/// RAND_bytes output must not be all zeros (probabilistic check).
/// The probability of 32 random bytes being all zero is 2^{-256}.
#[test]
fn rng_generates_nonzero() {
    let mut buf = [0u8; 32];
    let ret = unsafe { wolfcrypt_rs::RAND_bytes(buf.as_mut_ptr(), 32) };
    assert_eq!(ret, 1, "RAND_bytes failed");
    assert!(buf.iter().any(|&b| b != 0), "RAND_bytes returned all zeros");
}
