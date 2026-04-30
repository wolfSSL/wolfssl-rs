// tests/aead_shim_tests.rs
//
// Validates the EVP_AEAD shim layer using NIST test vectors.

use std::mem::MaybeUninit;

/// AES-128-GCM encryption using NIST SP 800-38D, Appendix B, Test Case 2.
///
/// Key:   00000000000000000000000000000000 (16 bytes of zero)
/// IV:    000000000000000000000000 (12 bytes of zero)
/// PT:    00000000000000000000000000000000 (16 bytes of zero)
/// AAD:   (empty)
/// CT:    0388dace60b6a392f328c2b971b2fe78 (16 bytes)
/// Tag:   ab6e47d42cec13bdf53a67b21257bddf (16 bytes)
#[test]
fn aes_128_gcm_nist_tc2_encrypt() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 16];

    let expected_ct: [u8; 16] = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    let expected_tag: [u8; 16] = [
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd,
        0xdf,
    ];

    unsafe {
        let mut ctx = MaybeUninit::<wolfcrypt_rs::EVP_AEAD_CTX>::uninit();
        wolfcrypt_rs::EVP_AEAD_CTX_zero(ctx.as_mut_ptr());

        let aead = wolfcrypt_rs::EVP_aead_aes_128_gcm();
        assert!(!aead.is_null());

        let ret = wolfcrypt_rs::EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            key.len(),
            16, // tag length
            std::ptr::null_mut(),
        );
        assert_eq!(ret, 1, "EVP_AEAD_CTX_init failed");

        // Output buffer: ciphertext (16) + tag (16) = 32 bytes
        let mut out = [0u8; 32];
        let mut out_len: usize = 0;

        let ret = wolfcrypt_rs::EVP_AEAD_CTX_seal(
            ctx.as_ptr(),
            out.as_mut_ptr(),
            &mut out_len,
            out.len(),
            nonce.as_ptr(),
            nonce.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            std::ptr::null(), // no AAD
            0,
        );
        assert_eq!(ret, 1, "EVP_AEAD_CTX_seal failed");
        assert_eq!(out_len, 32, "unexpected output length");

        assert_eq!(
            &out[..16],
            &expected_ct,
            "AES-128-GCM ciphertext does not match NIST SP 800-38D TC2"
        );
        assert_eq!(
            &out[16..32],
            &expected_tag,
            "AES-128-GCM tag does not match NIST SP 800-38D TC2"
        );
    }
}

/// AES-128-GCM round-trip: encrypt then decrypt must recover plaintext.
/// Uses the same NIST SP 800-38D Test Case 2 parameters.
#[test]
fn aes_128_gcm_nist_tc2_decrypt() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 16];

    unsafe {
        let mut ctx = MaybeUninit::<wolfcrypt_rs::EVP_AEAD_CTX>::uninit();
        wolfcrypt_rs::EVP_AEAD_CTX_zero(ctx.as_mut_ptr());

        let aead = wolfcrypt_rs::EVP_aead_aes_128_gcm();
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            key.len(),
            16,
            std::ptr::null_mut(),
        );
        assert_eq!(ret, 1);

        // Seal
        let mut sealed = [0u8; 32];
        let mut sealed_len: usize = 0;
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_seal(
            ctx.as_ptr(),
            sealed.as_mut_ptr(),
            &mut sealed_len,
            sealed.len(),
            nonce.as_ptr(),
            nonce.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            std::ptr::null(),
            0,
        );
        assert_eq!(ret, 1);

        // Open
        let mut recovered = [0xFFu8; 16];
        let mut recovered_len: usize = 0;
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_open(
            ctx.as_ptr(),
            recovered.as_mut_ptr(),
            &mut recovered_len,
            recovered.len(),
            nonce.as_ptr(),
            nonce.len(),
            sealed.as_ptr(),
            sealed_len,
            std::ptr::null(),
            0,
        );
        assert_eq!(ret, 1, "EVP_AEAD_CTX_open failed");
        assert_eq!(recovered_len, 16);
        assert_eq!(&recovered, &plaintext, "round-trip decryption mismatch");
    }
}

/// Corrupted tag must cause decryption to fail.
/// This confirms authentication is properly enforced.
#[test]
fn aes_gcm_rejects_wrong_tag() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = b"Hello, wolfSSL!X"; // 16 bytes

    unsafe {
        let mut ctx = MaybeUninit::<wolfcrypt_rs::EVP_AEAD_CTX>::uninit();
        wolfcrypt_rs::EVP_AEAD_CTX_zero(ctx.as_mut_ptr());

        let aead = wolfcrypt_rs::EVP_aead_aes_128_gcm();
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            key.len(),
            16,
            std::ptr::null_mut(),
        );
        assert_eq!(ret, 1);

        // Seal
        let mut sealed = [0u8; 32];
        let mut sealed_len: usize = 0;
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_seal(
            ctx.as_ptr(),
            sealed.as_mut_ptr(),
            &mut sealed_len,
            sealed.len(),
            nonce.as_ptr(),
            nonce.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            std::ptr::null(),
            0,
        );
        assert_eq!(ret, 1);

        // Corrupt one byte of the tag (last byte)
        sealed[sealed_len - 1] ^= 0xFF;

        // Open should fail
        let mut recovered = [0u8; 16];
        let mut recovered_len: usize = 0;
        let ret = wolfcrypt_rs::EVP_AEAD_CTX_open(
            ctx.as_ptr(),
            recovered.as_mut_ptr(),
            &mut recovered_len,
            recovered.len(),
            nonce.as_ptr(),
            nonce.len(),
            sealed.as_ptr(),
            sealed_len,
            std::ptr::null(),
            0,
        );
        assert_eq!(ret, 0, "decryption should fail with corrupted tag");
    }
}
