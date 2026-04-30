//! AES-GCM streaming API tests using NIST GCM test vectors.
//!
//! Test Case 3 from "The Galois/Counter Mode of Operation (GCM)" —
//! McGrew & Viega, NIST submission (AES-128, 60-byte plaintext, no AAD).

#![cfg(all(feature = "cipher", wolfssl_aes_gcm_stream))]

use hex_literal::hex;
use wolfcrypt::cipher::{AesGcmDecStream, AesGcmEncStream};

// NIST GCM Test Case 3 (AES-128)
const KEY: [u8; 16] = hex!("feffe9928665731c6d6a8f9467308308");
const IV: [u8; 12] = hex!("cafebabefacedbaddecaf888");
const PLAINTEXT: [u8; 64] = hex!(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255"
);
const CIPHERTEXT: [u8; 64] = hex!(
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091473f5985"
);
const TAG: [u8; 16] = hex!("4d5c2af327cd64a62cf35abd2ba6fab4");

/// Encrypt with streaming API, splitting plaintext into two chunks.
/// Verify ciphertext and tag match the NIST vector exactly.
#[test]
fn streaming_encrypt_matches_nist_vector() {
    let mut enc = AesGcmEncStream::new(&KEY, &IV).expect("encrypt init");

    // Split at byte 32 (two 32-byte chunks).
    let split = 32;
    let mut ct = [0u8; 64];
    enc.update(&PLAINTEXT[..split], &mut ct[..split])
        .expect("update chunk 1");
    enc.update(&PLAINTEXT[split..], &mut ct[split..])
        .expect("update chunk 2");

    let mut tag = [0u8; 16];
    enc.finalize(&mut tag).expect("finalize");

    assert_eq!(ct, CIPHERTEXT, "ciphertext mismatch");
    assert_eq!(tag, TAG, "tag mismatch");
}

/// Decrypt with streaming API, splitting ciphertext into two chunks.
/// Verify plaintext matches the NIST vector exactly.
#[test]
fn streaming_decrypt_matches_nist_vector() {
    let mut dec = AesGcmDecStream::new(&KEY, &IV).expect("decrypt init");

    let split = 32;
    let mut pt = [0u8; 64];
    dec.update(&CIPHERTEXT[..split], &mut pt[..split])
        .expect("update chunk 1");
    dec.update(&CIPHERTEXT[split..], &mut pt[split..])
        .expect("update chunk 2");

    dec.finalize(&TAG).expect("finalize (tag verify)");

    assert_eq!(pt, PLAINTEXT, "plaintext mismatch");
}

/// Verify that a wrong tag is rejected during decryption.
#[test]
fn wrong_tag_rejected() {
    let mut dec = AesGcmDecStream::new(&KEY, &IV).expect("decrypt init");

    let mut pt = [0u8; 64];
    dec.update(&CIPHERTEXT, &mut pt).expect("update");

    let mut bad_tag = TAG;
    bad_tag[0] ^= 0xff; // flip one byte

    let result = dec.finalize(&bad_tag);
    assert!(
        result.is_err(),
        "expected authentication failure with wrong tag"
    );
}

/// Verify that AAD affects the authentication tag.
///
/// Encrypt with AAD, then attempt to decrypt without AAD — tag
/// verification must fail.
#[test]
fn aad_affects_tag() {
    let aad = b"some additional data";

    // Encrypt with AAD.
    let mut enc = AesGcmEncStream::new(&KEY, &IV).expect("encrypt init");
    enc.update_aad(aad).expect("aad");

    let mut ct = [0u8; 64];
    enc.update(&PLAINTEXT, &mut ct).expect("update");

    let mut tag_with_aad = [0u8; 16];
    enc.finalize(&mut tag_with_aad).expect("finalize");

    // Decrypt WITHOUT AAD — tag should not verify.
    let mut dec = AesGcmDecStream::new(&KEY, &IV).expect("decrypt init");
    let mut pt = [0u8; 64];
    dec.update(&ct, &mut pt).expect("update");

    let result = dec.finalize(&tag_with_aad);
    assert!(
        result.is_err(),
        "expected authentication failure when AAD is missing"
    );
}
