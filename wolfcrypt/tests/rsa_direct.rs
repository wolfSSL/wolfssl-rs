//! Tests for RSA direct (no-padding) operations via [`NativeRsaKey`].
//!
//! These tests exercise the `wc_RsaFunction` path, which performs raw
//! modular exponentiation without any padding scheme.

#![cfg(all(feature = "rsa-direct", wolfssl_rsa))]

use wolfcrypt::rsa::{NativeRsaKey, RsaDirectType};
use wolfcrypt::rand::WolfRng;

// ===========================================================================
// Section 1: Generate + round-trip (private-encrypt then public-decrypt)
// ===========================================================================

/// Generate a native RSA key, apply the private exponent, then recover
/// with the public exponent.  The output must match the original input.
///
/// This exercises the "signature" direction: `m^d mod n` followed by
/// `s^e mod n` should yield the original `m`.
#[test]
fn private_encrypt_then_public_decrypt_roundtrip() {
    let mut rng = WolfRng::new().expect("RNG init");
    let mut key = NativeRsaKey::generate(2048, &mut rng)
        .expect("RSA 2048-bit key generation");

    let key_sz = key.encrypt_size().expect("encrypt_size");
    assert_eq!(key_sz, 256, "2048-bit key should have 256-byte modulus");

    // Build a valid input: must be < n.  We use a value with the high
    // byte set to 0x00 and the rest non-zero to stay below the modulus.
    let mut input = vec![0u8; key_sz];
    input[0] = 0x00;
    input[1] = 0x01;
    for i in 2..key_sz {
        input[i] = (i & 0xFF) as u8;
    }

    // private-encrypt (m^d mod n)
    let encrypted = key
        .rsa_direct(&input, RsaDirectType::PrivateEncrypt, &mut rng)
        .expect("rsa_direct PrivateEncrypt");
    assert_eq!(encrypted.len(), key_sz);
    assert_ne!(encrypted, input, "encrypted output should differ from input");

    // public-decrypt (s^e mod n) — should recover original input
    let recovered = key
        .rsa_direct(&encrypted, RsaDirectType::PublicDecrypt, &mut rng)
        .expect("rsa_direct PublicDecrypt");
    assert_eq!(recovered, input, "round-trip must recover original input");
}

// ===========================================================================
// Section 2: Public-encrypt then private-decrypt round-trip
// ===========================================================================

/// Apply the public exponent then recover with the private exponent.
/// This exercises the "encryption" direction: `m^e mod n` followed by
/// `c^d mod n`.
#[test]
fn public_encrypt_then_private_decrypt_roundtrip() {
    let mut rng = WolfRng::new().expect("RNG init");
    let mut key = NativeRsaKey::generate(2048, &mut rng)
        .expect("RSA 2048-bit key generation");

    let key_sz = key.encrypt_size().expect("encrypt_size");

    // Input value < n (high byte = 0x00).
    let mut input = vec![0u8; key_sz];
    input[0] = 0x00;
    input[1] = 0x42;
    for i in 2..key_sz {
        input[i] = ((key_sz - i) & 0xFF) as u8;
    }

    // public-encrypt (m^e mod n)
    let encrypted = key
        .rsa_direct(&input, RsaDirectType::PublicEncrypt, &mut rng)
        .expect("rsa_direct PublicEncrypt");
    assert_eq!(encrypted.len(), key_sz);

    // private-decrypt (c^d mod n)
    let recovered = key
        .rsa_direct(&encrypted, RsaDirectType::PrivateDecrypt, &mut rng)
        .expect("rsa_direct PrivateDecrypt");
    assert_eq!(recovered, input, "round-trip must recover original input");
}

// ===========================================================================
// Section 3: Wrong input size is rejected
// ===========================================================================

/// Passing input shorter than the key size must return `InvalidInput`.
#[test]
fn wrong_input_size_rejected() {
    let mut rng = WolfRng::new().expect("RNG init");
    let mut key = NativeRsaKey::generate(2048, &mut rng)
        .expect("RSA key generation");

    let too_short = vec![0x42u8; 128]; // 1024 bits, but key is 2048
    let result = key.rsa_direct(&too_short, RsaDirectType::PublicEncrypt, &mut rng);
    assert!(result.is_err(), "input shorter than key size should be rejected");
}

// ===========================================================================
// Section 4: encrypt_size is consistent
// ===========================================================================

/// `encrypt_size` should return 256 for a 2048-bit key and 512 for 4096-bit.
#[test]
fn encrypt_size_matches_key_bits() {
    let mut rng = WolfRng::new().expect("RNG init");

    let key_2048 = NativeRsaKey::generate(2048, &mut rng)
        .expect("RSA 2048 key generation");
    assert_eq!(key_2048.encrypt_size().unwrap(), 256);
}
