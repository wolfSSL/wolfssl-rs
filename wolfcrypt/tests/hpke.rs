//! HPKE (Hybrid Public Key Encryption) tests.
//!
//! All tests are structural — HPKE seal is randomized, so we verify
//! round-trip correctness and failure modes rather than fixed vectors.

#![cfg(all(feature = "hpke", wolfssl_hpke, feature = "rand"))]

use wolfcrypt::hpke::{Hpke, HpkeSuite};
use wolfcrypt::rand::WolfRng;

/// Seal a message then open it — the plaintext must round-trip exactly.
/// Also verify that `enc` has the expected length for the suite.
#[test]
fn seal_then_open_roundtrip() {
    let suite = HpkeSuite::X25519_SHA256_AES128;
    let mut hpke = Hpke::new(suite).expect("Hpke::new");
    let mut rng = WolfRng::new().expect("WolfRng::new");

    // Receiver generates a long-term key pair.
    let mut receiver_kp = hpke.generate_keypair(&mut rng).expect("receiver keypair");

    // Sender generates an ephemeral key pair and seals.
    let mut ephemeral_kp = hpke.generate_keypair(&mut rng).expect("ephemeral keypair");

    let info = b"test-info";
    let aad = b"test-aad";
    let plaintext = b"hello HPKE world";

    let (enc, ciphertext) = hpke
        .seal_base(&mut ephemeral_kp, &mut receiver_kp, info, aad, plaintext)
        .expect("seal_base");

    // enc must be non-empty and match the KEM's encapsulated key length.
    assert!(!enc.is_empty(), "enc must not be empty");
    assert_eq!(
        enc.len(),
        suite.enc_len(),
        "enc length must match suite.enc_len()"
    );

    // Ciphertext must be plaintext + tag.
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + suite.tag_len(),
        "ciphertext length must be plaintext + tag"
    );

    // Receiver opens the message.
    let recovered = hpke
        .open_base(&mut receiver_kp, &enc, info, aad, &ciphertext)
        .expect("open_base");

    assert_eq!(recovered.as_slice(), plaintext, "plaintext must round-trip");
}

/// Sealing to receiver A and opening with receiver B's key must fail.
/// This is the key anti-cheating test: it proves the implementation
/// actually uses the receiver's private key.
#[test]
fn wrong_receiver_fails() {
    let suite = HpkeSuite::X25519_SHA256_AES128;
    let mut hpke = Hpke::new(suite).expect("Hpke::new");
    let mut rng = WolfRng::new().expect("WolfRng::new");

    let mut receiver_a = hpke.generate_keypair(&mut rng).expect("receiver A");
    let mut receiver_b = hpke.generate_keypair(&mut rng).expect("receiver B");
    let mut ephemeral = hpke.generate_keypair(&mut rng).expect("ephemeral");

    let info = b"info";
    let aad = b"aad";
    let plaintext = b"secret message";

    let (enc, ciphertext) = hpke
        .seal_base(&mut ephemeral, &mut receiver_a, info, aad, plaintext)
        .expect("seal_base");

    // Try to open with receiver B's key — must fail.
    let result = hpke.open_base(&mut receiver_b, &enc, info, aad, &ciphertext);
    assert!(result.is_err(), "opening with wrong receiver key must fail");
}

/// Sealing with AAD "correct" and opening with AAD "wrong" must fail.
#[test]
fn wrong_aad_fails() {
    let suite = HpkeSuite::X25519_SHA256_AES128;
    let mut hpke = Hpke::new(suite).expect("Hpke::new");
    let mut rng = WolfRng::new().expect("WolfRng::new");

    let mut receiver = hpke.generate_keypair(&mut rng).expect("receiver");
    let mut ephemeral = hpke.generate_keypair(&mut rng).expect("ephemeral");

    let info = b"info";
    let plaintext = b"some data";

    let (enc, ciphertext) = hpke
        .seal_base(&mut ephemeral, &mut receiver, info, b"correct", plaintext)
        .expect("seal_base");

    let result = hpke.open_base(&mut receiver, &enc, info, b"wrong", &ciphertext);
    assert!(result.is_err(), "opening with wrong AAD must fail");
}

/// Empty plaintext is valid for HPKE — the ciphertext is just the AEAD tag.
#[test]
fn empty_plaintext() {
    let suite = HpkeSuite::X25519_SHA256_AES128;
    let mut hpke = Hpke::new(suite).expect("Hpke::new");
    let mut rng = WolfRng::new().expect("WolfRng::new");

    let mut receiver = hpke.generate_keypair(&mut rng).expect("receiver");
    let mut ephemeral = hpke.generate_keypair(&mut rng).expect("ephemeral");

    let (enc, ciphertext) = hpke
        .seal_base(&mut ephemeral, &mut receiver, b"", b"", b"")
        .expect("seal_base with empty plaintext");

    // Ciphertext should be exactly the tag length.
    assert_eq!(ciphertext.len(), suite.tag_len());

    let recovered = hpke
        .open_base(&mut receiver, &enc, b"", b"", &ciphertext)
        .expect("open_base with empty plaintext");

    assert!(recovered.is_empty(), "recovered plaintext must be empty");
}

/// Verify the const suite presets have the expected field values.
#[test]
fn suite_presets() {
    assert_eq!(HpkeSuite::P256_SHA256_AES128.kem, 0x0010);
    assert_eq!(HpkeSuite::P256_SHA256_AES128.kdf, 0x0001);
    assert_eq!(HpkeSuite::P256_SHA256_AES128.aead, 0x0001);

    assert_eq!(HpkeSuite::X25519_SHA256_AES128.kem, 0x0020);
    assert_eq!(HpkeSuite::X25519_SHA256_AES128.kdf, 0x0001);
    assert_eq!(HpkeSuite::X25519_SHA256_AES128.aead, 0x0001);

    assert_eq!(HpkeSuite::P256_SHA256_AES256.aead, 0x0002);
    assert_eq!(HpkeSuite::X25519_SHA256_AES256.aead, 0x0002);

    assert_eq!(HpkeSuite::P384_SHA384_AES256.kem, 0x0011);
    assert_eq!(HpkeSuite::P384_SHA384_AES256.kdf, 0x0002);

    assert_eq!(HpkeSuite::P521_SHA512_AES256.kem, 0x0012);
    assert_eq!(HpkeSuite::P521_SHA512_AES256.kdf, 0x0003);

    assert_eq!(HpkeSuite::X448_SHA512_AES256.kem, 0x0021);

    // enc_len for known KEMs
    assert_eq!(HpkeSuite::P256_SHA256_AES128.enc_len(), 65);
    assert_eq!(HpkeSuite::X25519_SHA256_AES128.enc_len(), 32);
    assert_eq!(HpkeSuite::P384_SHA384_AES256.enc_len(), 97);
    assert_eq!(HpkeSuite::P521_SHA512_AES256.enc_len(), 133);
    assert_eq!(HpkeSuite::X448_SHA512_AES256.enc_len(), 56);

    // tag_len is always 16 for the supported AEADs
    assert_eq!(HpkeSuite::P256_SHA256_AES128.tag_len(), 16);
    assert_eq!(HpkeSuite::X25519_SHA256_AES256.tag_len(), 16);
}
