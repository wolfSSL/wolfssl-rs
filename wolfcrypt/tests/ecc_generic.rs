//! Generic ECC module tests — exercises the native wolfCrypt `ecc_key` API
//! with runtime curve selection.
//!
//! All tests verify structural properties (round-trip, symmetry,
//! wrong-input rejection) rather than comparing against hardcoded outputs.

#![cfg(all(feature = "ecc", wolfssl_ecc))]

use wolfcrypt::ecc::{EccCurveId, EccKey};
use wolfcrypt::rand::WolfRng;

// ================================================================
// Key generation + check_key
// ================================================================

#[test]
fn generate_p256_and_check_key() {
    let mut rng = WolfRng::new().unwrap();
    let mut key = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();
    key.check_key().expect("generated P-256 key must pass check_key");
}

// ================================================================
// ECDH shared secret symmetry
// ================================================================

#[test]
fn ecdh_p256_shared_secret_symmetric() {
    let mut rng = WolfRng::new().unwrap();
    let mut alice = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();
    let mut bob = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();

    let shared_ab = alice.ecdh_shared_secret(&mut bob).unwrap();
    let shared_ba = bob.ecdh_shared_secret(&mut alice).unwrap();

    assert_eq!(
        shared_ab, shared_ba,
        "ECDH must be symmetric: alice*Bob == bob*Alice"
    );
    // P-256 shared secret is 32 bytes.
    assert_eq!(shared_ab.len(), 32, "P-256 shared secret must be 32 bytes");
}

// ================================================================
// ECDSA sign/verify round-trip
// ================================================================

#[test]
fn ecdsa_p256_sign_verify_roundtrip() {
    let mut rng = WolfRng::new().unwrap();
    let mut key = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();

    // A fake 32-byte "hash" (SHA-256 sized).
    let hash: [u8; 32] = [0xAB; 32];

    let sig = key.sign_hash(&hash, &mut rng).unwrap();
    assert!(!sig.is_empty(), "signature must not be empty");

    let valid = key.verify_hash(&sig, &hash).unwrap();
    assert!(valid, "signature must verify against the same hash");
}

// ================================================================
// Verify with wrong hash must fail
// ================================================================

#[test]
fn ecdsa_p256_verify_wrong_hash_fails() {
    let mut rng = WolfRng::new().unwrap();
    let mut key = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();

    let hash: [u8; 32] = [0xAB; 32];
    let wrong_hash: [u8; 32] = [0xCD; 32];

    let sig = key.sign_hash(&hash, &mut rng).unwrap();

    let valid = key.verify_hash(&sig, &wrong_hash).unwrap();
    assert!(!valid, "signature must NOT verify against a different hash");
}

// ================================================================
// Public key export/import round-trip
// ================================================================

#[test]
fn public_key_x963_export_import_roundtrip() {
    let mut rng = WolfRng::new().unwrap();
    let mut key = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();

    let pub_bytes = key.export_public_x963().unwrap();

    // Uncompressed P-256 X9.63: 1 (0x04) + 32 + 32 = 65 bytes.
    assert_eq!(pub_bytes.len(), 65, "P-256 X9.63 public key must be 65 bytes");
    assert_eq!(pub_bytes[0], 0x04, "X9.63 uncompressed marker must be 0x04");

    // Re-import the public key and verify a signature produced by the original.
    let hash: [u8; 32] = [0x42; 32];
    let sig = key.sign_hash(&hash, &mut rng).unwrap();

    let mut imported = EccKey::from_public_x963(&pub_bytes).unwrap();
    let valid = imported.verify_hash(&sig, &hash).unwrap();
    assert!(valid, "imported public key must verify original key's signature");
}

// ================================================================
// Private + public key import round-trip
// ================================================================

#[test]
fn private_and_public_import_roundtrip() {
    let mut rng = WolfRng::new().unwrap();
    let mut original = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();

    let pub_bytes = original.export_public_x963().unwrap();
    let priv_bytes = original.export_private().unwrap();

    // Re-import both components.
    let mut reimported =
        EccKey::from_private_and_public(EccCurveId::SecP256R1, &priv_bytes, &pub_bytes).unwrap();
    reimported.check_key().expect("reimported key must pass check_key");

    // Verify that the reimported key can sign and the original can verify.
    let hash: [u8; 32] = [0x99; 32];
    let sig = reimported.sign_hash(&hash, &mut rng).unwrap();
    let valid = original.verify_hash(&sig, &hash).unwrap();
    assert!(valid, "reimported key's signature must verify with original key");
}
