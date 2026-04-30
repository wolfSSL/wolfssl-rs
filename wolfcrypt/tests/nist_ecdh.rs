// NIST curve ECDH round-trip tests (P-256, P-384).
//
// Exercises the native wc_ecc_* NIST ECDH implementation.
// Validates DH symmetry, shared-secret length, key export/import, and
// rejection of malformed public keys.

#![cfg(all(wolfssl_ecc, feature = "ecdh"))]

use wolfcrypt::{NistEcdhPublicKey, NistP256, P256EcdhSecret};

#[cfg(wolfssl_ecc_p384)]
use wolfcrypt::{NistP384, P384EcdhSecret};

// ================================================================
// P-256 tests
// ================================================================

/// NIST SP 800-56Ar3, ECC CDH on P-256: generate two keypairs, compute
/// the shared secret from both sides, and verify they are equal.
#[test]
fn p256_round_trip() {
    let alice = P256EcdhSecret::generate().expect("P-256 generate alice");
    let alice_pub = alice.public_key().expect("P-256 export alice pub");

    let bob = P256EcdhSecret::generate().expect("P-256 generate bob");
    let bob_pub = bob.public_key().expect("P-256 export bob pub");

    let shared_ab = alice.diffie_hellman(&bob_pub).expect("P-256 DH alice->bob");
    let shared_ba = bob.diffie_hellman(&alice_pub).expect("P-256 DH bob->alice");

    assert_eq!(
        shared_ab.as_bytes(),
        shared_ba.as_bytes(),
        "P-256 ECDH must be symmetric: alice*Bob == bob*Alice"
    );
}

/// Shared secret length validation: P-256 ECDH must produce exactly
/// 32 bytes (the field element size for secp256r1).
#[test]
fn p256_shared_secret_length() {
    let alice = P256EcdhSecret::generate().expect("P-256 generate alice");
    let bob = P256EcdhSecret::generate().expect("P-256 generate bob");
    let bob_pub = bob.public_key().expect("P-256 export bob pub");

    let shared = alice.diffie_hellman(&bob_pub).expect("P-256 DH");
    assert_eq!(
        shared.as_bytes().len(),
        32,
        "P-256 shared secret must be 32 bytes"
    );
}

/// Different keypairs produce different shared secrets: generate two
/// independent pairs (A1,B1) and (A2,B2) and verify DH(A1,B1) != DH(A2,B2).
#[test]
fn p256_different_keypairs_different_secrets() {
    let a1 = P256EcdhSecret::generate().expect("generate a1");
    let b1 = P256EcdhSecret::generate().expect("generate b1");
    let b1_pub = b1.public_key().expect("export b1 pub");
    let shared1 = a1.diffie_hellman(&b1_pub).expect("DH a1*b1");

    let a2 = P256EcdhSecret::generate().expect("generate a2");
    let b2 = P256EcdhSecret::generate().expect("generate b2");
    let b2_pub = b2.public_key().expect("export b2 pub");
    let shared2 = a2.diffie_hellman(&b2_pub).expect("DH a2*b2");

    // Probability of collision is ~2^{-256}; safe to assert inequality.
    assert_ne!(
        shared1.as_bytes(),
        shared2.as_bytes(),
        "independent P-256 ECDH exchanges must produce different secrets"
    );
}

/// Public key export/import round-trip: export a public key as an
/// uncompressed point, import it into a new `NistEcdhPublicKey`, and
/// compute ECDH with it to verify correctness.
#[test]
fn p256_public_key_export_import_round_trip() {
    let checker = P256EcdhSecret::generate().expect("generate checker");
    let checker_pub = checker.public_key().expect("export checker pub");

    let exported = checker_pub.as_bytes();

    // Verify uncompressed point format: 0x04 prefix, 65 bytes total.
    assert_eq!(
        exported.len(),
        65,
        "P-256 uncompressed point must be 65 bytes"
    );
    assert_eq!(exported[0], 0x04, "uncompressed point must start with 0x04");

    // Re-import from bytes.
    let reimported: NistEcdhPublicKey<NistP256> =
        NistEcdhPublicKey::from_bytes(exported).expect("valid public key");

    // Verify DH works with the reimported key: compute from both sides.
    let peer = P256EcdhSecret::generate().expect("generate peer");
    let peer_pub = peer.public_key().expect("export peer pub");

    let shared_a = checker.diffie_hellman(&peer_pub).expect("DH checker*peer");
    let shared_b = peer
        .diffie_hellman(&reimported)
        .expect("DH peer*checker(reimported)");

    assert_eq!(
        shared_a.as_bytes(),
        shared_b.as_bytes(),
        "DH with re-imported public key must match"
    );
}

/// Reject invalid public key: wrong length.
#[test]
fn p256_reject_invalid_pubkey_length() {
    let short = [0x04u8; 10];
    assert!(
        NistEcdhPublicKey::<NistP256>::from_bytes(&short).is_err(),
        "must reject short public key"
    );
}

/// Reject invalid public key: missing 0x04 prefix.
#[test]
fn p256_reject_invalid_pubkey_prefix() {
    let mut bad = vec![0u8; 65];
    bad[0] = 0x02; // compressed prefix, not uncompressed
    assert!(
        NistEcdhPublicKey::<NistP256>::from_bytes(&bad).is_err(),
        "must reject non-uncompressed public key"
    );
}

// ================================================================
// P-384 tests
// ================================================================

/// NIST SP 800-56Ar3, ECC CDH on P-384: generate two keypairs, compute
/// the shared secret from both sides, and verify they are equal.
#[cfg(wolfssl_ecc_p384)]
#[test]
fn p384_round_trip() {
    let alice = P384EcdhSecret::generate().expect("P-384 generate alice");
    let alice_pub = alice.public_key().expect("P-384 export alice pub");

    let bob = P384EcdhSecret::generate().expect("P-384 generate bob");
    let bob_pub = bob.public_key().expect("P-384 export bob pub");

    let shared_ab = alice.diffie_hellman(&bob_pub).expect("P-384 DH alice->bob");
    let shared_ba = bob.diffie_hellman(&alice_pub).expect("P-384 DH bob->alice");

    assert_eq!(
        shared_ab.as_bytes(),
        shared_ba.as_bytes(),
        "P-384 ECDH must be symmetric: alice*Bob == bob*Alice"
    );
}

/// Shared secret length validation: P-384 ECDH must produce exactly
/// 48 bytes (the field element size for secp384r1).
#[cfg(wolfssl_ecc_p384)]
#[test]
fn p384_shared_secret_length() {
    let alice = P384EcdhSecret::generate().expect("P-384 generate alice");
    let bob = P384EcdhSecret::generate().expect("P-384 generate bob");
    let bob_pub = bob.public_key().expect("P-384 export bob pub");

    let shared = alice.diffie_hellman(&bob_pub).expect("P-384 DH");
    assert_eq!(
        shared.as_bytes().len(),
        48,
        "P-384 shared secret must be 48 bytes"
    );
}

/// Different keypairs produce different shared secrets on P-384.
#[cfg(wolfssl_ecc_p384)]
#[test]
fn p384_different_keypairs_different_secrets() {
    let a1 = P384EcdhSecret::generate().expect("generate a1");
    let b1 = P384EcdhSecret::generate().expect("generate b1");
    let b1_pub = b1.public_key().expect("export b1 pub");
    let shared1 = a1.diffie_hellman(&b1_pub).expect("DH a1*b1");

    let a2 = P384EcdhSecret::generate().expect("generate a2");
    let b2 = P384EcdhSecret::generate().expect("generate b2");
    let b2_pub = b2.public_key().expect("export b2 pub");
    let shared2 = a2.diffie_hellman(&b2_pub).expect("DH a2*b2");

    assert_ne!(
        shared1.as_bytes(),
        shared2.as_bytes(),
        "independent P-384 ECDH exchanges must produce different secrets"
    );
}

/// Public key export/import round-trip on P-384.
#[cfg(wolfssl_ecc_p384)]
#[test]
fn p384_public_key_export_import_round_trip() {
    let checker = P384EcdhSecret::generate().expect("generate checker");
    let checker_pub = checker.public_key().expect("export checker pub");

    let exported = checker_pub.as_bytes();

    // Verify uncompressed point format: 0x04 prefix, 97 bytes total.
    assert_eq!(
        exported.len(),
        97,
        "P-384 uncompressed point must be 97 bytes"
    );
    assert_eq!(exported[0], 0x04, "uncompressed point must start with 0x04");

    // Re-import from bytes.
    let reimported: NistEcdhPublicKey<NistP384> =
        NistEcdhPublicKey::from_bytes(exported).expect("valid public key");

    // Verify DH works with the reimported key.
    let peer = P384EcdhSecret::generate().expect("generate peer");
    let peer_pub = peer.public_key().expect("export peer pub");

    let shared_a = checker.diffie_hellman(&peer_pub).expect("DH checker*peer");
    let shared_b = peer
        .diffie_hellman(&reimported)
        .expect("DH peer*checker(reimported)");

    assert_eq!(
        shared_a.as_bytes(),
        shared_b.as_bytes(),
        "DH with re-imported P-384 public key must match"
    );
}
