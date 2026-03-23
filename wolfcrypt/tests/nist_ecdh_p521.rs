//! NIST P-521 ECDH round-trip tests for wolfcrypt.
//!
//! These tests exercise the wolfCrypt NIST ECDH P-521 implementation via the
//! wolfSSL OpenSSL compat layer (EC_KEY / ECDH_compute_key).

use wolfcrypt::P521EcdhSecret;

// ================================================================
// P-521 round-trip DH
// ================================================================

/// NIST SP 800-56Ar3, ECC CDH on P-521: generate two keypairs, compute
/// the shared secret from both sides, and verify they are equal.
#[test]
fn p521_round_trip() {
    let alice = P521EcdhSecret::generate().unwrap();
    let alice_pub = alice.public_key();

    let bob = P521EcdhSecret::generate().unwrap();
    let bob_pub = bob.public_key();

    let shared_ab = alice.diffie_hellman(&bob_pub);
    let shared_ba = bob.diffie_hellman(&alice_pub);

    assert_eq!(
        shared_ab.as_bytes(),
        shared_ba.as_bytes(),
        "P-521 ECDH must be symmetric: alice*Bob == bob*Alice"
    );
}

// ================================================================
// P-521 shared secret length = 66 bytes
// ================================================================

/// Shared secret length validation: P-521 ECDH must produce exactly
/// 66 bytes (the field element size for secp521r1, ceil(521/8)).
#[test]
fn p521_shared_secret_length() {
    let alice = P521EcdhSecret::generate().unwrap();
    let bob = P521EcdhSecret::generate().unwrap();
    let bob_pub = bob.public_key();

    let shared = alice.diffie_hellman(&bob_pub);
    assert_eq!(
        shared.as_bytes().len(),
        66,
        "P-521 shared secret must be 66 bytes"
    );
}
