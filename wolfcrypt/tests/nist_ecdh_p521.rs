//! NIST P-521 ECDH round-trip tests for wolfcrypt.
//!
//! Exercises the native wc_ecc_* P-521 ECDH implementation.

#![cfg(all(wolfssl_ecc, wolfssl_ecc_p521, feature = "ecdh"))]

use wolfcrypt::P521EcdhSecret;

/// NIST SP 800-56Ar3, ECC CDH on P-521: generate two keypairs, compute
/// the shared secret from both sides, and verify they are equal.
#[test]
fn p521_round_trip() {
    let alice = P521EcdhSecret::generate().expect("P-521 generate alice");
    let alice_pub = alice.public_key().expect("P-521 export alice pub");

    let bob = P521EcdhSecret::generate().expect("P-521 generate bob");
    let bob_pub = bob.public_key().expect("P-521 export bob pub");

    let shared_ab = alice.diffie_hellman(&bob_pub).expect("P-521 DH alice->bob");
    let shared_ba = bob.diffie_hellman(&alice_pub).expect("P-521 DH bob->alice");

    assert_eq!(
        shared_ab.as_bytes(),
        shared_ba.as_bytes(),
        "P-521 ECDH must be symmetric: alice*Bob == bob*Alice"
    );
}

/// Shared secret length validation: P-521 ECDH must produce exactly
/// 66 bytes (the field element size for secp521r1, ceil(521/8)).
#[test]
fn p521_shared_secret_length() {
    let alice = P521EcdhSecret::generate().expect("P-521 generate alice");
    let bob = P521EcdhSecret::generate().expect("P-521 generate bob");
    let bob_pub = bob.public_key().expect("P-521 export bob pub");

    let shared = alice.diffie_hellman(&bob_pub).expect("P-521 DH");
    assert_eq!(
        shared.as_bytes().len(),
        66,
        "P-521 shared secret must be 66 bytes"
    );
}
