// Wolf-only self-tests (commutativity, consistency). External known-answer
// validation is provided by rfc_x448.rs (RFC 7748 §6.2 vectors).
#![cfg(wolfssl_curve448)]

mod helpers;

use rand::RngCore;
use wolfcrypt::X448StaticSecret;

/// Generate a random 56-byte array suitable for X448 key material.
fn random_x448_bytes(rng: &mut impl RngCore) -> [u8; 56] {
    let mut buf = [0u8; 56];
    rng.fill_bytes(&mut buf);
    buf
}

#[test]
fn round_trip() {
    let mut rng = rand::thread_rng();
    let a_bytes = random_x448_bytes(&mut rng);
    let b_bytes = random_x448_bytes(&mut rng);

    // Derive public keys
    let a_for_pub = X448StaticSecret::from_bytes(&a_bytes);
    let a_pub = a_for_pub.public_key();

    let b_for_pub = X448StaticSecret::from_bytes(&b_bytes);
    let b_pub = b_for_pub.public_key();

    // DH in both directions (each consumes self)
    let a = X448StaticSecret::from_bytes(&a_bytes);
    let ss_a_to_b = a.diffie_hellman(&b_pub).expect("X448 DH a->b");

    let b = X448StaticSecret::from_bytes(&b_bytes);
    let ss_b_to_a = b.diffie_hellman(&a_pub).expect("X448 DH b->a");

    assert_eq!(
        ss_a_to_b.as_bytes(),
        ss_b_to_a.as_bytes(),
        "x448: DH(a, B_pub) must equal DH(b, A_pub) (commutativity)"
    );
}

#[test]
fn different_peers_different_secrets() {
    let mut rng = rand::thread_rng();
    let a_bytes = random_x448_bytes(&mut rng);
    let b_bytes = random_x448_bytes(&mut rng);
    let c_bytes = random_x448_bytes(&mut rng);

    // DH(a, B_pub)
    let b = X448StaticSecret::from_bytes(&b_bytes);
    let b_pub = b.public_key();
    let a1 = X448StaticSecret::from_bytes(&a_bytes);
    let ss_ab = a1.diffie_hellman(&b_pub).expect("X448 DH a-b");

    // DH(a, C_pub)
    let c = X448StaticSecret::from_bytes(&c_bytes);
    let c_pub = c.public_key();
    let a2 = X448StaticSecret::from_bytes(&a_bytes);
    let ss_ac = a2.diffie_hellman(&c_pub).expect("X448 DH a-c");

    assert_ne!(
        ss_ab.as_bytes(),
        ss_ac.as_bytes(),
        "x448: DH with different peers must produce different shared secrets"
    );
}

#[test]
fn key_bytes_round_trip() {
    let mut rng = rand::thread_rng();
    let bytes = random_x448_bytes(&mut rng);

    let sk1 = X448StaticSecret::from_bytes(&bytes);
    let pk1 = sk1.public_key();

    let sk2 = X448StaticSecret::from_bytes(&bytes);
    let pk2 = sk2.public_key();

    assert_eq!(
        pk1.as_bytes(),
        pk2.as_bytes(),
        "x448: same private bytes must produce the same public key on separate instantiations"
    );
}

#[test]
fn multiple_random_pairs() {
    let mut rng = rand::thread_rng();

    for i in 0..20 {
        let a_bytes = random_x448_bytes(&mut rng);
        let b_bytes = random_x448_bytes(&mut rng);

        // Derive public keys
        let a_for_pub = X448StaticSecret::from_bytes(&a_bytes);
        let a_pub = a_for_pub.public_key();

        let b_for_pub = X448StaticSecret::from_bytes(&b_bytes);
        let b_pub = b_for_pub.public_key();

        // DH both directions
        let a = X448StaticSecret::from_bytes(&a_bytes);
        let ss_a_to_b = a.diffie_hellman(&b_pub).expect("X448 DH a->b");

        let b = X448StaticSecret::from_bytes(&b_bytes);
        let ss_b_to_a = b.diffie_hellman(&a_pub).expect("X448 DH b->a");

        assert_eq!(
            ss_a_to_b.as_bytes(),
            ss_b_to_a.as_bytes(),
            "x448 round {i}: DH commutativity failed"
        );
    }
}
