#![cfg(wolfssl_curve25519)]

mod helpers;

use rand::Rng;
use wolfcrypt::X25519StaticSecret;

#[test]
fn pubkey_derivation_equiv() {
    let mut rng = rand::thread_rng();
    let secret_bytes: [u8; 32] = rng.gen();

    // Wolf: derive public key
    let wolf_sk = X25519StaticSecret::from_bytes(&secret_bytes);
    let wolf_pk = wolf_sk.public_key();

    // Dalek: derive public key
    let dalek_sk = x25519_dalek::StaticSecret::from(secret_bytes);
    let dalek_pk = x25519_dalek::PublicKey::from(&dalek_sk);

    assert_eq!(
        wolf_pk.as_bytes(),
        dalek_pk.as_bytes(),
        "x25519: public keys derived from the same secret must be byte-identical"
    );
}

#[test]
fn shared_secret_equiv() {
    let mut rng = rand::thread_rng();
    let alice_bytes: [u8; 32] = rng.gen();
    let bob_bytes: [u8; 32] = rng.gen();

    // Wolf: alice DH with bob's pub
    let wolf_bob = X25519StaticSecret::from_bytes(&bob_bytes);
    let wolf_bob_pub = wolf_bob.public_key();
    let wolf_alice = X25519StaticSecret::from_bytes(&alice_bytes);
    let wolf_ss = wolf_alice.diffie_hellman(&wolf_bob_pub);

    // Dalek: alice DH with bob's pub
    let dalek_alice = x25519_dalek::StaticSecret::from(alice_bytes);
    let dalek_bob = x25519_dalek::StaticSecret::from(bob_bytes);
    let dalek_bob_pub = x25519_dalek::PublicKey::from(&dalek_bob);
    let dalek_ss = dalek_alice.diffie_hellman(&dalek_bob_pub);

    assert_eq!(
        wolf_ss.as_bytes(),
        dalek_ss.as_bytes(),
        "x25519: shared secrets must match when both impls use same alice_priv + bob_pub"
    );
}

#[test]
fn cross_dh_commutativity() {
    let mut rng = rand::thread_rng();
    let a_bytes: [u8; 32] = rng.gen();
    let b_bytes: [u8; 32] = rng.gen();

    // Derive public keys first; diffie_hellman() consumes self,
    // so we re-create each secret for the DH step below.
    let wolf_a_for_pub = X25519StaticSecret::from_bytes(&a_bytes);
    let wolf_a_pub = wolf_a_for_pub.public_key();

    let wolf_b_for_pub = X25519StaticSecret::from_bytes(&b_bytes);
    let wolf_b_pub = wolf_b_for_pub.public_key();

    // DH in both directions
    let wolf_a = X25519StaticSecret::from_bytes(&a_bytes);
    let ss_a_to_b = wolf_a.diffie_hellman(&wolf_b_pub);

    // Wolf: B does DH with A's pub (consumes wolf_b)
    let wolf_b = X25519StaticSecret::from_bytes(&b_bytes);
    let ss_b_to_a = wolf_b.diffie_hellman(&wolf_a_pub);

    assert_eq!(
        ss_a_to_b.as_bytes(),
        ss_b_to_a.as_bytes(),
        "x25519: DH(a, B_pub) must equal DH(b, A_pub) (commutativity)"
    );

    // Verify against dalek for the same operation
    let dalek_a = x25519_dalek::StaticSecret::from(a_bytes);
    let dalek_b = x25519_dalek::StaticSecret::from(b_bytes);
    let dalek_b_pub = x25519_dalek::PublicKey::from(&dalek_b);
    let dalek_ss = dalek_a.diffie_hellman(&dalek_b_pub);

    assert_eq!(
        ss_a_to_b.as_bytes(),
        dalek_ss.as_bytes(),
        "x25519: wolf DH(a, B_pub) must match dalek DH(a, B_pub)"
    );
}

#[test]
fn multiple_random_pairs() {
    let mut rng = rand::thread_rng();

    for i in 0..20 {
        let a_bytes: [u8; 32] = rng.gen();
        let b_bytes: [u8; 32] = rng.gen();

        // Wolf: public key derivation
        let wolf_a_for_pub = X25519StaticSecret::from_bytes(&a_bytes);
        let wolf_a_pub = wolf_a_for_pub.public_key();

        let wolf_b_for_pub = X25519StaticSecret::from_bytes(&b_bytes);
        let wolf_b_pub = wolf_b_for_pub.public_key();

        // Dalek: public key derivation
        let dalek_a = x25519_dalek::StaticSecret::from(a_bytes);
        let dalek_a_pub = x25519_dalek::PublicKey::from(&dalek_a);

        let dalek_b = x25519_dalek::StaticSecret::from(b_bytes);
        let dalek_b_pub = x25519_dalek::PublicKey::from(&dalek_b);

        // Check public keys match
        assert_eq!(
            wolf_a_pub.as_bytes(),
            dalek_a_pub.as_bytes(),
            "x25519 round {i}: public key A mismatch between wolf and dalek"
        );
        assert_eq!(
            wolf_b_pub.as_bytes(),
            dalek_b_pub.as_bytes(),
            "x25519 round {i}: public key B mismatch between wolf and dalek"
        );

        // Wolf: DH(a, B_pub)
        let wolf_a = X25519StaticSecret::from_bytes(&a_bytes);
        let wolf_ss = wolf_a.diffie_hellman(&wolf_b_pub);

        // Dalek: DH(a, B_pub)
        let dalek_ss = dalek_a.diffie_hellman(&dalek_b_pub);

        assert_eq!(
            wolf_ss.as_bytes(),
            dalek_ss.as_bytes(),
            "x25519 round {i}: shared secret mismatch between wolf and dalek"
        );
    }
}

#[test]
fn canary_different_keys_different_secrets() {
    let mut rng = rand::thread_rng();

    let a_bytes: [u8; 32] = rng.gen();
    let b_bytes: [u8; 32] = rng.gen();
    let c_bytes: [u8; 32] = rng.gen();

    // Wolf: DH(a, B_pub)
    let wolf_b = X25519StaticSecret::from_bytes(&b_bytes);
    let wolf_b_pub = wolf_b.public_key();
    let wolf_a = X25519StaticSecret::from_bytes(&a_bytes);
    let ss_ab = wolf_a.diffie_hellman(&wolf_b_pub);

    // Wolf: DH(a, C_pub)
    let wolf_c = X25519StaticSecret::from_bytes(&c_bytes);
    let wolf_c_pub = wolf_c.public_key();
    let wolf_a2 = X25519StaticSecret::from_bytes(&a_bytes);
    let ss_ac = wolf_a2.diffie_hellman(&wolf_c_pub);

    assert_ne!(
        ss_ab.as_bytes(),
        ss_ac.as_bytes(),
        "x25519: DH with different peers must produce different shared secrets"
    );
}
