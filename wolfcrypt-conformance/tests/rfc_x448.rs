#![cfg(wolfssl_curve448)]

mod helpers;

use hex_literal::hex;
use wolfcrypt::{X448PublicKey, X448StaticSecret};

/// RFC 7748 Section 6.2 -- X448 Diffie-Hellman test vector.
///
/// Alice and Bob each have a private key (56 bytes). The RFC specifies
/// the expected public keys and shared secret, allowing us to verify
/// both scalar multiplication by the base point and the DH operation.

const ALICE_PRIVATE: [u8; 56] = hex!(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
    "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
);

const ALICE_PUBLIC: [u8; 56] = hex!(
    "9b08f7cc31b7e3e67d22d5aea121074a"
    "273bd2b83de09c63faa73d2c22c5d9bb"
    "c836647241d953d40c5b12da88120d53"
    "177f80e532c41fa0"
);

const BOB_PRIVATE: [u8; 56] = hex!(
    "1c306a7ac2a0e2e0990b294470cba339"
    "e6453772b075811d8fad0d1d6927c120"
    "bb5ee8972b0d3e21374c9c921b09d1b0"
    "366f10b65173992d"
);

const BOB_PUBLIC: [u8; 56] = hex!(
    "3eb7a829b0cd20f5bcfc0b599b6feccf"
    "6da4627107bdb0d4f345b43027d8b972"
    "fc3e34fb4232a13ca706dcb57aec3dae"
    "07bdc1c67bf33609"
);

const SHARED_SECRET: [u8; 56] = hex!(
    "07fff4181ac6cc95ec1c16a94a0f74d1"
    "2da232ce40a77552281d282bb60c0b56"
    "fd2464c335543936521c24403085d59a"
    "449a5037514a879d"
);

/// Alice's public key must match the RFC value.
#[test]
fn rfc7748_alice_pubkey() {
    let sk = X448StaticSecret::from_bytes(&ALICE_PRIVATE);
    let pk = sk.public_key();
    assert_eq!(
        pk.as_bytes(),
        &ALICE_PUBLIC,
        "RFC 7748 §6.2: Alice's derived public key must match expected"
    );
}

/// Bob's public key must match the RFC value.
#[test]
fn rfc7748_bob_pubkey() {
    let sk = X448StaticSecret::from_bytes(&BOB_PRIVATE);
    let pk = sk.public_key();
    assert_eq!(
        pk.as_bytes(),
        &BOB_PUBLIC,
        "RFC 7748 §6.2: Bob's derived public key must match expected"
    );
}

/// DH(alice_priv, bob_pub) must produce the RFC shared secret.
#[test]
fn rfc7748_shared_secret_alice_to_bob() {
    let alice = X448StaticSecret::from_bytes(&ALICE_PRIVATE);
    let bob_pub = X448PublicKey::from_bytes(&BOB_PUBLIC);
    let ss = alice.diffie_hellman(&bob_pub).expect("X448 DH alice->bob");
    assert_eq!(
        ss.as_bytes(),
        &SHARED_SECRET,
        "RFC 7748 §6.2: DH(alice, bob_pub) must match expected shared secret"
    );
}

/// DH(bob_priv, alice_pub) must produce the same shared secret (commutativity).
#[test]
fn rfc7748_shared_secret_bob_to_alice() {
    let bob = X448StaticSecret::from_bytes(&BOB_PRIVATE);
    let alice_pub = X448PublicKey::from_bytes(&ALICE_PUBLIC);
    let ss = bob.diffie_hellman(&alice_pub).expect("X448 DH bob->alice");
    assert_eq!(
        ss.as_bytes(),
        &SHARED_SECRET,
        "RFC 7748 §6.2: DH(bob, alice_pub) must match expected shared secret"
    );
}
