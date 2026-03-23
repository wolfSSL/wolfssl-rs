#![cfg(wolfssl_curve25519)]

mod helpers;

use hex_literal::hex;
use wolfcrypt::{X25519PublicKey, X25519StaticSecret};

/// RFC 7748 Section 6.1 -- X25519 Diffie-Hellman test vector.
///
/// Alice and Bob each have a private key. The RFC specifies the expected
/// public keys and shared secret, allowing us to verify both scalar
/// multiplication by the base point and the DH operation itself.

const ALICE_PRIVATE: [u8; 32] =
    hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const ALICE_PUBLIC: [u8; 32] =
    hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

const BOB_PRIVATE: [u8; 32] =
    hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
const BOB_PUBLIC: [u8; 32] =
    hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

const SHARED_SECRET: [u8; 32] =
    hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

/// Alice's public key must match the RFC value.
#[test]
fn rfc7748_alice_pubkey() {
    let sk = X25519StaticSecret::from_bytes(&ALICE_PRIVATE);
    let pk = sk.public_key();
    assert_eq!(
        pk.as_bytes(),
        &ALICE_PUBLIC,
        "RFC 7748 §6.1: Alice's derived public key must match expected"
    );
}

/// Bob's public key must match the RFC value.
#[test]
fn rfc7748_bob_pubkey() {
    let sk = X25519StaticSecret::from_bytes(&BOB_PRIVATE);
    let pk = sk.public_key();
    assert_eq!(
        pk.as_bytes(),
        &BOB_PUBLIC,
        "RFC 7748 §6.1: Bob's derived public key must match expected"
    );
}

/// DH(alice_priv, bob_pub) must produce the RFC shared secret.
#[test]
fn rfc7748_shared_secret_alice_to_bob() {
    let alice = X25519StaticSecret::from_bytes(&ALICE_PRIVATE);
    let bob_pub = X25519PublicKey::from_bytes(&BOB_PUBLIC);
    let ss = alice.diffie_hellman(&bob_pub);
    assert_eq!(
        ss.as_bytes(),
        &SHARED_SECRET,
        "RFC 7748 §6.1: DH(alice, bob_pub) must match expected shared secret"
    );
}

/// DH(bob_priv, alice_pub) must produce the same shared secret (commutativity).
#[test]
fn rfc7748_shared_secret_bob_to_alice() {
    let bob = X25519StaticSecret::from_bytes(&BOB_PRIVATE);
    let alice_pub = X25519PublicKey::from_bytes(&ALICE_PUBLIC);
    let ss = bob.diffie_hellman(&alice_pub);
    assert_eq!(
        ss.as_bytes(),
        &SHARED_SECRET,
        "RFC 7748 §6.1: DH(bob, alice_pub) must match expected shared secret"
    );
}

/// Cross-validate: dalek must produce identical public keys and shared secret.
#[test]
fn rfc7748_cross_validate_with_dalek() {
    // Dalek: derive public keys
    let dalek_alice = x25519_dalek::StaticSecret::from(ALICE_PRIVATE);
    let dalek_alice_pub = x25519_dalek::PublicKey::from(&dalek_alice);
    assert_eq!(
        dalek_alice_pub.as_bytes(),
        &ALICE_PUBLIC,
        "RFC 7748 §6.1: dalek Alice public key must match (sanity check)"
    );

    let dalek_bob = x25519_dalek::StaticSecret::from(BOB_PRIVATE);
    let dalek_bob_pub = x25519_dalek::PublicKey::from(&dalek_bob);
    assert_eq!(
        dalek_bob_pub.as_bytes(),
        &BOB_PUBLIC,
        "RFC 7748 §6.1: dalek Bob public key must match (sanity check)"
    );

    // Dalek: shared secret
    let dalek_ss = dalek_alice.diffie_hellman(&dalek_bob_pub);
    assert_eq!(
        dalek_ss.as_bytes(),
        &SHARED_SECRET,
        "RFC 7748 §6.1: dalek shared secret must match (sanity check)"
    );
}

/// Wolf and dalek must produce byte-identical shared secrets from the RFC keys.
#[test]
fn rfc7748_wolf_matches_dalek() {
    let wolf_alice = X25519StaticSecret::from_bytes(&ALICE_PRIVATE);
    let wolf_bob_for_pub = X25519StaticSecret::from_bytes(&BOB_PRIVATE);
    let wolf_bob_pub = wolf_bob_for_pub.public_key();
    let wolf_ss = wolf_alice.diffie_hellman(&wolf_bob_pub);

    let dalek_alice = x25519_dalek::StaticSecret::from(ALICE_PRIVATE);
    let dalek_bob = x25519_dalek::StaticSecret::from(BOB_PRIVATE);
    let dalek_bob_pub = x25519_dalek::PublicKey::from(&dalek_bob);
    let dalek_ss = dalek_alice.diffie_hellman(&dalek_bob_pub);

    assert_eq!(
        wolf_ss.as_bytes(),
        dalek_ss.as_bytes(),
        "RFC 7748 §6.1: wolf and dalek shared secrets must be byte-identical"
    );
}
