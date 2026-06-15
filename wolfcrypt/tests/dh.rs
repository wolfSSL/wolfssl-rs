//! Classic Diffie-Hellman tests using FFDHE named groups (RFC 7919).
//!
//! Reference: RFC 7919 — Negotiated Finite Field Diffie-Hellman
//! Ephemeral Parameters for Transport Layer Security (TLS).
//!
//! These tests verify that two parties using the same FFDHE group can
//! independently compute an identical shared secret.

#![cfg(all(feature = "dh"))]

use wolfcrypt::dh::{DhSecret, FfdheGroup};

/// Both sides of an FFDHE2048 exchange must compute the same shared secret.
/// Reference: RFC 7919, FFDHE2048 group.
#[test]
fn dh_ffdhe2048_round_trip() {
    let alice = DhSecret::generate_ffdhe2048().expect("Alice keygen failed");
    let bob = DhSecret::generate_ffdhe2048().expect("Bob keygen failed");

    let alice_pub = alice.public_key_bytes().expect("export pub key");
    let bob_pub = bob.public_key_bytes().expect("export pub key");

    // Public keys should be non-trivial.
    assert!(
        !alice_pub.iter().all(|&b| b == 0),
        "Alice pub key is all zeros"
    );
    assert!(!bob_pub.iter().all(|&b| b == 0), "Bob pub key is all zeros");

    let alice_secret = alice
        .compute_shared_secret(&bob_pub)
        .expect("Alice compute failed");
    let bob_secret = bob
        .compute_shared_secret(&alice_pub)
        .expect("Bob compute failed");

    assert_eq!(alice_secret, bob_secret, "Shared secrets must match");
    assert!(
        !alice_secret.iter().all(|&b| b == 0),
        "Shared secret is all zeros"
    );
}

/// FFDHE3072 round-trip test.
/// Reference: RFC 7919, FFDHE3072 group.
#[test]
fn dh_ffdhe3072_round_trip() {
    let alice = DhSecret::generate(FfdheGroup::Ffdhe3072).expect("Alice keygen failed");
    let bob = DhSecret::generate(FfdheGroup::Ffdhe3072).expect("Bob keygen failed");

    let alice_secret = alice
        .compute_shared_secret(&bob.public_key_bytes().expect("export pub key"))
        .expect("Alice compute failed");
    let bob_secret = bob
        .compute_shared_secret(&alice.public_key_bytes().expect("export pub key"))
        .expect("Bob compute failed");

    assert_eq!(alice_secret, bob_secret);
    assert!(!alice_secret.iter().all(|&b| b == 0));
}

/// FFDHE4096 round-trip test.
/// Reference: RFC 7919, FFDHE4096 group.
#[test]
fn dh_ffdhe4096_round_trip() {
    let alice = DhSecret::generate(FfdheGroup::Ffdhe4096).expect("Alice keygen failed");
    let bob = DhSecret::generate(FfdheGroup::Ffdhe4096).expect("Bob keygen failed");

    let alice_secret = alice
        .compute_shared_secret(&bob.public_key_bytes().expect("export pub key"))
        .expect("Alice compute failed");
    let bob_secret = bob
        .compute_shared_secret(&alice.public_key_bytes().expect("export pub key"))
        .expect("Bob compute failed");

    assert_eq!(alice_secret, bob_secret);
    assert!(!alice_secret.iter().all(|&b| b == 0));
}

/// Shared secret length should match the DH parameter size.
#[test]
fn dh_shared_secret_length() {
    let alice = DhSecret::generate_ffdhe2048().expect("keygen failed");
    let bob = DhSecret::generate_ffdhe2048().expect("keygen failed");

    let secret = alice
        .compute_shared_secret(&bob.public_key_bytes().expect("export pub key"))
        .expect("compute failed");

    // FFDHE2048 → 2048-bit prime → 256 bytes.
    assert_eq!(
        secret.len(),
        256,
        "FFDHE2048 shared secret should be 256 bytes"
    );
}

/// Two independent key generations should produce different public keys
/// (probabilistic — would only fail with negligible probability).
#[test]
fn dh_distinct_keys() {
    let a = DhSecret::generate_ffdhe2048().expect("keygen failed");
    let b = DhSecret::generate_ffdhe2048().expect("keygen failed");
    assert_ne!(
        a.public_key_bytes().expect("export pub key"),
        b.public_key_bytes().expect("export pub key"),
        "Two independent DH key pairs should have different public keys"
    );
}
