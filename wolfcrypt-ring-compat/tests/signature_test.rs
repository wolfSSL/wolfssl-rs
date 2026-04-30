// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

use ring::signature::KeyPair;
use ring::{rand, signature};

#[test]
fn signature_traits() {
    fn require_send<T: Send>() {}
    fn require_sync<T: Sync>() {}
    fn require_clone<T: Clone>() {}
    require_clone::<signature::Signature>();
    require_send::<signature::Signature>();
    require_sync::<signature::Signature>();
}

#[test]
fn unparsed_public_key_traits() {
    fn require_debug<T: std::fmt::Debug>() {}
    fn require_sync<T: Sync>() {}

    require_debug::<signature::UnparsedPublicKey<&[u8]>>();
    require_sync::<signature::UnparsedPublicKey<&[u8]>>();
}

#[test]
fn unparsed_public_key_debug_format() {
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let key = signature::UnparsedPublicKey::new(&signature::ED25519, bytes);
    let debug = format!("{:?}", key);

    // Should contain the algorithm name and bytes
    assert!(
        debug.contains("ED25519") || debug.contains("Ed25519") || debug.contains("EdDSA"),
        "Debug output should mention algorithm: {debug}"
    );
}

#[test]
fn unparsed_public_key_as_ref() {
    let bytes: &[u8] = &[0x01, 0x02, 0x03];
    let key = signature::UnparsedPublicKey::new(&signature::ED25519, bytes);
    assert_eq!(key.as_ref(), bytes);
}

#[test]
fn ed25519_sign_and_verify() {
    let rng = rand::SystemRandom::new();

    // Generate an Ed25519 key pair
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let msg = b"test message for signature";
    let sig = key_pair.sign(msg);

    // Verify with the public key
    let public_key = key_pair.public_key();
    let unparsed_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref());
    unparsed_public_key
        .verify(msg, sig.as_ref())
        .expect("Signature verification should succeed");
}

#[test]
fn ed25519_verify_wrong_message_fails() {
    let rng = rand::SystemRandom::new();

    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let sig = key_pair.sign(b"correct message");

    let public_key = key_pair.public_key();
    let unparsed_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref());

    assert!(
        unparsed_public_key
            .verify(b"wrong message", sig.as_ref())
            .is_err(),
        "Verification should fail for wrong message"
    );
}

#[test]
fn verification_algorithm_debug() {
    let algs: &[&dyn signature::VerificationAlgorithm] = &[
        &signature::ED25519,
        &signature::ECDSA_P256_SHA256_ASN1,
        &signature::ECDSA_P256_SHA256_FIXED,
        &signature::ECDSA_P384_SHA384_ASN1,
        &signature::ECDSA_P384_SHA384_FIXED,
    ];

    for alg in algs {
        let debug = format!("{:?}", alg);
        assert!(
            !debug.is_empty(),
            "VerificationAlgorithm Debug should not be empty"
        );
    }
}

#[test]
fn key_pair_public_key_accessor() {
    use signature::KeyPair;

    let rng = rand::SystemRandom::new();
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key();
    assert_eq!(
        public_key.as_ref().len(),
        signature::ED25519_PUBLIC_KEY_LEN,
        "Ed25519 public key should be {} bytes",
        signature::ED25519_PUBLIC_KEY_LEN
    );
}
