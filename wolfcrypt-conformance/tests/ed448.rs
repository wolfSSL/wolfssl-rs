// Wolf-only round-trip and property tests. No pure-Rust Ed448 crate with a
// stable API exists for cross-validation. External known-answer validation is
// provided by rfc_ed448.rs (RFC 8032 vectors) and wycheproof_eddsa.rs.
#![cfg(wolfssl_ed448)]

mod helpers;

use helpers::random_bytes;
use signature::{Signer, Verifier};
use wolfcrypt::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey, WolfRng};

#[test]
fn sign_verify_round_trip() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();
    let msg = b"ed448 sign-verify round trip";

    let sig: Ed448Signature = sk.sign(msg);
    vk.verify(msg, &sig)
        .expect("ed448: verification of valid signature must succeed");
}

#[test]
fn tampered_message_rejected() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();
    let msg = b"original ed448 message";
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0xFF;

    let sig: Ed448Signature = sk.sign(msg);
    let result = vk.verify(&tampered, &sig);
    assert!(
        result.is_err(),
        "ed448: verification must fail when message is tampered"
    );
}

#[test]
fn tampered_signature_rejected() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();
    let msg = b"ed448 tampered signature test";

    let sig: Ed448Signature = sk.sign(msg);
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[20] ^= 0x01;
    let tampered_sig = Ed448Signature::from_bytes(&sig_bytes);

    let result = vk.verify(msg, &tampered_sig);
    assert!(
        result.is_err(),
        "ed448: verification must fail when signature is tampered"
    );
}

#[test]
fn wrong_key_rejected() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk_a = Ed448SigningKey::generate(&mut rng).expect("ed448: keygen(a) should succeed");
    let sk_b = Ed448SigningKey::generate(&mut rng).expect("ed448: keygen(b) should succeed");
    let vk_b = sk_b.verifying_key();
    let msg = b"ed448 wrong key rejection";

    let sig: Ed448Signature = sk_a.sign(msg);
    let result = vk_b.verify(msg, &sig);
    assert!(
        result.is_err(),
        "ed448: verification must fail when using the wrong public key"
    );
}

#[test]
fn deterministic() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let msg = b"ed448 determinism test";

    let sig1: Ed448Signature = sk.sign(msg);
    let sig2: Ed448Signature = sk.sign(msg);
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "ed448: signing the same message twice must produce identical signatures"
    );
}

#[test]
fn signature_encoding_round_trip() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();
    let msg = b"ed448 signature encoding round trip";

    let sig: Ed448Signature = sk.sign(msg);
    let sig_bytes = sig.to_bytes();
    let sig_restored = Ed448Signature::from_bytes(&sig_bytes);

    assert_eq!(
        sig.to_bytes(),
        sig_restored.to_bytes(),
        "ed448: signature must survive to_bytes/from_bytes round trip"
    );

    vk.verify(msg, &sig_restored)
        .expect("ed448: restored signature must still verify");
}

#[test]
fn verifying_key_round_trip() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();
    let msg = b"ed448 verifying key round trip";

    let sig: Ed448Signature = sk.sign(msg);

    let vk_bytes = vk.as_bytes();
    let vk_restored = Ed448VerifyingKey::from_bytes(vk_bytes)
        .expect("ed448: from_bytes should accept exported verifying key");

    assert_eq!(
        vk.as_bytes(),
        vk_restored.as_bytes(),
        "ed448: verifying key must survive as_bytes/from_bytes round trip"
    );

    vk_restored
        .verify(msg, &sig)
        .expect("ed448: restored verifying key must still verify");
}

#[test]
fn multiple_random_messages() {
    let mut rng = WolfRng::new().expect("WolfRng::new should succeed");
    let sk = Ed448SigningKey::generate(&mut rng).expect("ed448: key generation should succeed");
    let vk = sk.verifying_key();

    let mut thread_rng = rand::thread_rng();
    for i in 0..50 {
        let msg = random_bytes(&mut thread_rng, 32 + i * 7);
        let sig: Ed448Signature = sk.sign(&msg);
        vk.verify(&msg, &sig).unwrap_or_else(|e| {
            panic!("ed448 round {i}: sign+verify must succeed for random message: {e}")
        });
    }
}
