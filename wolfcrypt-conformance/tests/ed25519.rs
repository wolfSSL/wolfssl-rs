#![cfg(wolfssl_ed25519)]

mod helpers;

use helpers::random_bytes;
use rand::Rng;

// Both `signature::Signer` and `ed25519_dalek::Signer` are in scope.
// Use explicit aliases to avoid repeating `use … as _` in every test.
use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::Verifier as DalekVerifier;
use signature::Signer as WolfSigner;
use signature::Verifier as WolfVerifier;

#[test]
fn same_seed_same_signature() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"ed25519 deterministic signature test";

    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);
    let dalek_sig = DalekSigner::sign(&dalek_sk, msg);

    assert_eq!(
        wolf_sig.to_bytes(),
        dalek_sig.to_bytes(),
        "ed25519: signatures from same seed must be byte-identical (deterministic)"
    );
}

#[test]
fn same_seed_same_pubkey() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();

    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    let wolf_vk = wolf_sk.verifying_key();
    let dalek_vk = dalek_sk.verifying_key();

    assert_eq!(
        wolf_vk.as_bytes(),
        &dalek_vk.to_bytes(),
        "ed25519: public keys derived from the same seed must be identical"
    );
}

#[test]
fn wolf_sign_dalek_verify() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"wolf signs, dalek verifies";

    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");

    let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);

    let wolf_vk = wolf_sk.verifying_key();
    let dalek_vk = ed25519_dalek::VerifyingKey::from_bytes(wolf_vk.as_bytes())
        .expect("dalek: should accept wolf public key bytes");

    let dalek_sig = ed25519_dalek::Signature::from_bytes(&wolf_sig.to_bytes());

    DalekVerifier::verify(&dalek_vk, msg, &dalek_sig)
        .expect("ed25519: dalek must accept wolf-generated signature");
}

#[test]
fn dalek_sign_wolf_verify() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"dalek signs, wolf verifies";

    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    let dalek_sig = DalekSigner::sign(&dalek_sk, msg);

    let dalek_vk = dalek_sk.verifying_key();
    let wolf_vk =
        wolfcrypt::Ed25519VerifyingKey::from_bytes(&dalek_vk.to_bytes())
            .expect("wolf: should accept dalek public key bytes");

    let wolf_sig = ed25519::Signature::from_bytes(&dalek_sig.to_bytes());

    WolfVerifier::verify(&wolf_vk, msg, &wolf_sig)
        .expect("ed25519: wolf must accept dalek-generated signature");
}

#[test]
fn random_seeds() {
    let mut rng = rand::thread_rng();

    for i in 0..20 {
        let seed: [u8; 32] = rng.gen();
        let msg_bytes = random_bytes(&mut rng, 64 + i);

        let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
            .unwrap_or_else(|e| panic!("ed25519 round {i}: wolf from_seed failed: {e}"));
        let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

        // Same pubkey
        let wolf_vk = wolf_sk.verifying_key();
        let dalek_vk = dalek_sk.verifying_key();
        assert_eq!(
            wolf_vk.as_bytes(),
            &dalek_vk.to_bytes(),
            "ed25519 round {i}: public keys must match for same seed"
        );

        // Same signature (deterministic)
        let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk, &msg_bytes);
        let dalek_sig = DalekSigner::sign(&dalek_sk, &msg_bytes);

        assert_eq!(
            wolf_sig.to_bytes(),
            dalek_sig.to_bytes(),
            "ed25519 round {i}: signatures must be byte-identical (deterministic)"
        );

        // Cross-verify: dalek verifies wolf sig
        let dalek_sig_from_wolf =
            ed25519_dalek::Signature::from_bytes(&wolf_sig.to_bytes());
        DalekVerifier::verify(&dalek_vk, &msg_bytes, &dalek_sig_from_wolf)
            .unwrap_or_else(|e| {
                panic!("ed25519 round {i}: dalek must verify wolf signature: {e}")
            });

        // Cross-verify: wolf verifies dalek sig
        let wolf_sig_from_dalek = ed25519::Signature::from_bytes(&dalek_sig.to_bytes());
        WolfVerifier::verify(&wolf_vk, &msg_bytes, &wolf_sig_from_dalek)
            .unwrap_or_else(|e| {
                panic!("ed25519 round {i}: wolf must verify dalek signature: {e}")
            });
    }
}

#[test]
fn tampered_message_both_reject() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"original message for tamper test";
    let mut tampered_msg = msg.to_vec();
    tampered_msg[0] ^= 0xFF;

    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);

    // Wolf must reject tampered message
    let wolf_vk = wolf_sk.verifying_key();
    let wolf_result = WolfVerifier::verify(&wolf_vk, &tampered_msg, &wolf_sig);
    assert!(
        wolf_result.is_err(),
        "ed25519: wolf must reject signature against tampered message"
    );

    // Dalek must reject tampered message
    let dalek_vk = dalek_sk.verifying_key();
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&wolf_sig.to_bytes());
    let dalek_result = DalekVerifier::verify(&dalek_vk, &tampered_msg, &dalek_sig);
    assert!(
        dalek_result.is_err(),
        "ed25519: dalek must reject signature against tampered message"
    );
}

#[test]
fn tampered_signature_both_reject() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"message for signature tamper test";

    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);

    let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);
    let mut sig_bytes = wolf_sig.to_bytes();
    sig_bytes[16] ^= 0x01;

    // Wolf must reject tampered signature
    let wolf_vk = wolf_sk.verifying_key();
    let tampered_wolf_sig = ed25519::Signature::from_bytes(&sig_bytes);
    let wolf_result = WolfVerifier::verify(&wolf_vk, msg, &tampered_wolf_sig);
    assert!(
        wolf_result.is_err(),
        "ed25519: wolf must reject tampered signature"
    );

    // Dalek must reject tampered signature
    let dalek_vk = dalek_sk.verifying_key();
    let tampered_dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let dalek_result = DalekVerifier::verify(&dalek_vk, msg, &tampered_dalek_sig);
    assert!(
        dalek_result.is_err(),
        "ed25519: dalek must reject tampered signature"
    );
}

#[test]
fn wrong_key_both_reject() {
    let mut rng = rand::thread_rng();
    let seed_a: [u8; 32] = rng.gen();
    let seed_b: [u8; 32] = rng.gen();
    let msg = b"wrong key rejection test";

    let wolf_sk_a = wolfcrypt::Ed25519SigningKey::from_seed(&seed_a)
        .expect("wolf: from_seed(a) should succeed");

    let wolf_sig: ed25519::Signature = WolfSigner::sign(&wolf_sk_a, msg);

    // Wolf: verify with key B's public
    let wolf_sk_b = wolfcrypt::Ed25519SigningKey::from_seed(&seed_b)
        .expect("wolf: from_seed(b) should succeed");
    let wolf_vk_b = wolf_sk_b.verifying_key();
    let wolf_result = WolfVerifier::verify(&wolf_vk_b, msg, &wolf_sig);
    assert!(
        wolf_result.is_err(),
        "ed25519: wolf must reject signature verified with wrong public key"
    );

    // Dalek: verify with key B's public
    let dalek_sk_b = ed25519_dalek::SigningKey::from_bytes(&seed_b);
    let dalek_vk_b = dalek_sk_b.verifying_key();
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&wolf_sig.to_bytes());
    let dalek_result = DalekVerifier::verify(&dalek_vk_b, msg, &dalek_sig);
    assert!(
        dalek_result.is_err(),
        "ed25519: dalek must reject signature verified with wrong public key"
    );
}

#[test]
fn canary_different_seed_different_sig() {
    let mut rng = rand::thread_rng();
    let seed_a: [u8; 32] = rng.gen();
    let seed_b: [u8; 32] = rng.gen();
    let msg = b"different seeds should produce different signatures";

    let wolf_sk_a = wolfcrypt::Ed25519SigningKey::from_seed(&seed_a)
        .expect("wolf: from_seed(a) should succeed");
    let wolf_sk_b = wolfcrypt::Ed25519SigningKey::from_seed(&seed_b)
        .expect("wolf: from_seed(b) should succeed");

    let sig_a: ed25519::Signature = WolfSigner::sign(&wolf_sk_a, msg);
    let sig_b: ed25519::Signature = WolfSigner::sign(&wolf_sk_b, msg);

    assert_ne!(
        sig_a.to_bytes(),
        sig_b.to_bytes(),
        "ed25519: different seeds must produce different signatures on the same message"
    );
}

#[test]
fn deterministic() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"determinism check: sign twice, get same result";

    // Wolf: sign twice
    let wolf_sk = wolfcrypt::Ed25519SigningKey::from_seed(&seed)
        .expect("wolf: from_seed should succeed");
    let wolf_sig1: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);
    let wolf_sig2: ed25519::Signature = WolfSigner::sign(&wolf_sk, msg);
    assert_eq!(
        wolf_sig1.to_bytes(),
        wolf_sig2.to_bytes(),
        "ed25519: wolf must produce identical signatures for the same key+message"
    );

    // Dalek: sign twice
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let dalek_sig1 = DalekSigner::sign(&dalek_sk, msg);
    let dalek_sig2 = DalekSigner::sign(&dalek_sk, msg);
    assert_eq!(
        dalek_sig1.to_bytes(),
        dalek_sig2.to_bytes(),
        "ed25519: dalek must produce identical signatures for the same key+message"
    );
}
