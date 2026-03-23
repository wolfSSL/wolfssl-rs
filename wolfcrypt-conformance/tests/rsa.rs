// Wolf-only round-trip and property tests. External known-answer validation
// is provided by wycheproof_rsa.rs (Wycheproof PKCS#1v1.5 and PSS vectors).
// TODO: add cross-validation against the pure-Rust `rsa` crate when its
// API stabilises enough for signing interop.
#![cfg(all(wolfssl_openssl_extra, wolfssl_rsa))]

mod helpers;

use helpers::random_bytes;
use wolfcrypt::rsa::{RsaPrivateKey, RsaPkcs1v15Signature, RsaPssSignature};

#[test]
fn pkcs1v15_sign_verify_round_trip() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"PKCS#1v1.5 round-trip test message";

    let sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing should succeed");
    pk.verify_pkcs1v15(msg, &sig)
        .expect("rsa: PKCS#1v1.5 verification of valid signature must succeed");
}

#[test]
fn pss_sign_verify_round_trip() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"PSS round-trip test message";

    let sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing should succeed");
    pk.verify_pss(msg, &sig)
        .expect("rsa: PSS verification of valid signature must succeed");
}

#[test]
fn pkcs1v15_deterministic() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let msg = b"determinism check for PKCS#1v1.5";

    let sig1 = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing (1) should succeed");
    let sig2 = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing (2) should succeed");

    assert_eq!(
        sig1.as_ref(),
        sig2.as_ref(),
        "rsa: PKCS#1v1.5 must produce identical signatures for same key+message (deterministic)"
    );
}

#[test]
fn pss_not_deterministic() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let msg = b"PSS randomization check";

    let sig1 = sk.sign_pss(msg)
        .expect("rsa: PSS signing (1) should succeed");
    let sig2 = sk.sign_pss(msg)
        .expect("rsa: PSS signing (2) should succeed");

    // PSS uses random salt, so signatures should differ.
    // Theoretically they could collide, but with 256-bit salt that is negligible.
    assert_ne!(
        sig1.as_ref(),
        sig2.as_ref(),
        "rsa: PSS signatures for same key+message should differ (randomized salt)"
    );
}

#[test]
fn pkcs1v15_tampered_message_rejected() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"original message for tamper test";
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0xFF;

    let sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing should succeed");

    let result = pk.verify_pkcs1v15(&tampered, &sig);
    assert!(
        result.is_err(),
        "rsa: PKCS#1v1.5 must reject signature against tampered message"
    );
}

#[test]
fn pss_tampered_message_rejected() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"original message for PSS tamper test";
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0xFF;

    let sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing should succeed");

    let result = pk.verify_pss(&tampered, &sig);
    assert!(
        result.is_err(),
        "rsa: PSS must reject signature against tampered message"
    );
}

#[test]
fn pkcs1v15_tampered_signature_rejected() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"message for signature tamper test";

    let sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing should succeed");

    let mut sig_bytes = sig.as_ref().to_vec();
    sig_bytes[16] ^= 0x01;
    let tampered_sig = RsaPkcs1v15Signature::try_from(sig_bytes.as_slice())
        .expect("rsa: constructing tampered PKCS#1v1.5 signature from bytes should succeed");

    let result = pk.verify_pkcs1v15(msg, &tampered_sig);
    assert!(
        result.is_err(),
        "rsa: PKCS#1v1.5 must reject tampered signature"
    );
}

#[test]
fn pss_tampered_signature_rejected() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"message for PSS signature tamper test";

    let sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing should succeed");

    let mut sig_bytes = sig.as_ref().to_vec();
    sig_bytes[16] ^= 0x01;
    let tampered_sig = RsaPssSignature::try_from(sig_bytes.as_slice())
        .expect("rsa: constructing tampered PSS signature from bytes should succeed");

    let result = pk.verify_pss(msg, &tampered_sig);
    assert!(
        result.is_err(),
        "rsa: PSS must reject tampered signature"
    );
}

#[test]
fn pkcs1v15_wrong_key_rejected() {
    let sk_a = RsaPrivateKey::generate(2048)
        .expect("rsa: key A generation should succeed");
    let sk_b = RsaPrivateKey::generate(2048)
        .expect("rsa: key B generation should succeed");
    let pk_b = sk_b.public_key();
    let msg = b"wrong key rejection test PKCS#1v1.5";

    let sig = sk_a.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing with key A should succeed");

    let result = pk_b.verify_pkcs1v15(msg, &sig);
    assert!(
        result.is_err(),
        "rsa: PKCS#1v1.5 must reject signature verified with wrong public key"
    );
}

#[test]
fn pss_wrong_key_rejected() {
    let sk_a = RsaPrivateKey::generate(2048)
        .expect("rsa: key A generation should succeed");
    let sk_b = RsaPrivateKey::generate(2048)
        .expect("rsa: key B generation should succeed");
    let pk_b = sk_b.public_key();
    let msg = b"wrong key rejection test PSS";

    let sig = sk_a.sign_pss(msg)
        .expect("rsa: PSS signing with key A should succeed");

    let result = pk_b.verify_pss(msg, &sig);
    assert!(
        result.is_err(),
        "rsa: PSS must reject signature verified with wrong public key"
    );
}

#[test]
fn key_size_4096() {
    let sk = RsaPrivateKey::generate(4096)
        .expect("rsa: 4096-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"4096-bit key test message";

    let pkcs_sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing with 4096-bit key should succeed");
    pk.verify_pkcs1v15(msg, &pkcs_sig)
        .expect("rsa: PKCS#1v1.5 verification with 4096-bit key must succeed");

    let pss_sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing with 4096-bit key should succeed");
    pk.verify_pss(msg, &pss_sig)
        .expect("rsa: PSS verification with 4096-bit key must succeed");

    assert_eq!(
        pkcs_sig.as_ref().len(),
        512,
        "rsa: PKCS#1v1.5 signature for 4096-bit key must be 512 bytes"
    );
    assert_eq!(
        pss_sig.as_ref().len(),
        512,
        "rsa: PSS signature for 4096-bit key must be 512 bytes"
    );
}

#[test]
fn multiple_random_messages() {
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();

    for i in 0..10 {
        let msg = random_bytes(&mut rng, 32 + i * 13);

        let pkcs_sig = sk.sign_pkcs1v15(&msg)
            .unwrap_or_else(|e| panic!("rsa round {i}: PKCS#1v1.5 signing failed: {e}"));
        pk.verify_pkcs1v15(&msg, &pkcs_sig)
            .unwrap_or_else(|e| panic!("rsa round {i}: PKCS#1v1.5 verification failed: {e}"));

        let pss_sig = sk.sign_pss(&msg)
            .unwrap_or_else(|e| panic!("rsa round {i}: PSS signing failed: {e}"));
        pk.verify_pss(&msg, &pss_sig)
            .unwrap_or_else(|e| panic!("rsa round {i}: PSS verification failed: {e}"));
    }
}

#[test]
fn signature_encoding_round_trip() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let msg = b"encoding round-trip test";

    // PKCS#1v1.5
    let pkcs_sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing should succeed");
    let pkcs_bytes = pkcs_sig.as_ref();
    let pkcs_restored = RsaPkcs1v15Signature::try_from(pkcs_bytes)
        .expect("rsa: PKCS#1v1.5 signature round-trip from bytes should succeed");
    assert_eq!(
        pkcs_sig.as_ref(),
        pkcs_restored.as_ref(),
        "rsa: PKCS#1v1.5 signature encoding must round-trip"
    );

    // PSS
    let pss_sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing should succeed");
    let pss_bytes = pss_sig.as_ref();
    let pss_restored = RsaPssSignature::try_from(pss_bytes)
        .expect("rsa: PSS signature round-trip from bytes should succeed");
    assert_eq!(
        pss_sig.as_ref(),
        pss_restored.as_ref(),
        "rsa: PSS signature encoding must round-trip"
    );
}

#[test]
fn pkcs1v15_cross_scheme_rejected() {
    let sk = RsaPrivateKey::generate(2048)
        .expect("rsa: 2048-bit key generation should succeed");
    let pk = sk.public_key();
    let msg = b"cross-scheme rejection test";

    // Sign PKCS#1v1.5, try to verify as PSS
    let pkcs_sig = sk.sign_pkcs1v15(msg)
        .expect("rsa: PKCS#1v1.5 signing should succeed");
    let fake_pss = RsaPssSignature::try_from(pkcs_sig.as_ref())
        .expect("rsa: constructing PSS sig from PKCS#1v1.5 bytes should succeed");
    let result = pk.verify_pss(msg, &fake_pss);
    assert!(
        result.is_err(),
        "rsa: PKCS#1v1.5 signature must not verify as PSS"
    );

    // Sign PSS, try to verify as PKCS#1v1.5
    let pss_sig = sk.sign_pss(msg)
        .expect("rsa: PSS signing should succeed");
    let fake_pkcs = RsaPkcs1v15Signature::try_from(pss_sig.as_ref())
        .expect("rsa: constructing PKCS#1v1.5 sig from PSS bytes should succeed");
    let result = pk.verify_pkcs1v15(msg, &fake_pkcs);
    assert!(
        result.is_err(),
        "rsa: PSS signature must not verify as PKCS#1v1.5"
    );
}
