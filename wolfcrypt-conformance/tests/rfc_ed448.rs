#![cfg(wolfssl_ed448)]

mod helpers;

use hex_literal::hex;
use signature::{Signer, Verifier};
use wolfcrypt::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};

/// RFC 8032 Section 7.4 -- Ed448 test vectors (pure Ed448, no context).
///
/// Each vector specifies a 57-byte secret key (seed), the derived public key,
/// a message, and the expected 114-byte signature. Ed448 is deterministic, so
/// the signature is uniquely determined by (seed, message).
///
/// All hex values verified against Python's `cryptography` library.
struct Ed448Vector {
    name: &'static str,
    seed: &'static [u8; 57],
    public_key: &'static [u8; 57],
    message: &'static [u8],
    signature: &'static [u8; 114],
}

// --- Test Vector 1: empty message ---
const VEC1_SEED: [u8; 57] = hex!(
    "6c82a562cb808d10d632be89c8513ebf"
    "6c929f34ddfa8c9f63c9960ef6e348a3"
    "528c8a3fcc2f044e39a3fc5b94492f8f"
    "032e7549a20098f95b"
);
const VEC1_PK: [u8; 57] = hex!(
    "5fd7449b59b461fd2ce787ec616ad46a"
    "1da1342485a70e1f8a0ea75d80e96778"
    "edf124769b46c7061bd6783df1e50f6c"
    "d1fa1abeafe8256180"
);
const VEC1_SIG: [u8; 114] = hex!(
    "533a37f6bbe457251f023c0d88f976ae"
    "2dfb504a843e34d2074fd823d41a591f"
    "2b233f034f628281f2fd7a22ddd47d78"
    "28c59bd0a21bfd3980"
    "ff0d2028d4b18a9df63e006c5d1c2d34"
    "5b925d8dc00b4104852db99ac5c7cdda"
    "8530a113a0f4dbb61149f05a7363268c"
    "71d95808ff2e652600"
);

// --- Test Vector 2: 1-byte message (0x03) ---
const VEC2_SEED: [u8; 57] = hex!(
    "c4eab05d357007c632f3dbb48489924d"
    "552b08fe0c353a0d4a1f00acda2c463a"
    "fbea67c5e8d2877c5e3bc397a659949e"
    "f8021e954e0a12274e"
);
const VEC2_PK: [u8; 57] = hex!(
    "43ba28f430cdff456ae531545f7ecd0a"
    "c834a55d9358c0372bfa0c6c6798c086"
    "6aea01eb00742802b8438ea4cb82169c"
    "235160627b4c3a9480"
);
const VEC2_MSG: [u8; 1] = hex!("03");
const VEC2_SIG: [u8; 114] = hex!(
    "26b8f91727bd62897af15e41eb43c377"
    "efb9c610d48f2335cb0bd0087810f435"
    "2541b143c4b981b7e18f62de8ccdf633"
    "fc1bf037ab7cd77980"
    "5e0dbcc0aae1cbcee1afb2e027df36bc"
    "04dcecbf154336c19f0af7e0a6472905"
    "e799f1953d2a0ff3348ab21aa4adafd1"
    "d234441cf807c03a00"
);

// --- Test Vector 5: 12-byte message ---
const VEC5_SEED: [u8; 57] = hex!(
    "258cdd4ada32ed9c9ff54e63756ae582"
    "fb8fab2ac721f2c8e676a72768513d93"
    "9f63dddb55609133f29adf86ec9929dc"
    "cb52c1c5fd2ff7e21b"
);
const VEC5_PK: [u8; 57] = hex!(
    "3ba16da0c6f2cc1f30187740756f5e79"
    "8d6bc5fc015d7c63cc9510ee3fd44adc"
    "24d8e968b6e46e6f94d19b945361726b"
    "d75e149ef09817f580"
);
const VEC5_MSG: [u8; 12] = hex!("64a65f3cdedcdd66811e2915");
const VEC5_SIG: [u8; 114] = hex!(
    "7eeeab7c4e50fb799b418ee5e3197ff6"
    "bf15d43a14c34389b59dd1a7b1b85b4a"
    "e90438aca634bea45e3a2695f1270f07"
    "fdcdf7c62b8efeaf00"
    "b45c2c96ba457eb1a8bf075a3db28e5c"
    "24f6b923ed4ad747c3c9e03c7079efb8"
    "7cb110d3a99861e72003cbae6d6b8b82"
    "7e4e6c143064ff3c00"
);

fn vectors() -> Vec<Ed448Vector> {
    vec![
        Ed448Vector {
            name: "RFC 8032 §7.4 Vector 1 (empty message)",
            seed: &VEC1_SEED,
            public_key: &VEC1_PK,
            message: &[],
            signature: &VEC1_SIG,
        },
        Ed448Vector {
            name: "RFC 8032 §7.4 Vector 2 (1 byte: 0x03)",
            seed: &VEC2_SEED,
            public_key: &VEC2_PK,
            message: &VEC2_MSG,
            signature: &VEC2_SIG,
        },
        Ed448Vector {
            name: "RFC 8032 §7.4 Vector 5 (12 bytes)",
            seed: &VEC5_SEED,
            public_key: &VEC5_PK,
            message: &VEC5_MSG,
            signature: &VEC5_SIG,
        },
    ]
}

/// Verify that from_seed derives the correct public key for each RFC vector.
#[test]
fn rfc8032_pubkey_derivation() {
    for v in vectors() {
        let sk = Ed448SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));
        let vk = sk.verifying_key();
        assert_eq!(
            vk.as_bytes(),
            v.public_key,
            "{}: derived public key does not match expected",
            v.name
        );
    }
}

/// Verify that signing each RFC message produces the exact expected signature.
#[test]
fn rfc8032_sign_deterministic() {
    for v in vectors() {
        let sk = Ed448SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));

        let sig: Ed448Signature = sk.sign(v.message);
        assert_eq!(
            &sig.to_bytes(),
            v.signature,
            "{}: signature does not match RFC vector",
            v.name
        );
    }
}

/// Verify that the expected signature passes verification.
#[test]
fn rfc8032_verify_succeeds() {
    for v in vectors() {
        let sk = Ed448SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));
        let vk = sk.verifying_key();

        let sig = Ed448Signature::from_bytes(v.signature);
        vk.verify(v.message, &sig)
            .unwrap_or_else(|e| panic!("{}: verify of expected signature failed: {e}", v.name));
    }
}

/// Verify using only the public key bytes (no signing key needed).
#[test]
fn rfc8032_verify_from_pubkey_bytes() {
    for v in vectors() {
        let vk = Ed448VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let sig = Ed448Signature::from_bytes(v.signature);
        vk.verify(v.message, &sig).unwrap_or_else(|e| {
            panic!(
                "{}: verify using public-key-only construction failed: {e}",
                v.name
            )
        });
    }
}

/// Flipping a byte in the signature must cause verification to fail.
#[test]
fn rfc8032_tampered_signature_rejected() {
    for v in vectors() {
        let vk = Ed448VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let mut bad_sig_bytes = *v.signature;
        bad_sig_bytes[0] ^= 0x01;
        let bad_sig = Ed448Signature::from_bytes(&bad_sig_bytes);

        let result = vk.verify(v.message, &bad_sig);
        assert!(
            result.is_err(),
            "{}: verification must fail with tampered signature",
            v.name
        );
    }
}

/// Altering the message must cause verification to fail.
#[test]
fn rfc8032_tampered_message_rejected() {
    for v in vectors() {
        let vk = Ed448VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let sig = Ed448Signature::from_bytes(v.signature);

        let tampered_msg = if v.message.is_empty() {
            vec![0x42]
        } else {
            let mut m = v.message.to_vec();
            m[0] ^= 0xff;
            m
        };

        let result = vk.verify(&tampered_msg, &sig);
        assert!(
            result.is_err(),
            "{}: verification must fail with tampered message",
            v.name
        );
    }
}

/// Verification must fail when using a different vector's public key.
#[test]
fn rfc8032_wrong_key_rejected() {
    let sk1 =
        Ed448SigningKey::from_seed(&VEC1_SEED).expect("RFC 8032 vector 1: from_seed must succeed");
    let sig: Ed448Signature = sk1.sign(&[]);

    let wrong_vk = Ed448VerifyingKey::from_bytes(&VEC5_PK)
        .expect("RFC 8032 vector 5: from_bytes(pubkey) must succeed");

    let result = wrong_vk.verify(&[], &sig);
    assert!(
        result.is_err(),
        "RFC 8032: verification must fail when using wrong public key"
    );
}
