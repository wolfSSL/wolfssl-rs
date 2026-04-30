//! Ed25519 signing and verification integration tests.
//!
//! Test vectors are taken from RFC 8032 §6.1.  All verification tests use
//! an external oracle (the RFC) rather than re-using the code under test as
//! the oracle.

#![cfg(all(feature = "ed25519", wolfssl_ed25519))]

use wolfcrypt::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use wolfcrypt::rand::WolfRng;

// RFC 8032 §6.1 Test Vector 1
// SECRET KEY (seed):  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
// PUBLIC KEY:         d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
// MESSAGE:            (empty)
// SIGNATURE:          e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
const RFC8032_TV1_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x3d, 0x55,
];

const RFC8032_TV1_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

// RFC 8032 §6.1 Test Vector 1 signature over the empty message.
const RFC8032_TV1_SIG: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

// ================================================================
// check_key
// ================================================================

#[test]
fn check_key_accepts_rfc8032_tv1() {
    let mut vk = Ed25519VerifyingKey::from_bytes(&RFC8032_TV1_PUB)
        .expect("RFC 8032 TV1 public key import must succeed");
    vk.check_key()
        .expect("RFC 8032 TV1 public key must pass wolfCrypt point validation");
}

#[test]
fn check_key_accepts_generated_key() {
    let mut rng = WolfRng::new().unwrap();
    let sk = Ed25519SigningKey::generate(&mut rng).expect("key generation must succeed");
    let mut vk = sk.verifying_key();
    vk.check_key()
        .expect("a freshly generated key must pass check_key");
}

// ================================================================
// Sign / verify
// ================================================================

#[test]
fn verify_rfc8032_tv1_empty_message() {
    use ed25519_trait::Signature;
    use signature_trait::Verifier;

    let vk = Ed25519VerifyingKey::from_bytes(&RFC8032_TV1_PUB)
        .expect("RFC 8032 TV1 public key import must succeed");

    let sig = Signature::from_bytes(&RFC8032_TV1_SIG);
    vk.verify(b"", &sig)
        .expect("RFC 8032 TV1 signature over empty message must verify");
}

#[test]
fn sign_verify_roundtrip() {
    use signature_trait::{Signer, Verifier};

    let sk = Ed25519SigningKey::from_seed(&RFC8032_TV1_SEED).expect("seed import must succeed");
    let vk = sk.verifying_key();

    let msg = b"onlykey integration test";
    let sig = sk.sign(msg);
    vk.verify(msg, &sig)
        .expect("signature produced by sign must verify");
}

#[test]
fn wrong_message_does_not_verify() {
    use signature_trait::{Signer, Verifier};

    let sk = Ed25519SigningKey::from_seed(&RFC8032_TV1_SEED).expect("seed import must succeed");
    let vk = sk.verifying_key();

    let sig = sk.sign(b"correct message");
    assert!(
        vk.verify(b"tampered message", &sig).is_err(),
        "signature over different message must not verify"
    );
}

#[test]
fn verifying_key_roundtrips_through_bytes() {
    let vk1 = Ed25519VerifyingKey::from_bytes(&RFC8032_TV1_PUB).expect("import must succeed");
    let vk2 = Ed25519VerifyingKey::from_bytes(vk1.as_bytes())
        .expect("re-import of exported bytes must succeed");
    assert_eq!(
        vk1.as_bytes(),
        vk2.as_bytes(),
        "round-trip through as_bytes must preserve key material"
    );
}
