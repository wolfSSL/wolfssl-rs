//! wolfHSM integration tests.
//!
//! These tests require a running wolfHSM server.  Set the `WOLFHSM_SERVER`
//! environment variable to the server address before running:
//!
//! - `/path/to/socket` — Unix Domain Socket (path starts with `/`)
//! - `host:port`       — TCP (e.g. `127.0.0.1:8080`)
//!
//! Every test silently returns (is skipped) when `WOLFHSM_SERVER` is unset.

use wolfhsm::{Client, Transport, WolfHsmError};
use wolfhsm::crypto::{
    aes::AesKey,
    cmac::CmacKey,
    ecc::EccP256Key,
    ed25519::Ed25519Key,
    curve25519::Curve25519Key,
    rsa::{RsaKey, RsaRawOp},
};
use wolfhsm::nvm::NvmId;
use hex_literal::hex;

// ── Server connection helper ──────────────────────────────────────────────────

fn connect_or_skip() -> Option<Client> {
    let server = std::env::var("WOLFHSM_SERVER").ok()?;
    let transport = if server.starts_with('/') {
        Transport::Uds { path: server }
    } else {
        let (ip, port_str) = server.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        Transport::Tcp { ip: ip.to_string(), port }
    };
    Client::connect(transport, 1).ok()
}

/// Early-return (skip) the test if `WOLFHSM_SERVER` is not set.
macro_rules! require_client {
    ($name:ident) => {
        let mut $name = match connect_or_skip() {
            Some(c) => c,
            None => return,
        };
    };
}

// ── Connectivity ──────────────────────────────────────────────────────────────

#[test]
fn connect_echo() {
    require_client!(client);
    let msg = b"hello wolfhsm";
    let mut buf = [0u8; 32];
    let n = client.echo(msg, &mut buf).expect("echo");
    assert_eq!(&buf[..n], msg);
}

#[test]
fn server_info() {
    require_client!(client);
    let info = client.info().expect("info");
    // Any real wolfHSM server reports a non-zero version or build number.
    assert!(
        info.version > 0 || info.build > 0,
        "server returned all-zero version/build: {info:?}",
    );
}

// ── RNG ───────────────────────────────────────────────────────────────────────

#[test]
fn rng_nonzero() {
    require_client!(client);
    let bytes = client.rng_generate(32).expect("rng generate");
    assert_eq!(bytes.len(), 32);
    // 32 random bytes that are all-zero indicates a broken RNG.
    assert_ne!(bytes, vec![0u8; 32], "RNG returned 32 zero bytes");
}

// ── Key cache ─────────────────────────────────────────────────────────────────

#[test]
fn key_cache_and_evict() {
    require_client!(client);
    let key = AesKey::cache(&mut client, &[0u8; 32]).expect("key_cache");
    key.evict(&mut client).expect("key_evict");
}

// ── NVM ───────────────────────────────────────────────────────────────────────

// Each test uses a distinct NVM ID to avoid interference when tests run in parallel.
const NVM_ID_RW: NvmId = NvmId(0x4242);
const NVM_ID_LIST: NvmId = NvmId(0x4244);

#[test]
fn nvm_available_returns_space() {
    require_client!(client);
    let avail = client.nvm_available().expect("nvm_available");
    // Sanity check: the server reports some available or reclaimable space.
    assert!(
        avail.avail_size > 0 || avail.reclaim_size > 0,
        "NVM reports no space at all: {avail:?}",
    );
}

#[test]
fn nvm_write_read_delete() {
    require_client!(client);
    let data = b"integration test payload";
    // Remove any leftover object from a previous failed run.
    let _ = client.nvm_delete(NVM_ID_RW);
    client.nvm_write(NVM_ID_RW, 0, 0, b"test", data).expect("nvm_write");
    let read = client.nvm_read(NVM_ID_RW, 0).expect("nvm_read");
    assert_eq!(read, data);
    client.nvm_delete(NVM_ID_RW).expect("nvm_delete");
}

#[test]
fn nvm_list_contains_written_object() {
    require_client!(client);
    let _ = client.nvm_delete(NVM_ID_LIST);
    client.nvm_write(NVM_ID_LIST, 0, 0, b"list-test", b"payload").expect("nvm_write");
    let ids = client.nvm_list().expect("nvm_list");
    assert!(
        ids.contains(&NVM_ID_LIST),
        "written NVM ID not found in list: {ids:?}",
    );
    client.nvm_delete(NVM_ID_LIST).expect("nvm_delete cleanup");
}

// ── Counter ───────────────────────────────────────────────────────────────────

const COUNTER_ID: NvmId = NvmId(0x4243);

#[test]
fn counter_lifecycle() {
    require_client!(client);
    // Remove any leftover counter from a previous failed run.
    let _ = client.counter_destroy(COUNTER_ID);

    let v0 = client.counter_init(COUNTER_ID, 5).expect("counter_init");
    assert_eq!(v0, 5);

    let v1 = client.counter_increment(COUNTER_ID).expect("counter_increment");
    assert_eq!(v1, 6);

    let v2 = client.counter_read(COUNTER_ID).expect("counter_read");
    assert_eq!(v2, 6);

    let v3 = client.counter_reset(COUNTER_ID).expect("counter_reset");
    assert_eq!(v3, 0);

    client.counter_destroy(COUNTER_ID).expect("counter_destroy");
}

// ── SHA-256 (NIST FIPS 180-4) ─────────────────────────────────────────────────

#[test]
fn sha256_nist_abc() {
    require_client!(client);
    // NIST FIPS 180-4 SHA-256("abc")
    let expected = hex!("ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469121b9e42a45b6b0d5");
    let got = client.sha256(b"abc").expect("sha256");
    assert_eq!(got, expected);
}

// ── CMAC (NIST SP 800-38B, Example 1) ────────────────────────────────────────

#[test]
fn cmac_nist_empty_message() {
    require_client!(client);
    // NIST SP 800-38B AES-128 CMAC, Key1, empty message → Example 1
    let key_bytes = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let expected  = hex!("bb1d6929e95937287fa37d129b756746");
    let key = CmacKey::cache(&mut client, &key_bytes).expect("cmac cache");
    let tag = key.compute(&mut client, b"").expect("cmac compute");
    key.evict(&mut client).expect("cmac evict");
    assert_eq!(tag, expected);
}

// ── AES-GCM (NIST SP 800-38D, Test Case 13) ──────────────────────────────────

#[test]
fn aes_gcm_nist_empty_plaintext() {
    require_client!(client);
    // NIST SP 800-38D AES-256-GCM test case 13:
    //   Key = 0x00…00 (32 bytes), IV = 0x00…00 (12 bytes), PT/AAD = empty
    //   Expected AT = 530f8afbc74536b9a963b4f1c4cb738b
    let key_bytes    = [0u8; 32];
    let iv           = [0u8; 12];
    let expected_tag = hex!("530f8afbc74536b9a963b4f1c4cb738b");

    let key = AesKey::cache(&mut client, &key_bytes).expect("aes cache");
    let (ct, tag) = key.gcm_encrypt(&mut client, &iv, &[], &[]).expect("gcm_encrypt");
    key.evict(&mut client).expect("aes evict");

    assert!(ct.is_empty(), "ciphertext of empty plaintext must be empty");
    assert_eq!(tag, expected_tag);
}

// ── ECC P-256: sign/verify cross-validation ───────────────────────────────────
//
// wolfHSM signs a SHA-256 digest; the p256 crate independently verifies.

#[test]
fn ecc_p256_sign_verify_cross() {
    require_client!(client);
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};

    let key = EccP256Key::generate(&mut client).expect("ecc generate");
    let msg    = b"cross-validation: wolfhsm signs, p256 verifies";
    let digest: [u8; 32] = Sha256::digest(msg).into();

    let sig_der = key.sign_digest(&mut client, &digest).expect("ecc sign_digest");
    let pub_der = key.public_key_der(&mut client).expect("ecc public_key_der");
    key.evict(&mut client).expect("ecc evict");

    let vk  = VerifyingKey::from_public_key_der(&pub_der)
        .expect("p256: parse SubjectPublicKeyInfo DER");
    let sig = Signature::from_der(&sig_der)
        .expect("p256: parse DER-encoded ECDSA signature");
    vk.verify_prehash(&digest, &sig)
        .expect("p256: verify_prehash failed — wolfhsm/p256 cross-validation error");
}

// ── ECC P-256: ECDH cross-validation ─────────────────────────────────────────
//
// wolfHSM computes ECDH with a p256-generated public key; the p256 crate
// computes ECDH from the other direction; shared secrets must agree.

#[test]
fn ecc_p256_ecdh_cross() {
    require_client!(client);
    use p256::{PublicKey, ecdh::EphemeralSecret};
    use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
    use rand::rngs::OsRng;

    let hsm_key = EccP256Key::generate(&mut client).expect("ecc generate");

    // Local side: generate a p256 ephemeral key pair.
    let local_secret = EphemeralSecret::random(&mut OsRng);
    let local_pub_key = local_secret.public_key();
    let local_pub_der = local_pub_key
        .to_public_key_der()
        .expect("p256: encode SubjectPublicKeyInfo DER");

    // HSM side: ECDH with the local public key.
    let hsm_shared = hsm_key
        .ecdh(&mut client, local_pub_der.as_bytes())
        .expect("ecc ecdh");

    // Export HSM public key for local ECDH computation.
    let hsm_pub_der = hsm_key.public_key_der(&mut client).expect("ecc public_key_der");
    hsm_key.evict(&mut client).expect("ecc evict");

    // Local side: ECDH with the HSM public key.
    let hsm_public = PublicKey::from_public_key_der(&hsm_pub_der)
        .expect("p256: parse HSM SubjectPublicKeyInfo DER");
    let local_shared = local_secret.diffie_hellman(&hsm_public);

    assert_eq!(
        hsm_shared.as_slice(),
        local_shared.raw_secret_bytes().as_slice(),
        "ECDH shared secrets do not match",
    );
}

// ── Ed25519: sign/verify cross-validation ─────────────────────────────────────
//
// wolfHSM signs; ed25519-dalek independently verifies.

#[test]
fn ed25519_sign_verify_cross() {
    require_client!(client);
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = Ed25519Key::generate(&mut client).expect("ed25519 generate");
    let msg = b"cross-validation: wolfhsm signs, ed25519-dalek verifies";

    let sig_bytes = key.sign(&mut client, msg).expect("ed25519 sign");
    let pub_bytes = key.public_key(&mut client).expect("ed25519 public_key");
    key.evict(&mut client).expect("ed25519 evict");

    let vk  = VerifyingKey::from_bytes(&pub_bytes)
        .expect("ed25519-dalek: parse public key bytes");
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(msg, &sig)
        .expect("ed25519-dalek: verify failed — wolfhsm/ed25519-dalek cross-validation error");
}

// ── Curve25519 / X25519: ECDH cross-validation ───────────────────────────────
//
// wolfHSM computes DH with an x25519-dalek public key; the dalek crate computes
// DH from the other direction; shared secrets must agree.

#[test]
fn curve25519_x25519_ecdh_cross() {
    require_client!(client);
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    let hsm_key = Curve25519Key::generate(&mut client).expect("curve25519 generate");

    // Local side: generate an x25519 static secret.
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let local_public = PublicKey::from(&local_secret);

    // HSM side: DH with the local public key (little-endian bytes).
    let hsm_shared = hsm_key
        .diffie_hellman(&mut client, local_public.as_bytes())
        .expect("curve25519 diffie_hellman");

    // Export HSM public key for local DH computation.
    let hsm_pub_bytes = hsm_key.public_key(&mut client).expect("curve25519 public_key");
    hsm_key.evict(&mut client).expect("curve25519 evict");

    // Local side: DH with the HSM public key.
    let hsm_public = PublicKey::from(hsm_pub_bytes);
    let local_shared = local_secret.diffie_hellman(&hsm_public);

    assert_eq!(
        hsm_shared,
        *local_shared.as_bytes(),
        "X25519 shared secrets do not match",
    );
}

// ── RSA: encrypt/decrypt; PublicEncrypt cross-validated against pure Rust ────

#[test]
fn rsa_round_trip() {
    require_client!(client);
    // RSA-1024 for faster key generation during testing.
    let key = RsaKey::generate(&mut client, 1024, 65537).expect("rsa generate");
    let key_bytes = key.key_size_bytes() as usize;

    // Build a valid raw RSA input: zero-padded, small value, guaranteed < n.
    let mut msg = vec![0u8; key_bytes];
    msg[key_bytes - 1] = 0x42;

    let ciphertext = key
        .raw_op(&mut client, RsaRawOp::PublicEncrypt, &msg)
        .expect("rsa PublicEncrypt");

    // Cross-validate PublicEncrypt against pure Rust: export the public key
    // (n, e) and independently compute m^e mod n.  This ensures the HSM
    // produces a standard RSA result, not merely one it can reverse itself.
    {
        use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, BigUint, RsaPublicKey};

        let pub_der = key.public_key_der(&mut client).expect("export public key DER");
        let pub_key = RsaPublicKey::from_public_key_der(&pub_der)
            .expect("parse public key DER");
        let m_big = BigUint::from_bytes_be(&msg);
        let c_expected = m_big.modpow(pub_key.e(), pub_key.n());
        // BigUint strips leading zeros; restore to key length.
        let mut c_expected_bytes = c_expected.to_bytes_be();
        while c_expected_bytes.len() < key_bytes {
            c_expected_bytes.insert(0, 0);
        }
        assert_eq!(
            ciphertext, c_expected_bytes,
            "HSM PublicEncrypt mismatch vs pure-Rust m^e mod n"
        );
    }

    let plaintext = key
        .raw_op(&mut client, RsaRawOp::PrivateDecrypt, &ciphertext)
        .expect("rsa PrivateDecrypt");
    key.evict(&mut client).expect("rsa evict");

    assert_eq!(plaintext, msg, "RSA round-trip plaintext mismatch");
}

// ── ML-DSA: sign/verify round-trip (no independent oracle; feature-gated) ─────

#[cfg(feature = "mldsa")]
#[test]
fn mldsa_round_trip() {
    require_client!(client);
    use wolfhsm::crypto::mldsa::MlDsaKey;

    let key = MlDsaKey::generate(&mut client, 44).expect("mldsa generate level=44");
    let msg = b"ML-DSA level-44 round-trip test";
    let sig = key.sign(&mut client, msg).expect("mldsa sign");
    key.verify(&mut client, msg, &sig).expect("mldsa verify");
    key.evict(&mut client).expect("mldsa evict");
}

// ── CryptoCb: registration / guard lifecycle ─────────────────────────────────
//
// Verifies the RAII guard prevents double-registration and correctly
// unregisters on drop.  Requires two separate Client connections.

#[test]
fn cryptocb_register_lifecycle() {
    let mut client1 = match connect_or_skip() { Some(c) => c, None => return };
    let mut client2 = match connect_or_skip() { Some(c) => c, None => return };

    // First registration succeeds.
    let guard1 = client1.register_cryptocb().expect("first registration");

    // While guard1 is alive, a second registration must be rejected.
    match client2.register_cryptocb() {
        Err(WolfHsmError::AlreadyRegistered) => {}
        Err(e) => panic!("expected AlreadyRegistered, got Err: {e}"),
        Ok(_) => panic!("expected Err(AlreadyRegistered), got Ok"),
    }

    // Dropping the guard unregisters; client2 can now register.
    drop(guard1);
    let guard2 = client2.register_cryptocb()
        .expect("re-registration after guard drop");
    drop(guard2);
}
