//! RSA OAEP and PKCS#1 v1.5 encryption/decryption tests for wolfcrypt.
//!
//! Tests verify round-trip correctness and error handling per RFC 8017
//! (PKCS#1 v2.2) Sections 7.1 (OAEP) and 7.2 (PKCS1-v1_5).

use wolfcrypt::rsa::RsaPrivateKey;

/// Generate a fresh 2048-bit RSA keypair.
fn gen_key() -> RsaPrivateKey {
    RsaPrivateKey::generate(2048).expect("RSA 2048-bit key generation failed")
}

// ===========================================================================
// Section 1: OAEP round-trip (RFC 8017 Section 7.1)
// ===========================================================================

/// Encrypt with OAEP/SHA-256 then decrypt — plaintext must be recovered.
#[test]
fn oaep_round_trip() {
    let sk = gen_key();
    let plaintext = b"RFC 8017 Section 7.1 - OAEP round-trip test";

    let ciphertext = sk.encrypt_oaep(plaintext).unwrap();
    let recovered = sk.decrypt_oaep(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), &recovered[..]);
}

// ===========================================================================
// Section 2: PKCS#1 v1.5 round-trip (RFC 8017 Section 7.2)
// ===========================================================================

/// Encrypt with PKCS#1 v1.5 then decrypt — plaintext must be recovered.
#[test]
fn pkcs1v15_round_trip() {
    let sk = gen_key();
    let plaintext = b"RFC 8017 Section 7.2 - PKCS1v15 round-trip test";

    let ciphertext = sk.encrypt_pkcs1v15(plaintext).unwrap();
    let recovered = sk.decrypt_pkcs1v15(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), &recovered[..]);
}

// ===========================================================================
// Section 3: OAEP ciphertext is randomized
// ===========================================================================

/// OAEP encryption is randomized: encrypting the same plaintext twice must
/// produce different ciphertexts (with overwhelming probability).
#[test]
fn oaep_ciphertext_is_randomized() {
    let sk = gen_key();
    let plaintext = b"randomization check";

    let ct1 = sk.encrypt_oaep(plaintext).unwrap();
    let ct2 = sk.encrypt_oaep(plaintext).unwrap();
    assert_ne!(
        ct1, ct2,
        "OAEP ciphertexts should differ due to randomized padding"
    );
}

// ===========================================================================
// Section 4: Wrong key rejection
// ===========================================================================

/// Encrypt with key A, decrypt with key B — must fail.
#[test]
fn oaep_wrong_key_rejected() {
    let sk_a = gen_key();
    let sk_b = gen_key();
    let plaintext = b"wrong key rejection test";

    let ciphertext = sk_a.encrypt_oaep(plaintext).unwrap();
    let result = sk_b.decrypt_oaep(&ciphertext);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

/// PKCS#1 v1.5: encrypt with key A, decrypt with key B — must fail.
#[test]
fn pkcs1v15_wrong_key_rejected() {
    let sk_a = gen_key();
    let sk_b = gen_key();
    let plaintext = b"wrong key rejection test pkcs1v15";

    let ciphertext = sk_a.encrypt_pkcs1v15(plaintext).unwrap();
    let result = sk_b.decrypt_pkcs1v15(&ciphertext);
    assert!(
        result.is_err(),
        "PKCS#1v1.5 decryption with wrong key should fail"
    );
}

// ===========================================================================
// Section 5: Max plaintext size for OAEP/SHA-256 with 2048-bit key
// ===========================================================================

/// For a 2048-bit RSA key with OAEP, the max plaintext is bounded by
/// modulus_bytes - 2*hash_len - 2 (RFC 8017 Section 7.1.1 step 1.b).
/// With SHA-256 this is 190 bytes; with SHA-1 (wolfSSL default) it is 214.
/// We test that 190 bytes always works and that 246 bytes (exceeding even
/// PKCS#1 v1.5 capacity) is rejected.
#[test]
fn oaep_max_plaintext_size() {
    let sk = gen_key();

    // 190 bytes should always succeed regardless of OAEP hash.
    let pt_190 = vec![0x42u8; 190];
    let ct = sk.encrypt_oaep(&pt_190).unwrap();
    let recovered = sk.decrypt_oaep(&ct).unwrap();
    assert_eq!(pt_190, recovered);

    // 246 bytes exceeds the modulus capacity and must fail.
    let pt_246 = vec![0x42u8; 246];
    let result = sk.encrypt_oaep(&pt_246);
    assert!(
        result.is_err(),
        "OAEP with 246-byte plaintext on 2048-bit key should fail"
    );
}

// ===========================================================================
// Section 6: Public-key-only encryption via RsaPublicKey
// ===========================================================================

/// Encrypt with the public key, decrypt with the private key.
#[test]
fn oaep_encrypt_with_public_key() {
    let sk = gen_key();
    let vk = sk.public_key();
    let plaintext = b"public-key encryption test";

    let ciphertext = vk.encrypt_oaep(plaintext).unwrap();
    let recovered = sk.decrypt_oaep(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), &recovered[..]);
}

/// PKCS#1 v1.5: encrypt with public key, decrypt with private key.
#[test]
fn pkcs1v15_encrypt_with_public_key() {
    let sk = gen_key();
    let vk = sk.public_key();
    let plaintext = b"public-key pkcs1v15 encryption test";

    let ciphertext = vk.encrypt_pkcs1v15(plaintext).unwrap();
    let recovered = sk.decrypt_pkcs1v15(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), &recovered[..]);
}
