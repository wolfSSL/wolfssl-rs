//! Canary tests: verify that the wolf implementation isn't a no-op or
//! passthrough.  If any of these fail, the entire conformance suite is suspect.
//!
//! Each test asserts a negative property (inequality, error, non-zero) that
//! would catch a catastrophically broken implementation — e.g. an encrypt
//! that returns plaintext, a MAC that ignores the key, or an RNG that
//! emits zeros.

#[cfg(wolfssl_openssl_extra)]
#[test]
fn digest_comparison_detects_difference() {
    use digest::Digest;
    use wolfcrypt::Sha256 as WolfSha256;

    let h1 = WolfSha256::digest(b"A");
    let h2 = sha2::Sha256::digest(b"B");
    assert_ne!(
        h1.as_slice(),
        h2.as_slice(),
        "canary: different inputs must produce different SHA-256 hashes"
    );
}

#[cfg(wolfssl_openssl_extra)]
#[test]
fn digest_flip_detected() {
    use digest::Digest;
    use wolfcrypt::Sha256 as WolfSha256;

    let hash = WolfSha256::digest(b"canary flip test");
    let mut flipped = hash.to_vec();
    flipped[0] ^= 0x01;
    assert_ne!(
        hash.as_slice(),
        flipped.as_slice(),
        "canary: flipping one bit in a SHA-256 hash must produce a different value"
    );
}

#[cfg(wolfssl_aes_gcm)]
#[test]
fn aead_wrong_key_decrypt_fails() {
    use aead::{Aead, KeyInit};
    use generic_array::GenericArray;
    use rand::RngCore;
    use wolfcrypt::Aes128Gcm;

    let mut rng = rand::thread_rng();

    let mut key_a = [0u8; 16];
    let mut key_b = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut key_a);
    rng.fill_bytes(&mut key_b);
    rng.fill_bytes(&mut nonce_bytes);
    // Ensure keys differ
    key_b[0] ^= 0xFF;

    let cipher_a = Aes128Gcm::new(GenericArray::from_slice(&key_a));
    let cipher_b = Aes128Gcm::new(GenericArray::from_slice(&key_b));
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ct = cipher_a
        .encrypt(nonce, b"canary plaintext".as_ref())
        .expect("canary: encryption with key A must succeed");

    let result = cipher_b.decrypt(nonce, ct.as_ref());
    assert!(
        result.is_err(),
        "canary: decryption with wrong key must fail"
    );
}

#[cfg(wolfssl_aes_gcm)]
#[test]
fn aead_ct_not_pt() {
    use aead::{Aead, KeyInit};
    use generic_array::GenericArray;
    use rand::RngCore;
    use wolfcrypt::Aes128Gcm;

    let mut rng = rand::thread_rng();

    let mut key = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let pt = b"this plaintext must not appear in ciphertext";

    let ct = cipher
        .encrypt(nonce, pt.as_ref())
        .expect("canary: encryption must succeed");

    assert_ne!(
        &ct[..pt.len()],
        pt.as_slice(),
        "canary: ciphertext must differ from plaintext"
    );
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_hmac))]
#[test]
fn hmac_key_matters() {
    use hmac::Mac;
    use wolfcrypt::WolfHmacSha256;

    let key_a = b"canary key AAAA AAAA AAAA AAAA AA";
    let key_b = b"canary key BBBB BBBB BBBB BBBB BB";
    let msg = b"same message for both MACs";

    let mut mac_a = WolfHmacSha256::new_from_slice(key_a)
        .expect("canary: HMAC-SHA256 init with key A must succeed");
    mac_a.update(msg);
    let result_a = mac_a.finalize().into_bytes();

    let mut mac_b = WolfHmacSha256::new_from_slice(key_b)
        .expect("canary: HMAC-SHA256 init with key B must succeed");
    mac_b.update(msg);
    let result_b = mac_b.finalize().into_bytes();

    assert_ne!(
        result_a.as_slice(),
        result_b.as_slice(),
        "canary: different HMAC keys must produce different MACs on the same message"
    );
}

#[cfg(wolfssl_ed25519)]
#[test]
fn signature_not_message() {
    use rand::Rng;
    use wolfcrypt::Ed25519SigningKey;

    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let msg = b"the signature should not equal this message";

    let sk = Ed25519SigningKey::from_seed(&seed).expect("canary: Ed25519 from_seed must succeed");

    use signature::Signer as _;
    let sig: ed25519::Signature = sk.sign(msg);

    assert_ne!(
        sig.to_bytes().as_slice(),
        msg.as_slice(),
        "canary: Ed25519 signature bytes must differ from the message bytes"
    );
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]
#[test]
fn ecdsa_signature_varies() {
    use signature::Signer as _;
    use wolfcrypt::{EcdsaSignature, EcdsaSigningKey, P256};

    let sk = EcdsaSigningKey::<P256>::generate()
        .expect("canary: ECDSA P-256 key generation must succeed");
    let msg = b"ecdsa randomness canary";

    let sig1: EcdsaSignature<P256> = sk.sign(msg);
    let sig2: EcdsaSignature<P256> = sk.sign(msg);

    // ECDSA with a proper RNG should produce different signatures each time.
    assert_ne!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "canary: two ECDSA signatures on the same message must differ (randomized ECDSA)"
    );
}

#[test]
fn rng_not_zeros() {
    use rand_core::Rng;
    use wolfcrypt::WolfRng;

    let mut rng = WolfRng::new().expect("canary: WolfRng::new must succeed");
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);

    assert!(
        buf.iter().any(|&b| b != 0),
        "canary: 32 bytes from WolfRng must not all be zero"
    );
}

#[test]
fn rng_not_constant() {
    use rand_core::Rng;
    use wolfcrypt::WolfRng;

    let mut rng = WolfRng::new().expect("canary: WolfRng::new must succeed");
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    rng.fill_bytes(&mut buf1);
    rng.fill_bytes(&mut buf2);

    assert_ne!(
        buf1, buf2,
        "canary: two consecutive 32-byte outputs from WolfRng must differ"
    );
}
