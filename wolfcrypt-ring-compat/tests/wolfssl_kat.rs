// Supplemental Known Answer Tests (KATs) for the wolfSSL backend.
// Each test vector cites its normative source.

use ring::{aead, digest, hkdf, hmac, signature};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, EcdsaKeyPair, KeyPair, UnparsedPublicKey};

/// Helper: decode a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// SHA-256: NIST FIPS 180-4, Section B.1
// Input: "abc"
// Expected: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
// ---------------------------------------------------------------------------
#[test]
fn sha256_fips_180_4_b1() {
    let expected = hex_to_bytes(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    let actual = digest::digest(&digest::SHA256, b"abc");
    assert_eq!(actual.as_ref(), expected.as_slice());
}

// ---------------------------------------------------------------------------
// SHA-384: NIST FIPS 180-4, Section B.1
// Input: "abc"
// Expected: cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
//           1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7
// ---------------------------------------------------------------------------
#[test]
fn sha384_fips_180_4_b1() {
    let expected = hex_to_bytes(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    );
    let actual = digest::digest(&digest::SHA384, b"abc");
    assert_eq!(actual.as_ref(), expected.as_slice());
}

// ---------------------------------------------------------------------------
// AES-128-GCM: NIST SP 800-38D, Appendix B, Test Case 2
// Key:  00000000000000000000000000000000
// PT:   00000000000000000000000000000000
// IV:   000000000000000000000000
// CT:   0388dace60b6a392f328c2b971b2fe78
// Tag:  ab6e47d42cec13bdf53a67b21257bddf
// ---------------------------------------------------------------------------
#[test]
fn aes_128_gcm_nist_sp800_38d_test_case_2() {
    let key_bytes = [0u8; 16];
    let nonce_bytes = [0u8; 12];
    let plaintext = [0u8; 16];
    let expected_ct = hex_to_bytes("0388dace60b6a392f328c2b971b2fe78");
    let expected_tag = hex_to_bytes("ab6e47d42cec13bdf53a67b21257bddf");

    // Seal (encrypt)
    let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes).unwrap();
    let less_safe_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();

    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .unwrap();

    let tag_len = aead::AES_128_GCM.tag_len();
    let (ct, tag) = in_out.split_at(in_out.len() - tag_len);
    assert_eq!(ct, expected_ct.as_slice());
    assert_eq!(tag, expected_tag.as_slice());

    // Open (decrypt) to verify round-trip
    let unbound_key2 = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes).unwrap();
    let less_safe_key2 = aead::LessSafeKey::new(unbound_key2);
    let nonce2 = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let decrypted = less_safe_key2
        .open_in_place(nonce2, aead::Aad::empty(), &mut in_out)
        .unwrap();
    assert_eq!(decrypted, &plaintext);
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256: RFC 4231, Test Case 2
// Key:  "Jefe"
// Data: "what do ya want for nothing?"
// Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
// ---------------------------------------------------------------------------
#[test]
fn hmac_sha256_rfc4231_test_case_2() {
    let expected = hex_to_bytes(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
    let tag = hmac::sign(&key, b"what do ya want for nothing?");
    assert_eq!(tag.as_ref(), expected.as_slice());

    // Also verify
    hmac::verify(&key, b"what do ya want for nothing?", &expected).unwrap();
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256: RFC 5869, Test Case 1
// IKM:  0x0b repeated 22 times
// Salt: 0x000102030405060708090a0b0c (13 octets)
// Info: 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
// L:    42
// OKM:  3cb25f25faacd57a90434f64d0362f2a
//       2d2d0a90cf1a5a4c5db02d56ecc4c5bf
//       34007208d5b887185865
// ---------------------------------------------------------------------------
#[test]
fn hkdf_sha256_rfc5869_test_case_1() {
    let ikm = vec![0x0bu8; 22];
    let salt_bytes = hex_to_bytes("000102030405060708090a0b0c");
    let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
    );

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(&ikm);

    let mut okm_bytes = vec![0u8; 42];
    let info_slice = [info.as_slice()];
    let okm = prk
        .expand(&info_slice, HkdfLen(42))
        .unwrap();
    okm.fill(&mut okm_bytes).unwrap();

    assert_eq!(okm_bytes, expected_okm);
}

/// Wrapper type for HKDF output length.
#[derive(Debug, PartialEq)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256: FIPS 186-4
// Generate a key, sign a message, verify the signature.
// ---------------------------------------------------------------------------
#[test]
fn ecdsa_p256_sign_verify_fips186_4() {
    let rng = SystemRandom::new();
    let pkcs8_doc =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_doc.as_ref(),
    )
    .unwrap();

    let msg = b"FIPS 186-4 ECDSA P-256 sign/verify test";
    let sig = key_pair.sign(&rng, msg).unwrap();

    // Verify with the public key
    let public_key = key_pair.public_key();
    let upk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key.as_ref());
    upk.verify(msg, sig.as_ref()).unwrap();

    // Verify that a tampered message fails
    let bad_msg = b"FIPS 186-4 ECDSA P-256 sign/verify TAMPERED";
    assert!(upk.verify(bad_msg, sig.as_ref()).is_err());
}

// ---------------------------------------------------------------------------
// Ed25519: RFC 8032, Section 7.1, Test Vector 1
// Seed:      9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
// Public key (per existing BoringSSL-compatible test vectors):
//            d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
// Message:   "" (empty)
// Signature: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
//
// Note: The public key and signature are taken from the BoringSSL test vectors
// that use this same seed. The signature value matches RFC 8032, Section 7.1,
// Test Vector 1.
// ---------------------------------------------------------------------------
#[test]
fn ed25519_rfc8032_test_vector_1() {
    let seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pub = hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_sig = hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();

    // Verify public key derived from seed
    assert_eq!(key_pair.public_key().as_ref(), expected_pub.as_slice());

    // Sign the empty message and verify against known signature
    let sig = key_pair.sign(b"");
    assert_eq!(sig.as_ref(), expected_sig.as_slice());

    // Verify the signature using the public key
    let upk = UnparsedPublicKey::new(&signature::ED25519, &expected_pub);
    upk.verify(b"", sig.as_ref()).unwrap();
}
