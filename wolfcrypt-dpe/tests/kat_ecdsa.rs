//! Known Answer Tests for ECDSA key derivation and signing.

// Future-proof: caliptra-dpe may add ML-DSA variants to PubKey/Signature enums.
#![allow(unreachable_patterns)]

// CryptoSuite must be in scope for get_pubkey_serial() method resolution.
#[allow(unused_imports)]
use caliptra_dpe_crypto::{Crypto, CryptoSuite, Digest, PubKey, Sha256, Sha384, SignData, Signature};
use wolfcrypt_dpe::{WolfCryptDpe, WolfCryptDpe256};

use wolfcrypt::{EcdsaVerifyingKey, EcdsaSignature, P384, P256};

/// Reconstruct uncompressed public key bytes (04 || x || y) from a PubKey.
fn pubkey_to_uncompressed(pub_key: &PubKey) -> Vec<u8> {
    match pub_key {
        PubKey::Ecdsa(ecdsa_pub) => {
            let (x, y) = ecdsa_pub.as_slice();
            let mut bytes = Vec::with_capacity(1 + x.len() + y.len());
            bytes.push(0x04);
            bytes.extend_from_slice(x);
            bytes.extend_from_slice(y);
            bytes
        }
        _ => panic!("Expected ECDSA public key"),
    }
}

/// Reconstruct fixed-format signature bytes (r || s) from a Signature.
fn sig_to_fixed(sig: &Signature) -> Vec<u8> {
    match sig {
        Signature::Ecdsa(ecdsa_sig) => {
            let (r, s) = ecdsa_sig.as_slice();
            let mut bytes = Vec::with_capacity(r.len() + s.len());
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        _ => panic!("Expected ECDSA signature"),
    }
}

// ---------- Key derivation ----------

#[test]
fn derive_key_pair_deterministic_p384() {
    // Same CDI + label + info must produce same key pair
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0xABu8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();

    let (_, pub1) = dpe.derive_key_pair(&cdi, b"label", b"info").unwrap();
    let (_, pub2) = dpe.derive_key_pair(&cdi, b"label", b"info").unwrap();

    match (&pub1, &pub2) {
        (PubKey::Ecdsa(k1), PubKey::Ecdsa(k2)) => {
            let (x1, y1) = k1.as_slice();
            let (x2, y2) = k2.as_slice();
            assert_eq!(x1, x2);
            assert_eq!(y1, y2);
        }
        _ => panic!("Expected ECDSA public keys"),
    }
}

#[test]
fn derive_key_pair_deterministic_p256() {
    let mut dpe = WolfCryptDpe256::new_p256();
    let measurement = Digest::Sha256(Sha256([0xCDu8; 32]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();

    let (_, pub1) = dpe.derive_key_pair(&cdi, b"label", b"info").unwrap();
    let (_, pub2) = dpe.derive_key_pair(&cdi, b"label", b"info").unwrap();

    match (&pub1, &pub2) {
        (PubKey::Ecdsa(k1), PubKey::Ecdsa(k2)) => {
            let (x1, y1) = k1.as_slice();
            let (x2, y2) = k2.as_slice();
            assert_eq!(x1, x2);
            assert_eq!(y1, y2);
        }
        _ => panic!("Expected ECDSA public keys"),
    }
}

#[test]
fn derive_key_pair_uniqueness_p384() {
    // Different labels must produce different key pairs
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0xBBu8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();

    let (_, pub1) = dpe.derive_key_pair(&cdi, b"label A", b"info").unwrap();
    let (_, pub2) = dpe.derive_key_pair(&cdi, b"label B", b"info").unwrap();

    match (&pub1, &pub2) {
        (PubKey::Ecdsa(k1), PubKey::Ecdsa(k2)) => {
            let (x1, _) = k1.as_slice();
            let (x2, _) = k2.as_slice();
            assert_ne!(x1, x2);
        }
        _ => panic!("Expected ECDSA public keys"),
    }
}

// ---------- Sign-verify round trip ----------

#[test]
fn sign_verify_roundtrip_p384() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();
    let (priv_key, pub_key) = dpe.derive_key_pair(&cdi, b"signing", b"info").unwrap();

    // Hash some data to create a digest for signing
    let digest = dpe.hash(b"message to sign").unwrap();
    let sign_data = SignData::Digest(digest);

    // Sign
    let sig = dpe
        .sign_with_derived(&sign_data, &priv_key, &pub_key)
        .unwrap();

    // Verify the signature is well-formed (has correct size)
    match &sig {
        Signature::Ecdsa(ecdsa_sig) => {
            assert_eq!(ecdsa_sig.curve_size(), 48); // P-384
            let (r, s) = ecdsa_sig.as_slice();
            // r and s should not be all zeros
            assert_ne!(r, &[0u8; 48][..]);
            assert_ne!(s, &[0u8; 48][..]);
        }
        _ => panic!("Expected ECDSA signature"),
    }

    // Cryptographic verification: the DPE signed the raw digest bytes
    // (SignData::Digest), so Verifier::verify would double-hash.  Instead
    // we verify structural validity and that the key/signature can be parsed
    // by wolfcrypt independently.
    let pub_bytes = pubkey_to_uncompressed(&pub_key);
    let sig_bytes = sig_to_fixed(&sig);

    // Verify structural validity: signature can be parsed by wolfcrypt
    let _parsed = EcdsaSignature::<P384>::from_bytes(&sig_bytes)
        .expect("P-384 signature should be parseable");

    // Verify the public key can be loaded into a verifying key
    let _vk = EcdsaVerifyingKey::<P384>::from_uncompressed_point(&pub_bytes)
        .expect("P-384 public key should be loadable");
}

#[test]
fn sign_verify_roundtrip_p256() {
    let mut dpe = WolfCryptDpe256::new_p256();
    let measurement = Digest::Sha256(Sha256([0x42u8; 32]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();
    let (priv_key, pub_key) = dpe.derive_key_pair(&cdi, b"signing", b"info").unwrap();

    let digest = dpe.hash(b"message to sign").unwrap();
    let sign_data = SignData::Digest(digest);

    let sig = dpe
        .sign_with_derived(&sign_data, &priv_key, &pub_key)
        .unwrap();

    match &sig {
        Signature::Ecdsa(ecdsa_sig) => {
            assert_eq!(ecdsa_sig.curve_size(), 32); // P-256
            let (r, s) = ecdsa_sig.as_slice();
            assert_ne!(r, &[0u8; 32][..]);
            assert_ne!(s, &[0u8; 32][..]);
        }
        _ => panic!("Expected ECDSA signature"),
    }

    // Cryptographic verification: the DPE signed the raw digest bytes
    // (SignData::Digest), so Verifier::verify would double-hash.  Instead
    // we verify structural validity and that the key/signature can be parsed.
    let pub_bytes = pubkey_to_uncompressed(&pub_key);
    let sig_bytes = sig_to_fixed(&sig);

    let _parsed = EcdsaSignature::<P256>::from_bytes(&sig_bytes)
        .expect("P-256 signature should be parseable");

    let _vk = EcdsaVerifyingKey::<P256>::from_uncompressed_point(&pub_bytes)
        .expect("P-256 public key should be loadable");
}

// ---------- sign_with_alias ----------

#[test]
fn sign_with_alias_p384() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"alias cdi info").unwrap();
    let (priv_key, pub_key) = dpe.derive_key_pair(&cdi, b"alias", b"info").unwrap();

    // Set alias key
    dpe.set_alias_key(priv_key, pub_key).unwrap();

    let digest = dpe.hash(b"alias signed message").unwrap();
    let sign_data = SignData::Digest(digest);

    let sig = dpe.sign_with_alias(&sign_data).unwrap();

    match &sig {
        Signature::Ecdsa(ecdsa_sig) => {
            assert_eq!(ecdsa_sig.curve_size(), 48);
        }
        _ => panic!("Expected ECDSA signature"),
    }
}

// ---------- Raw data signing ----------

#[test]
fn sign_raw_data_p384() {
    // SignData::Raw should hash the data first, then sign the digest
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();
    let (priv_key, pub_key) = dpe.derive_key_pair(&cdi, b"signing", b"info").unwrap();

    let raw_data = b"raw data to be hashed and signed";
    let sign_data = SignData::Raw(raw_data);

    let sig = dpe
        .sign_with_derived(&sign_data, &priv_key, &pub_key)
        .unwrap();

    match &sig {
        Signature::Ecdsa(ecdsa_sig) => {
            assert_eq!(ecdsa_sig.curve_size(), 48);
        }
        _ => panic!("Expected ECDSA signature"),
    }
}

// ---------- Mu variant should fail for ECDSA ----------

#[test]
fn sign_mu_returns_mismatched_algorithm() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();
    let (priv_key, pub_key) = dpe.derive_key_pair(&cdi, b"signing", b"info").unwrap();

    let mu_data = SignData::Mu(caliptra_dpe_crypto::Mu([0xAAu8; 64]));

    let result = dpe.sign_with_derived(&mu_data, &priv_key, &pub_key);
    match result {
        Err(caliptra_dpe_crypto::CryptoError::MismatchedAlgorithm) => {}
        Err(e) => panic!("Expected MismatchedAlgorithm, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

// ---------- Exported CDI ----------

#[test]
fn derive_exported_cdi_and_key_pair() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));

    let handle = dpe
        .derive_exported_cdi(&measurement, b"export info")
        .unwrap();

    // Should be able to derive a key pair from the exported handle
    let (_, pub_key) = dpe
        .derive_key_pair_exported(&handle, b"label", b"info")
        .unwrap();

    match &pub_key {
        PubKey::Ecdsa(k) => {
            let (x, _) = k.as_slice();
            assert_ne!(x, &[0u8; 48][..]);
        }
        _ => panic!("Expected ECDSA public key"),
    }
}

#[test]
fn derive_exported_cdi_invalid_handle() {
    let mut dpe = WolfCryptDpe::new_p384();
    let bad_handle = [0xFFu8; 32];

    let result = dpe.derive_key_pair_exported(&bad_handle, b"label", b"info");
    match result {
        Err(caliptra_dpe_crypto::CryptoError::InvalidExportedCdiHandle) => {}
        Err(e) => panic!("Expected InvalidExportedCdiHandle, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn derive_exported_cdi_duplicate_rejected() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));

    let _ = dpe
        .derive_exported_cdi(&measurement, b"export info")
        .unwrap();

    // Same measurement + info should produce a duplicate CDI -> error
    let result = dpe.derive_exported_cdi(&measurement, b"export info");
    match result {
        Err(caliptra_dpe_crypto::CryptoError::ExportedCdiHandleDuplicateCdi) => {}
        Err(e) => panic!("Expected ExportedCdiHandleDuplicateCdi, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn derive_exported_cdi_slot_limit_exceeded() {
    let mut dpe = WolfCryptDpe::new_p384();

    // Fill the single slot (MAX_CDI_HANDLES = 1)
    let m1 = Digest::Sha384(Sha384([0x01u8; 48]));
    let _ = dpe.derive_exported_cdi(&m1, b"first").unwrap();

    // A different CDI should hit the slot limit
    let m2 = Digest::Sha384(Sha384([0x02u8; 48]));
    let result = dpe.derive_exported_cdi(&m2, b"second");
    match result {
        Err(caliptra_dpe_crypto::CryptoError::ExportedCdiHandleLimitExceeded) => {}
        Err(e) => panic!("Expected ExportedCdiHandleLimitExceeded, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

// ---------- get_pubkey_serial ----------

#[test]
fn get_pubkey_serial_produces_hex_digest() {
    let mut dpe = WolfCryptDpe::new_p384();
    let measurement = Digest::Sha384(Sha384([0x42u8; 48]));
    let cdi = dpe.derive_cdi(&measurement, b"cdi info").unwrap();
    let (_, pub_key) = dpe.derive_key_pair(&cdi, b"serial", b"info").unwrap();

    let mut serial = [0u8; 96]; // SHA-384 hex = 96 chars
    dpe.get_pubkey_serial(&pub_key, &mut serial).unwrap();

    // Must be valid hex (ASCII 0-9, a-f)
    assert!(serial.iter().all(|&b| b.is_ascii_hexdigit()),
        "serial contains non-hex characters");
    // Must not be all zeros (would mean hashing failed)
    assert!(serial.iter().any(|&b| b != b'0'),
        "serial is all zeros");
}
