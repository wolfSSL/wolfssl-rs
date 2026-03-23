#![cfg(all(not(feature = "fips"), feature = "unstable"))]

use ring::signature::VerificationAlgorithm;
use ring::signature::KeyPair;
use ring::unstable::signature::{
    PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87,
    ML_DSA_87_SIGNING,
};
use ring::{test, test_file};

// ============================================================
// ACVP keyGen test vectors
// ============================================================

macro_rules! mldsa_keygen_test {
    ($file:literal, $signing:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let seed = test_case.consume_bytes("SEED");
            let public = test_case.consume_bytes("PUBLIC");
            let secret = test_case.consume_bytes("SECRET");

            // Verify key construction from combined raw key (secret || public) produces expected public key
            let mut combined = secret.clone();
            combined.extend_from_slice(&public);
            let key_pair_secret = PqdsaKeyPair::from_raw_private_key($signing, combined.as_slice())?;
            let public_secret = key_pair_secret.public_key();
            assert_eq!(
                public.as_slice(),
                public_secret.as_ref(),
                "public key from raw private key does not match expected"
            );

            // Verify seed-based key generation produces the same public key
            let key_pair_seed = PqdsaKeyPair::from_seed($signing, seed.as_slice())?;
            assert_eq!(
                public.as_slice(),
                key_pair_seed.public_key().as_ref(),
                "public key from seed does not match expected"
            );

            // Verify seed-based key generation produces the same raw private key
            // as_raw_bytes returns combined format (secret || public)
            let seed_raw_private = key_pair_seed.private_key().as_raw_bytes()?;
            assert_eq!(
                combined.as_slice(),
                seed_raw_private.as_ref(),
                "combined key from seed does not match expected"
            );

            Ok(())
        });
    };
}

// ============================================================
// ACVP sigVer test vectors
// ============================================================

macro_rules! mldsa_sigver_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let _context = test_case.consume_bytes("CONTEXT");
            let expected_result = test_case.consume_bool("RESULT");

            let result =
                $verification.verify_sig(public_key.as_ref(), message.as_ref(), signature.as_ref());
            if expected_result {
                assert!(
                    result.is_ok(),
                    "expected verification to succeed but it failed"
                );
            } else {
                assert!(
                    result.is_err(),
                    "expected verification to fail but it succeeded"
                );
            }

            Ok(())
        });
    };
}

macro_rules! mldsa_sigver_digest_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let _context = test_case.consume_bytes("CONTEXT");
            let _expected_result = test_case.consume_bool("RESULT");

            // ML-DSA does not support digest-then-sign; this must always fail
            let digest = ring::digest::digest(&ring::digest::SHA256, message.as_ref());
            let result =
                $verification.verify_digest_sig(public_key.as_ref(), &digest, signature.as_ref());
            assert!(result.is_err(), "digest_sig should always fail for ML-DSA");

            Ok(())
        });
    };
}

// ============================================================
// ACVP keyGen tests
// ============================================================

#[test]
fn mldsa_44_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_44_ACVP_keyGen.txt", &ML_DSA_44_SIGNING);
}

#[test]
fn mldsa_65_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_65_ACVP_keyGen.txt", &ML_DSA_65_SIGNING);
}

#[test]
fn mldsa_87_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_87_ACVP_keyGen.txt", &ML_DSA_87_SIGNING);
}

// ============================================================
// ACVP sigVer tests
// ============================================================

#[test]
fn mldsa_44_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_44_sigVer.txt", &ML_DSA_44);
}

#[test]
fn mldsa_65_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_65_sigVer.txt", &ML_DSA_65);
}

#[test]
fn mldsa_87_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_87_sigVer.txt", &ML_DSA_87);
}

#[test]
fn mldsa_44_sigver_digest_test() {
    mldsa_sigver_digest_test!("data/MLDSA_44_sigVer.txt", &ML_DSA_44);
}

// ============================================================
// Round-trip: seed -> sign -> verify
// ============================================================

#[test]
fn test_mldsa_seed_sign_verify() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let seed = [7u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &seed)
            .expect("from_seed should succeed with valid 32-byte seed");
        let msg = b"test message";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        let sig_len = kp
            .sign(msg, &mut sig)
            .expect("signing with seed-derived key should succeed");
        assert_eq!(sig_len, signing_alg.signature_len());
        let pk = ring::signature::UnparsedPublicKey::new(verify_alg, kp.public_key().as_ref());
        pk.verify(msg, &sig)
            .expect("verification of seed-derived signature should succeed");
    }
}

// ============================================================
// Negative: wrong seed size
// ============================================================

#[test]
fn test_mldsa_seed_wrong_size() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        assert!(
            PqdsaKeyPair::from_seed(signing_alg, &[0u8; 31]).is_err(),
            "31 bytes should be rejected as too short"
        );
        assert!(
            PqdsaKeyPair::from_seed(signing_alg, &[0u8; 33]).is_err(),
            "33 bytes should be rejected as too long"
        );
        assert!(
            PqdsaKeyPair::from_seed(signing_alg, &[]).is_err(),
            "empty seed should be rejected"
        );
        assert!(
            PqdsaKeyPair::from_seed(signing_alg, &[0u8; 32]).is_ok(),
            "32 bytes should be accepted"
        );
    }
}

// ============================================================
// Raw private key serialization round-trip
// ============================================================

#[test]
fn test_mldsa_seed_serialization_roundtrip() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        let seed = [99u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &seed).unwrap();

        // Raw private key round-trip
        let raw = kp
            .private_key()
            .as_raw_bytes()
            .expect("as_raw_bytes should succeed");
        let kp_raw = PqdsaKeyPair::from_raw_private_key(signing_alg, raw.as_ref())
            .expect("from_raw_private_key should reconstruct the key");
        assert_eq!(
            kp.public_key().as_ref(),
            kp_raw.public_key().as_ref(),
            "raw private key round-trip should preserve public key"
        );

        // Stability: re-exported bytes should be identical
        let raw2 = kp_raw
            .private_key()
            .as_raw_bytes()
            .expect("re-export should succeed");
        assert_eq!(
            raw.as_ref(),
            raw2.as_ref(),
            "raw private key bytes should be stable across round-trips"
        );
    }
}

// ============================================================
// Different seeds -> different keys
// ============================================================

#[test]
fn test_mldsa_seed_different_seeds_different_keys() {
    for signing_alg in [&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING] {
        let kp1 = PqdsaKeyPair::from_seed(signing_alg, &[1u8; 32]).unwrap();
        let kp2 = PqdsaKeyPair::from_seed(signing_alg, &[2u8; 32]).unwrap();
        assert_ne!(
            kp1.public_key().as_ref(),
            kp2.public_key().as_ref(),
            "different seeds should produce different public keys"
        );
    }
}

// ============================================================
// Zeroed seed should still produce a functional key
// ============================================================

#[test]
fn test_mldsa_seed_zeroed_bytes() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let zeroed_seed = [0u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &zeroed_seed)
            .expect("from_seed should accept zeroed bytes of correct size");

        let msg = b"zeroed seed test";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        let sig_len = kp.sign(msg, &mut sig).expect("signing should succeed");
        assert_eq!(sig_len, signing_alg.signature_len());

        let pk = ring::signature::UnparsedPublicKey::new(verify_alg, kp.public_key().as_ref());
        pk.verify(msg, &sig)
            .expect("verification with zeroed-seed key should succeed");

        // Determinism
        let kp2 = PqdsaKeyPair::from_seed(signing_alg, &zeroed_seed).unwrap();
        assert_eq!(kp.public_key().as_ref(), kp2.public_key().as_ref());
    }
}

// ============================================================
// Functional equivalence: seed vs reconstructed key
// ============================================================

#[test]
fn test_mldsa_seed_functional_equivalence() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let seed = [123u8; 32];
        let original = PqdsaKeyPair::from_seed(signing_alg, &seed).unwrap();

        let raw = original.private_key().as_raw_bytes().unwrap();
        let reconstructed = PqdsaKeyPair::from_raw_private_key(signing_alg, raw.as_ref()).unwrap();

        assert_eq!(original.public_key().as_ref(), reconstructed.public_key().as_ref());

        let msg = b"equivalence test";

        let mut sig_original = vec![0u8; signing_alg.signature_len()];
        original.sign(msg, &mut sig_original).unwrap();

        let mut sig_reconstructed = vec![0u8; signing_alg.signature_len()];
        reconstructed.sign(msg, &mut sig_reconstructed).unwrap();

        let pk = ring::signature::UnparsedPublicKey::new(
            verify_alg,
            original.public_key().as_ref(),
        );
        pk.verify(msg, &sig_original).expect("original signature should verify");
        pk.verify(msg, &sig_reconstructed).expect("reconstructed signature should verify");
    }
}

// ============================================================
// Negative: verify with wrong key
// ============================================================

#[test]
fn test_mldsa_verify_wrong_key() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let kp1 = PqdsaKeyPair::generate(signing_alg).unwrap();
        let kp2 = PqdsaKeyPair::generate(signing_alg).unwrap();
        let msg = b"wrong key test";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        kp1.sign(msg, &mut sig).unwrap();

        // Verify with wrong public key should fail
        let wrong_pk = ring::signature::UnparsedPublicKey::new(
            verify_alg,
            kp2.public_key().as_ref(),
        );
        assert!(
            wrong_pk.verify(msg, &sig).is_err(),
            "verification with wrong key should fail"
        );
    }
}

// ============================================================
// Negative: corrupted signature
// ============================================================

#[test]
fn test_mldsa_corrupted_signature() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let kp = PqdsaKeyPair::generate(signing_alg).unwrap();
        let msg = b"corrupted sig test";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        kp.sign(msg, &mut sig).unwrap();

        // First verify the original signature works
        let pk = ring::signature::UnparsedPublicKey::new(
            verify_alg,
            kp.public_key().as_ref(),
        );
        assert!(pk.verify(msg, &sig).is_ok(), "original sig should verify");

        // Corrupt the first byte
        sig[0] ^= 0xff;
        assert!(
            pk.verify(msg, &sig).is_err(),
            "corrupted signature should fail verification"
        );
    }
}

// ============================================================
// Negative: all-zeros signature
// ============================================================

#[test]
fn test_mldsa_zero_signature() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let kp = PqdsaKeyPair::generate(signing_alg).unwrap();
        let msg = b"zero sig test";
        let zero_sig = vec![0u8; signing_alg.signature_len()];

        let pk = ring::signature::UnparsedPublicKey::new(
            verify_alg,
            kp.public_key().as_ref(),
        );
        assert!(
            pk.verify(msg, &zero_sig).is_err(),
            "all-zeros signature should fail verification"
        );
    }
}

// ============================================================
// ring-sig-verify feature: VerificationAlgorithm::verify()
// ============================================================

#[cfg(feature = "ring-sig-verify")]
#[test]
#[allow(deprecated)]
fn test_mldsa_ring_sig_verify() {
    for (signing_alg, verify_alg) in [
        (&ML_DSA_44_SIGNING, &ML_DSA_44),
        (&ML_DSA_65_SIGNING, &ML_DSA_65),
        (&ML_DSA_87_SIGNING, &ML_DSA_87),
    ] {
        let seed = [42u8; 32];
        let kp = PqdsaKeyPair::from_seed(signing_alg, &seed).unwrap();
        let msg = b"ring compat test";
        let mut sig = vec![0u8; signing_alg.signature_len()];
        kp.sign(msg, &mut sig).unwrap();

        let pk_bytes = kp.public_key().as_ref();
        assert!(verify_alg.verify(
            pk_bytes.into(),
            msg.as_ref().into(),
            sig.as_slice().into(),
        ).is_ok());
    }
}
