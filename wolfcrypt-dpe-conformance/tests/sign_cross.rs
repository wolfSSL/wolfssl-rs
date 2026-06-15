//! Cross-backend signing and verification tests.
//! Validates that wolf and reference backends produce identical signatures
//! (via RFC 6979 deterministic ECDSA) and that signatures can be verified
//! independently using the p384/p256 crates.

#![expect(unreachable_patterns)]

mod helpers;

macro_rules! sign_cross_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $fixed_meas:path,
        $random_meas:path,
        $variant:expr,
        $cdi_size:expr,
        $sig_size:expr,
        $verify_fn:path,
        $sha_mod:path
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, CryptoError, Mu, SignData};
            use rand::RngCore;

            #[test]
            fn wolf_sign_independent_verify() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"signing";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();

                let digest = wolf.hash(b"message to verify").unwrap();
                let digest_bytes = digest.as_slice().to_vec();
                let sign_data = SignData::Digest(digest);

                let sig = wolf
                    .sign_with_derived(&sign_data, &wolf_priv, &wolf_pub)
                    .unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let sig_bytes = helpers::sig_to_fixed(&sig);

                $verify_fn(&pub_bytes, &digest_bytes, &sig_bytes).expect(concat!(
                    $variant,
                    ": wolf signature failed independent verification"
                ));
            }

            #[test]
            fn ref_sign_independent_verify() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"signing";
                let kp_info = b"kp info";

                let mut refb = $new_ref();

                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let digest = refb.hash(b"message to verify").unwrap();
                let digest_bytes = digest.as_slice().to_vec();
                let sign_data = SignData::Digest(digest);

                let sig = refb
                    .sign_with_derived(&sign_data, &ref_priv, &ref_pub)
                    .unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&ref_pub);
                let sig_bytes = helpers::sig_to_fixed(&sig);

                $verify_fn(&pub_bytes, &digest_bytes, &sig_bytes).expect(concat!(
                    $variant,
                    ": ref signature failed independent verification"
                ));
            }

            #[test]
            fn wolf_sign_format() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"signing";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();

                let digest = wolf.hash(b"format check").unwrap();
                let sign_data = SignData::Digest(digest);

                let sig = wolf
                    .sign_with_derived(&sign_data, &wolf_priv, &wolf_pub)
                    .unwrap();

                let sig_bytes = helpers::sig_to_fixed(&sig);
                assert_eq!(
                    sig_bytes.len(),
                    $sig_size,
                    "{}: wolf signature should be {} bytes (r||s)",
                    $variant,
                    $sig_size
                );
            }

            #[test]
            fn sign_with_derived_roundtrip() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"roundtrip";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();

                let digest = wolf.hash(b"roundtrip message").unwrap();
                let digest_bytes = digest.as_slice().to_vec();
                let sign_data = SignData::Digest(digest);

                let sig = wolf
                    .sign_with_derived(&sign_data, &wolf_priv, &wolf_pub)
                    .unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let sig_bytes = helpers::sig_to_fixed(&sig);

                $verify_fn(&pub_bytes, &digest_bytes, &sig_bytes).expect(concat!(
                    $variant,
                    ": wolf sign_with_derived roundtrip verification failed"
                ));
            }

            #[test]
            fn sign_raw_data_cross() {
                use sha2::Digest as Sha2Digest;

                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"raw-sign";
                let kp_info = b"kp info";
                let raw_data = b"raw data for cross-backend signing test";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_sig = wolf
                    .sign_with_derived(&SignData::Raw(raw_data), &wolf_priv, &wolf_pub)
                    .unwrap();
                let ref_sig = refb
                    .sign_with_derived(&SignData::Raw(raw_data), &ref_priv, &ref_pub)
                    .unwrap();

                // Both should produce identical pub keys
                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                assert_eq!(
                    pub_bytes,
                    helpers::pubkey_to_uncompressed(&ref_pub),
                    "{}: raw sign cross: public keys should match",
                    $variant
                );

                // Compute the expected digest independently for verification
                let expected_digest = <$sha_mod>::digest(raw_data);

                // Verify wolf signature independently
                let wolf_sig_bytes = helpers::sig_to_fixed(&wolf_sig);
                $verify_fn(&pub_bytes, &expected_digest, &wolf_sig_bytes).expect(concat!(
                    $variant,
                    ": wolf raw signature failed independent verification"
                ));

                // Verify ref signature independently
                let ref_sig_bytes = helpers::sig_to_fixed(&ref_sig);
                $verify_fn(&pub_bytes, &expected_digest, &ref_sig_bytes).expect(concat!(
                    $variant,
                    ": ref raw signature failed independent verification"
                ));
            }

            #[test]
            fn sign_digest_data_cross() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"digest-sign";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                // Compute digest using wolf backend (both produce the same hash)
                let digest_wolf = wolf.hash(b"cross-verify digest data").unwrap();
                let digest_ref = refb.hash(b"cross-verify digest data").unwrap();
                let digest_bytes = digest_wolf.as_slice().to_vec();

                let wolf_sig = wolf
                    .sign_with_derived(&SignData::Digest(digest_wolf), &wolf_priv, &wolf_pub)
                    .unwrap();
                let ref_sig = refb
                    .sign_with_derived(&SignData::Digest(digest_ref), &ref_priv, &ref_pub)
                    .unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);

                // Verify wolf signature independently
                let wolf_sig_bytes = helpers::sig_to_fixed(&wolf_sig);
                $verify_fn(&pub_bytes, &digest_bytes, &wolf_sig_bytes).expect(concat!(
                    $variant,
                    ": wolf digest signature failed independent verification"
                ));

                // Verify ref signature independently
                let ref_sig_bytes = helpers::sig_to_fixed(&ref_sig);
                $verify_fn(&pub_bytes, &digest_bytes, &ref_sig_bytes).expect(concat!(
                    $variant,
                    ": ref digest signature failed independent verification"
                ));
            }

            #[test]
            fn sign_mu_rejected() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"mu-reject";
                let kp_info = b"kp info";
                let mu_data = SignData::Mu(Mu([0xAAu8; 64]));

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_result = wolf.sign_with_derived(&mu_data, &wolf_priv, &wolf_pub);
                match wolf_result {
                    Err(CryptoError::MismatchedAlgorithm) => {}
                    Err(e) => panic!(
                        "{}: wolf SignData::Mu expected MismatchedAlgorithm, got {:?}",
                        $variant, e
                    ),
                    Ok(_) => panic!(
                        "{}: wolf SignData::Mu should return error, got Ok",
                        $variant
                    ),
                }

                let mu_data2 = SignData::Mu(Mu([0xAAu8; 64]));
                let ref_result = refb.sign_with_derived(&mu_data2, &ref_priv, &ref_pub);
                match ref_result {
                    Err(CryptoError::MismatchedAlgorithm) => {}
                    Err(e) => panic!(
                        "{}: ref SignData::Mu expected MismatchedAlgorithm, got {:?}",
                        $variant, e
                    ),
                    Ok(_) => panic!("{}: ref SignData::Mu should return error, got Ok", $variant),
                }
            }

            #[test]
            fn sign_deterministic_equiv() {
                // wolfSSL may use randomized ECDSA, not RFC 6979.
                // Both signatures must verify independently over the same key+digest.
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"rfc6979";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                // Public keys MUST match (deterministic HKDF derivation)
                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                assert_eq!(
                    pub_bytes,
                    helpers::pubkey_to_uncompressed(&ref_pub),
                    "{}: derived public keys must match across backends",
                    $variant
                );

                let digest_wolf = wolf.hash(b"deterministic signing test").unwrap();
                let digest_ref = refb.hash(b"deterministic signing test").unwrap();
                let digest_bytes = digest_wolf.as_slice().to_vec();

                let wolf_sig = wolf
                    .sign_with_derived(&SignData::Digest(digest_wolf), &wolf_priv, &wolf_pub)
                    .unwrap();
                let ref_sig = refb
                    .sign_with_derived(&SignData::Digest(digest_ref), &ref_priv, &ref_pub)
                    .unwrap();

                // Cross-verify: both signatures valid for shared public key
                let wolf_sig_bytes = helpers::sig_to_fixed(&wolf_sig);
                let ref_sig_bytes = helpers::sig_to_fixed(&ref_sig);

                $verify_fn(&pub_bytes, &digest_bytes, &wolf_sig_bytes)
                    .expect(&format!("{}: wolf signature must verify", $variant));
                $verify_fn(&pub_bytes, &digest_bytes, &ref_sig_bytes)
                    .expect(&format!("{}: ref signature must verify", $variant));
            }

            #[test]
            fn sign_different_message_different_sig() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"diff-msg";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();

                let digest1 = wolf.hash(b"message one").unwrap();
                let digest2 = wolf.hash(b"message two").unwrap();

                let sig1 = wolf
                    .sign_with_derived(&SignData::Digest(digest1), &wolf_priv, &wolf_pub)
                    .unwrap();
                let sig2 = wolf
                    .sign_with_derived(&SignData::Digest(digest2), &wolf_priv, &wolf_pub)
                    .unwrap();

                assert_ne!(
                    helpers::sig_to_fixed(&sig1),
                    helpers::sig_to_fixed(&sig2),
                    "{}: different messages should produce different signatures",
                    $variant
                );
            }

            #[test]
            fn tampered_signature_rejected() {
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"tamper";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();

                let digest = wolf.hash(b"tamper test message").unwrap();
                let digest_bytes = digest.as_slice().to_vec();
                let sign_data = SignData::Digest(digest);

                let sig = wolf
                    .sign_with_derived(&sign_data, &wolf_priv, &wolf_pub)
                    .unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let mut sig_bytes = helpers::sig_to_fixed(&sig);

                // Flip a byte in the signature
                sig_bytes[0] ^= 0xFF;

                let result = $verify_fn(&pub_bytes, &digest_bytes, &sig_bytes);
                assert!(
                    result.is_err(),
                    "{}: tampered signature should fail verification",
                    $variant
                );
            }

            #[test]
            fn wrong_key_rejected() {
                let m1 = $fixed_meas(0x01);
                let m2 = $fixed_meas(0x02);
                let cdi_info = b"cdi info";
                let label = b"wrong-key";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();

                let cdi1 = wolf.derive_cdi(&m1, cdi_info).unwrap();
                let cdi2 = wolf.derive_cdi(&m2, cdi_info).unwrap();

                let (priv_a, pub_a) = wolf.derive_key_pair(&cdi1, label, kp_info).unwrap();
                let (_, pub_b) = wolf.derive_key_pair(&cdi2, label, kp_info).unwrap();

                let digest = wolf.hash(b"wrong key test").unwrap();
                let digest_bytes = digest.as_slice().to_vec();
                let sign_data = SignData::Digest(digest);

                // Sign with key A
                let sig = wolf.sign_with_derived(&sign_data, &priv_a, &pub_a).unwrap();

                // Verify with key B -> should fail
                let pub_b_bytes = helpers::pubkey_to_uncompressed(&pub_b);
                let sig_bytes = helpers::sig_to_fixed(&sig);

                let result = $verify_fn(&pub_b_bytes, &digest_bytes, &sig_bytes);
                assert!(
                    result.is_err(),
                    "{}: signature verified with wrong key should fail",
                    $variant
                );
            }

            #[test]
            fn multiple_random_messages() {
                // 20 random digests: sign with both backends, cross-verify.
                // Signatures may differ (randomized ECDSA) but both must be valid.
                let measurement = $fixed_meas(0x42);
                let cdi_info = b"cdi info";
                let label = b"multi-msg";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();
                let mut rng = rand::thread_rng();

                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                let (wolf_priv, wolf_pub) =
                    wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (ref_priv, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let pub_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);

                for i in 0..20 {
                    let msg_len = (i + 1) * 32;
                    let msg = helpers::random_info(&mut rng, msg_len);

                    let digest_wolf = wolf.hash(&msg).unwrap();
                    let digest_ref = refb.hash(&msg).unwrap();
                    let digest_bytes = digest_wolf.as_slice().to_vec();

                    let wolf_sig = wolf
                        .sign_with_derived(&SignData::Digest(digest_wolf), &wolf_priv, &wolf_pub)
                        .unwrap();
                    let ref_sig = refb
                        .sign_with_derived(&SignData::Digest(digest_ref), &ref_priv, &ref_pub)
                        .unwrap();

                    let wolf_sig_bytes = helpers::sig_to_fixed(&wolf_sig);
                    let ref_sig_bytes = helpers::sig_to_fixed(&ref_sig);

                    // Both signatures must verify against the shared public key
                    $verify_fn(&pub_bytes, &digest_bytes, &wolf_sig_bytes).expect(&format!(
                        "{}: wolf signature verification failed at iteration {}",
                        $variant, i
                    ));
                    $verify_fn(&pub_bytes, &digest_bytes, &ref_sig_bytes).expect(&format!(
                        "{}: ref signature verification failed at iteration {}",
                        $variant, i
                    ));
                }
            }
        }
    };
}

sign_cross_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::fixed_measurement_384,
    helpers::random_measurement_384,
    "P-384/SHA-384",
    48,
    96, // 48 + 48
    helpers::verify_p384_signature,
    sha2::Sha384
);

sign_cross_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::fixed_measurement_256,
    helpers::random_measurement_256,
    "P-256/SHA-256",
    32,
    64, // 32 + 32
    helpers::verify_p256_signature,
    sha2::Sha256
);
