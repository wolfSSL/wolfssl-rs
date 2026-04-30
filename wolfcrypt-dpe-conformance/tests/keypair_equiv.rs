//! Key pair derivation equivalence tests between wolf and reference backends.
//! Validates that identical CDI + label + info produce identical (x, y) public
//! key coordinates, and that the keys are valid points on the expected curve.

mod helpers;

macro_rules! keypair_equiv_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $fixed_meas:path,
        $random_meas:path,
        $variant:expr,
        $cdi_size:expr,
        $uncompressed_len:expr,
        $curve_mod:ident
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::Crypto;
            use rand::RngCore;

            #[test]
            fn derive_key_pair_equiv_fixed() {
                let measurement = $fixed_meas(0x42);
                let info = b"cdi info";
                let label = b"ECC";
                let kp_info = b"keypair info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let ref_bytes = helpers::pubkey_to_uncompressed(&ref_pub);

                assert_eq!(
                    wolf_bytes, ref_bytes,
                    "{}: fixed key pair derivation mismatch",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_equiv_random() {
                let mut rng = rand::thread_rng();

                for i in 0..20 {
                    // Generate random CDI directly (same bytes for both)
                    let mut cdi = vec![0u8; $cdi_size];
                    rng.fill_bytes(&mut cdi);

                    let label_len = (i % 4) * 8 + 4;
                    let label = helpers::random_info(&mut rng, label_len);
                    let info_len = (i % 5) * 16 + 8;
                    let info = helpers::random_info(&mut rng, info_len);

                    let mut wolf = $new_wolf();
                    let mut refb = $new_ref();

                    let (_, wolf_pub) = wolf.derive_key_pair(&cdi, &label, &info).unwrap();
                    let (_, ref_pub) = refb.derive_key_pair(&cdi, &label, &info).unwrap();

                    let wolf_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                    let ref_bytes = helpers::pubkey_to_uncompressed(&ref_pub);

                    assert_eq!(
                        wolf_bytes, ref_bytes,
                        "{}: random key pair derivation mismatch at iteration {}",
                        $variant, i
                    );
                }
            }

            #[test]
            fn derive_key_pair_deterministic() {
                let measurement = $fixed_meas(0xCD);
                let info = b"cdi info";
                let label = b"label";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub1) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, wolf_pub2) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub1) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();
                let (_, ref_pub2) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                assert_eq!(
                    helpers::pubkey_to_uncompressed(&wolf_pub1),
                    helpers::pubkey_to_uncompressed(&wolf_pub2),
                    "{}: wolf key pair derivation is not deterministic",
                    $variant
                );
                assert_eq!(
                    helpers::pubkey_to_uncompressed(&ref_pub1),
                    helpers::pubkey_to_uncompressed(&ref_pub2),
                    "{}: ref key pair derivation is not deterministic",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_different_label() {
                let measurement = $fixed_meas(0xBB);
                let info = b"cdi info";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub_a) = wolf
                    .derive_key_pair(&wolf_cdi, b"label A", kp_info)
                    .unwrap();
                let (_, wolf_pub_b) = wolf
                    .derive_key_pair(&wolf_cdi, b"label B", kp_info)
                    .unwrap();
                let (_, ref_pub_a) = refb.derive_key_pair(&ref_cdi, b"label A", kp_info).unwrap();
                let (_, ref_pub_b) = refb.derive_key_pair(&ref_cdi, b"label B", kp_info).unwrap();

                assert_ne!(
                    helpers::pubkey_to_uncompressed(&wolf_pub_a),
                    helpers::pubkey_to_uncompressed(&wolf_pub_b),
                    "{}: wolf should produce different keys for different labels",
                    $variant
                );
                assert_ne!(
                    helpers::pubkey_to_uncompressed(&ref_pub_a),
                    helpers::pubkey_to_uncompressed(&ref_pub_b),
                    "{}: ref should produce different keys for different labels",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_different_info() {
                let measurement = $fixed_meas(0xCC);
                let info = b"cdi info";
                let label = b"label";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub_a) = wolf.derive_key_pair(&wolf_cdi, label, b"info A").unwrap();
                let (_, wolf_pub_b) = wolf.derive_key_pair(&wolf_cdi, label, b"info B").unwrap();
                let (_, ref_pub_a) = refb.derive_key_pair(&ref_cdi, label, b"info A").unwrap();
                let (_, ref_pub_b) = refb.derive_key_pair(&ref_cdi, label, b"info B").unwrap();

                assert_ne!(
                    helpers::pubkey_to_uncompressed(&wolf_pub_a),
                    helpers::pubkey_to_uncompressed(&wolf_pub_b),
                    "{}: wolf should produce different keys for different info",
                    $variant
                );
                assert_ne!(
                    helpers::pubkey_to_uncompressed(&ref_pub_a),
                    helpers::pubkey_to_uncompressed(&ref_pub_b),
                    "{}: ref should produce different keys for different info",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_different_cdi() {
                let m1 = $fixed_meas(0x01);
                let m2 = $fixed_meas(0x02);
                let info = b"cdi info";
                let label = b"label";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi1 = wolf.derive_cdi(&m1, info).unwrap();
                let wolf_cdi2 = wolf.derive_cdi(&m2, info).unwrap();
                let ref_cdi1 = refb.derive_cdi(&m1, info).unwrap();
                let ref_cdi2 = refb.derive_cdi(&m2, info).unwrap();

                let (_, wolf_pub1) = wolf.derive_key_pair(&wolf_cdi1, label, kp_info).unwrap();
                let (_, wolf_pub2) = wolf.derive_key_pair(&wolf_cdi2, label, kp_info).unwrap();
                let (_, ref_pub1) = refb.derive_key_pair(&ref_cdi1, label, kp_info).unwrap();
                let (_, ref_pub2) = refb.derive_key_pair(&ref_cdi2, label, kp_info).unwrap();

                assert_ne!(
                    helpers::pubkey_to_uncompressed(&wolf_pub1),
                    helpers::pubkey_to_uncompressed(&wolf_pub2),
                    "{}: wolf should produce different keys for different CDIs",
                    $variant
                );
                assert_ne!(
                    helpers::pubkey_to_uncompressed(&ref_pub1),
                    helpers::pubkey_to_uncompressed(&ref_pub2),
                    "{}: ref should produce different keys for different CDIs",
                    $variant
                );
            }

            #[test]
            fn pubkey_format_uncompressed() {
                let measurement = $fixed_meas(0x42);
                let info = b"cdi info";
                let label = b"ECC";
                let kp_info = b"format check";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let ref_bytes = helpers::pubkey_to_uncompressed(&ref_pub);

                // SEC1 uncompressed: 04 || x || y
                assert_eq!(
                    wolf_bytes.len(),
                    $uncompressed_len,
                    "{}: wolf uncompressed public key should be {} bytes",
                    $variant,
                    $uncompressed_len
                );
                assert_eq!(
                    ref_bytes.len(),
                    $uncompressed_len,
                    "{}: ref uncompressed public key should be {} bytes",
                    $variant,
                    $uncompressed_len
                );
                assert_eq!(
                    wolf_bytes[0], 0x04,
                    "{}: wolf public key should start with 0x04",
                    $variant
                );
                assert_eq!(
                    ref_bytes[0], 0x04,
                    "{}: ref public key should start with 0x04",
                    $variant
                );
            }

            #[test]
            fn pubkey_on_curve() {
                let measurement = $fixed_meas(0x42);
                let info = b"cdi info";
                let label = b"ECC";
                let kp_info = b"curve check";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let ref_bytes = helpers::pubkey_to_uncompressed(&ref_pub);

                // Validate that the public key is a valid point on the curve
                $curve_mod::PublicKey::from_sec1_bytes(&wolf_bytes).expect(concat!(
                    $variant,
                    ": wolf public key is not on the expected curve"
                ));
                $curve_mod::PublicKey::from_sec1_bytes(&ref_bytes).expect(concat!(
                    $variant,
                    ": ref public key is not on the expected curve"
                ));
            }

            #[test]
            fn full_pipeline_equiv() {
                let measurement = $fixed_meas(0x99);
                let cdi_info = b"pipeline cdi info";
                let label = b"ECC";
                let kp_info = b"pipeline kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                // Step 1: derive CDI
                let wolf_cdi = wolf.derive_cdi(&measurement, cdi_info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, cdi_info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: pipeline CDI mismatch",
                    $variant
                );

                // Step 2: derive key pair
                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_bytes = helpers::pubkey_to_uncompressed(&wolf_pub);
                let ref_bytes = helpers::pubkey_to_uncompressed(&ref_pub);

                assert_eq!(
                    wolf_bytes, ref_bytes,
                    "{}: full pipeline key pair mismatch",
                    $variant
                );
            }

            #[test]
            fn canary_wrong_cdi() {
                let m_a = $fixed_meas(0xAA);
                let m_b = $fixed_meas(0xBB);
                let info = b"cdi info";
                let label = b"ECC";
                let kp_info = b"kp info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&m_a, info).unwrap();
                let ref_cdi = refb.derive_cdi(&m_b, info).unwrap();

                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                assert_ne!(
                    helpers::pubkey_to_uncompressed(&wolf_pub),
                    helpers::pubkey_to_uncompressed(&ref_pub),
                    "{}: keys from different CDIs should differ",
                    $variant
                );
            }
        }
    };
}

keypair_equiv_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::fixed_measurement_384,
    helpers::random_measurement_384,
    "P-384/SHA-384",
    48,
    97, // 1 + 48 + 48
    p384
);

keypair_equiv_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::fixed_measurement_256,
    helpers::random_measurement_256,
    "P-256/SHA-256",
    32,
    65, // 1 + 32 + 32
    p256
);
