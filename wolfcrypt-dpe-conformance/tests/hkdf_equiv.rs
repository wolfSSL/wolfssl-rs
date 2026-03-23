//! CDI derivation equivalence tests between wolf and reference backends.
//! This is the most critical conformance module: it validates that both
//! backends produce identical CDI bytes from identical inputs, which is
//! the foundation for all downstream key derivation and signing agreement.

mod helpers;

macro_rules! hkdf_equiv_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $fixed_meas:path,
        $random_meas:path,
        $variant:expr,
        $cdi_size:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::Crypto;
            use rand::RngCore;

            #[test]
            fn derive_cdi_equiv_fixed() {
                let measurement = $fixed_meas(0x42);
                let info = b"test-info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: fixed CDI derivation mismatch",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_equiv_random() {
                let mut rng = rand::thread_rng();

                for i in 0..20 {
                    let measurement = $random_meas(&mut rng);
                    let info_len = (i % 5) * 16 + 8; // varying lengths
                    let info = helpers::random_info(&mut rng, info_len);

                    let mut wolf = $new_wolf();
                    let mut refb = $new_ref();

                    let wolf_cdi = wolf.derive_cdi(&measurement, &info).unwrap();
                    let ref_cdi = refb.derive_cdi(&measurement, &info).unwrap();

                    assert_eq!(
                        wolf_cdi.as_slice(),
                        ref_cdi.as_slice(),
                        "{}: random CDI derivation mismatch at iteration {}",
                        $variant,
                        i
                    );
                }
            }

            #[test]
            fn derive_cdi_deterministic_wolf() {
                let measurement = $fixed_meas(0xAB);
                let info = b"determinism check";

                let mut wolf = $new_wolf();

                let cdi1 = wolf.derive_cdi(&measurement, info).unwrap();
                let cdi2 = wolf.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    cdi1.as_slice(),
                    cdi2.as_slice(),
                    "{}: wolf CDI derivation is not deterministic",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_deterministic_ref() {
                let measurement = $fixed_meas(0xAB);
                let info = b"determinism check";

                let mut refb = $new_ref();

                let cdi1 = refb.derive_cdi(&measurement, info).unwrap();
                let cdi2 = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    cdi1.as_slice(),
                    cdi2.as_slice(),
                    "{}: ref CDI derivation is not deterministic",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_different_measurement() {
                let m1 = $fixed_meas(0x01);
                let m2 = $fixed_meas(0x02);
                let info = b"same info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi1 = wolf.derive_cdi(&m1, info).unwrap();
                let wolf_cdi2 = wolf.derive_cdi(&m2, info).unwrap();
                let ref_cdi1 = refb.derive_cdi(&m1, info).unwrap();
                let ref_cdi2 = refb.derive_cdi(&m2, info).unwrap();

                assert_ne!(
                    wolf_cdi1.as_slice(),
                    wolf_cdi2.as_slice(),
                    "{}: wolf should produce different CDIs for different measurements",
                    $variant
                );
                assert_ne!(
                    ref_cdi1.as_slice(),
                    ref_cdi2.as_slice(),
                    "{}: ref should produce different CDIs for different measurements",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_different_info() {
                let measurement = $fixed_meas(0xAA);

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi1 = wolf.derive_cdi(&measurement, b"info A").unwrap();
                let wolf_cdi2 = wolf.derive_cdi(&measurement, b"info B").unwrap();
                let ref_cdi1 = refb.derive_cdi(&measurement, b"info A").unwrap();
                let ref_cdi2 = refb.derive_cdi(&measurement, b"info B").unwrap();

                assert_ne!(
                    wolf_cdi1.as_slice(),
                    wolf_cdi2.as_slice(),
                    "{}: wolf should produce different CDIs for different info",
                    $variant
                );
                assert_ne!(
                    ref_cdi1.as_slice(),
                    ref_cdi2.as_slice(),
                    "{}: ref should produce different CDIs for different info",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_empty_info() {
                let measurement = $fixed_meas(0x55);
                let info = b"";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: empty info CDI derivation mismatch",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_large_info() {
                let mut rng = rand::thread_rng();
                let measurement = $fixed_meas(0x77);
                let info = helpers::random_info(&mut rng, 1024);

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, &info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, &info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: large info (1024 bytes) CDI derivation mismatch",
                    $variant
                );
            }

            #[test]
            fn derive_cdi_size() {
                let measurement = $fixed_meas(0x42);
                let info = b"size check";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    wolf_cdi.len(),
                    $cdi_size,
                    "{}: wolf CDI size should be {} bytes",
                    $variant,
                    $cdi_size
                );
                assert_eq!(
                    ref_cdi.len(),
                    $cdi_size,
                    "{}: ref CDI size should be {} bytes",
                    $variant,
                    $cdi_size
                );
            }

            #[test]
            fn hkdf_parameter_ordering() {
                // Verify that both backends agree on HKDF parameter ordering:
                // Extract(salt=info, IKM=measurement) -> Expand(PRK, info=measurement, L=curve_size)
                // If the parameter mapping differs, the CDIs will not match.
                let measurement = $fixed_meas(0x37);
                let info = b"caliptra-dpe interop parameter ordering";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: HKDF parameter ordering mismatch between wolf and ref",
                    $variant
                );
            }

            #[test]
            fn canary_different_inputs() {
                let m_a = $fixed_meas(0xAA);
                let m_b = $fixed_meas(0xBB);
                let info = b"canary";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_cdi = wolf.derive_cdi(&m_a, info).unwrap();
                let ref_cdi = refb.derive_cdi(&m_b, info).unwrap();

                assert_ne!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: wolf(A) and ref(B) CDIs should differ for different measurements",
                    $variant
                );
            }

            #[test]
            fn full_pipeline_derive_then_keypair() {
                let measurement = $fixed_meas(0x42);
                let info = b"pipeline test";
                let label = b"ECC";
                let kp_info = b"keypair info";

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                // Derive CDI
                let wolf_cdi = wolf.derive_cdi(&measurement, info).unwrap();
                let ref_cdi = refb.derive_cdi(&measurement, info).unwrap();

                assert_eq!(
                    wolf_cdi.as_slice(),
                    ref_cdi.as_slice(),
                    "{}: pipeline CDI mismatch",
                    $variant
                );

                // Derive key pair from CDI
                let (_, wolf_pub) = wolf.derive_key_pair(&wolf_cdi, label, kp_info).unwrap();
                let (_, ref_pub) = refb.derive_key_pair(&ref_cdi, label, kp_info).unwrap();

                let wolf_uncompressed = helpers::pubkey_to_uncompressed(&wolf_pub);
                let ref_uncompressed = helpers::pubkey_to_uncompressed(&ref_pub);

                assert_eq!(
                    wolf_uncompressed, ref_uncompressed,
                    "{}: pipeline key pair mismatch after CDI derivation",
                    $variant
                );
            }
        }
    };
}

hkdf_equiv_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::fixed_measurement_384,
    helpers::random_measurement_384,
    "P-384/SHA-384",
    48
);

hkdf_equiv_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::fixed_measurement_256,
    helpers::random_measurement_256,
    "P-256/SHA-256",
    32
);
