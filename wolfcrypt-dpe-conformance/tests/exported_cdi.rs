//! Exported CDI handle behaviour tests.
//!
//! Tests derive_exported_cdi, derive_key_pair_exported, handle validity,
//! duplicate rejection, and slot limits. Instantiated for both P-384 and P-256.

mod helpers;

macro_rules! exported_cdi_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $make_meas:path,
        $verify_sig:path,
        $variant:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, CryptoError};

            #[test]
            fn derive_exported_cdi_returns_handle_wolf() {
                let mut backend = $new_wolf();
                let measurement = $make_meas(0x10);
                let handle = backend
                    .derive_exported_cdi(&measurement, b"export-test")
                    .expect(concat!($variant, ": wolf derive_exported_cdi should succeed"));
                assert_eq!(
                    handle.len(),
                    32,
                    "{}: exported CDI handle should be 32 bytes",
                    $variant
                );
                // Handle should not be all zeros (random)
                assert!(
                    handle.iter().any(|&b| b != 0),
                    "{}: exported CDI handle should not be all zeros",
                    $variant
                );
            }

            #[test]
            fn derive_exported_cdi_returns_handle_ref() {
                let mut backend = $new_ref();
                let measurement = $make_meas(0x10);
                let handle = backend
                    .derive_exported_cdi(&measurement, b"export-test")
                    .expect(concat!($variant, ": ref derive_exported_cdi should succeed"));
                assert_eq!(
                    handle.len(),
                    32,
                    "{}: exported CDI handle should be 32 bytes",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_exported_works_wolf() {
                let mut backend = $new_wolf();
                let measurement = $make_meas(0x20);
                let handle = backend
                    .derive_exported_cdi(&measurement, b"kp-export")
                    .expect("derive_exported_cdi should succeed");
                let (priv_key, pub_key) = backend
                    .derive_key_pair_exported(&handle, b"label", b"info")
                    .expect(concat!(
                        $variant,
                        ": wolf derive_key_pair_exported should succeed"
                    ));

                // Public key should have valid coordinates
                let (x, y) = helpers::pubkey_xy(&pub_key);
                assert!(
                    !x.is_empty() && !y.is_empty(),
                    "{}: exported key pair should have non-empty public key coordinates",
                    $variant
                );
            }

            #[test]
            fn derive_key_pair_exported_works_ref() {
                let mut backend = $new_ref();
                let measurement = $make_meas(0x20);
                let handle = backend
                    .derive_exported_cdi(&measurement, b"kp-export")
                    .expect("derive_exported_cdi should succeed");
                let (_priv_key, pub_key) = backend
                    .derive_key_pair_exported(&handle, b"label", b"info")
                    .expect(concat!(
                        $variant,
                        ": ref derive_key_pair_exported should succeed"
                    ));
                let (x, y) = helpers::pubkey_xy(&pub_key);
                assert!(
                    !x.is_empty() && !y.is_empty(),
                    "{}: exported key pair should have non-empty public key coordinates",
                    $variant
                );
            }

            #[test]
            fn exported_matches_direct_wolf() {
                let mut backend = $new_wolf();
                let measurement = $make_meas(0x30);
                let info = b"equiv-test";
                let label = b"equiv-label";
                let kp_info = b"equiv-kp-info";

                // Direct path: derive_cdi → derive_key_pair
                let cdi = backend.derive_cdi(&measurement, info).unwrap();
                let (_priv_direct, pub_direct) =
                    backend.derive_key_pair(&cdi, label, kp_info).unwrap();

                // Exported path: derive_exported_cdi → derive_key_pair_exported
                // Need a fresh instance because the CDI slot is taken
                let mut backend2 = $new_wolf();
                let handle = backend2
                    .derive_exported_cdi(&measurement, info)
                    .unwrap();
                let (_priv_exported, pub_exported) = backend2
                    .derive_key_pair_exported(&handle, label, kp_info)
                    .unwrap();

                assert_eq!(
                    helpers::pubkey_to_uncompressed(&pub_direct),
                    helpers::pubkey_to_uncompressed(&pub_exported),
                    "{}: wolf exported path should produce same key pair as direct path",
                    $variant
                );
            }

            #[test]
            fn exported_matches_direct_ref() {
                let mut backend = $new_ref();
                let measurement = $make_meas(0x30);
                let info = b"equiv-test";
                let label = b"equiv-label";
                let kp_info = b"equiv-kp-info";

                let cdi = backend.derive_cdi(&measurement, info).unwrap();
                let (_priv_direct, pub_direct) =
                    backend.derive_key_pair(&cdi, label, kp_info).unwrap();

                let mut backend2 = $new_ref();
                let handle = backend2
                    .derive_exported_cdi(&measurement, info)
                    .unwrap();
                let (_priv_exported, pub_exported) = backend2
                    .derive_key_pair_exported(&handle, label, kp_info)
                    .unwrap();

                assert_eq!(
                    helpers::pubkey_to_uncompressed(&pub_direct),
                    helpers::pubkey_to_uncompressed(&pub_exported),
                    "{}: ref exported path should produce same key pair as direct path",
                    $variant
                );
            }

            #[test]
            fn invalid_handle_rejected_wolf() {
                let mut backend = $new_wolf();
                let bad_handle = [0xFFu8; 32];
                let result =
                    backend.derive_key_pair_exported(&bad_handle, b"label", b"info");
                match result {
                    Err(CryptoError::InvalidExportedCdiHandle) => {}
                    Err(other) => panic!(
                        "{}: wolf expected InvalidExportedCdiHandle, got {:?}",
                        $variant, other
                    ),
                    Ok(_) => panic!(
                        "{}: wolf should reject invalid handle, but got Ok",
                        $variant
                    ),
                }
            }

            #[test]
            fn invalid_handle_rejected_ref() {
                let mut backend = $new_ref();
                let bad_handle = [0xFFu8; 32];
                let result =
                    backend.derive_key_pair_exported(&bad_handle, b"label", b"info");
                match result {
                    Err(CryptoError::InvalidExportedCdiHandle) => {}
                    Err(other) => panic!(
                        "{}: ref expected InvalidExportedCdiHandle, got {:?}",
                        $variant, other
                    ),
                    Ok(_) => panic!(
                        "{}: ref should reject invalid handle, but got Ok",
                        $variant
                    ),
                }
            }

            #[test]
            fn duplicate_cdi_rejected_wolf() {
                let mut backend = $new_wolf();
                let measurement = $make_meas(0x40);
                let _handle = backend
                    .derive_exported_cdi(&measurement, b"dup-test")
                    .expect("first derive_exported_cdi should succeed");
                // Same measurement and info again
                let result = backend.derive_exported_cdi(&measurement, b"dup-test");
                match result {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi) => {}
                    other => panic!(
                        "{}: wolf should reject duplicate CDI with ExportedCdiHandleDuplicateCdi, got {:?}",
                        $variant, other
                    ),
                }
            }

            #[test]
            fn duplicate_cdi_rejected_ref() {
                let mut backend = $new_ref();
                let measurement = $make_meas(0x40);
                let _handle = backend
                    .derive_exported_cdi(&measurement, b"dup-test")
                    .expect("first derive_exported_cdi should succeed");
                let result = backend.derive_exported_cdi(&measurement, b"dup-test");
                match result {
                    Err(CryptoError::ExportedCdiHandleDuplicateCdi) => {}
                    other => panic!(
                        "{}: ref should reject duplicate CDI with ExportedCdiHandleDuplicateCdi, got {:?}",
                        $variant, other
                    ),
                }
            }

            #[test]
            fn slot_limit_exceeded_wolf() {
                let mut backend = $new_wolf();
                // Fill the single slot
                let meas1 = $make_meas(0x50);
                let _handle = backend
                    .derive_exported_cdi(&meas1, b"slot-fill")
                    .expect("first slot should succeed");

                // Try a different CDI
                let meas2 = $make_meas(0x51);
                let result = backend.derive_exported_cdi(&meas2, b"slot-overflow");
                match result {
                    Err(CryptoError::ExportedCdiHandleLimitExceeded) => {}
                    other => panic!(
                        "{}: wolf should reject exceeding slot limit with ExportedCdiHandleLimitExceeded, got {:?}",
                        $variant, other
                    ),
                }
            }

            #[test]
            fn slot_limit_exceeded_ref() {
                let mut backend = $new_ref();
                let meas1 = $make_meas(0x50);
                let _handle = backend
                    .derive_exported_cdi(&meas1, b"slot-fill")
                    .expect("first slot should succeed");

                let meas2 = $make_meas(0x51);
                let result = backend.derive_exported_cdi(&meas2, b"slot-overflow");
                match result {
                    Err(CryptoError::ExportedCdiHandleLimitExceeded) => {}
                    other => panic!(
                        "{}: ref should reject exceeding slot limit with ExportedCdiHandleLimitExceeded, got {:?}",
                        $variant, other
                    ),
                }
            }
        }
    };
}

exported_cdi_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::fixed_measurement_384,
    helpers::verify_p384_signature,
    "P-384"
);

exported_cdi_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::fixed_measurement_256,
    helpers::verify_p256_signature,
    "P-256"
);
