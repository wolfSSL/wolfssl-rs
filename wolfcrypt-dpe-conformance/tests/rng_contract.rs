//! RNG contract compliance tests.
//!
//! RNG outputs cannot be compared between backends (different entropy sources),
//! so these tests verify the contract/format only: buffers are filled, outputs
//! are non-constant, and various sizes are handled.

mod helpers;

macro_rules! rng_contract_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $variant:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::Crypto;

            #[test]
            fn rand_bytes_fills_buffer_wolf() {
                let mut backend = $new_wolf();
                let mut buf = [0u8; 64];
                backend
                    .rand_bytes(&mut buf)
                    .expect("wolf rand_bytes(64) should succeed");
                assert!(
                    buf.iter().any(|&b| b != 0),
                    "{}: wolf 64-byte random buffer should not be all zeros",
                    $variant
                );
            }

            #[test]
            fn rand_bytes_fills_buffer_ref() {
                let mut backend = $new_ref();
                let mut buf = [0u8; 64];
                backend
                    .rand_bytes(&mut buf)
                    .expect("ref rand_bytes(64) should succeed");
                assert!(
                    buf.iter().any(|&b| b != 0),
                    "{}: ref 64-byte random buffer should not be all zeros",
                    $variant
                );
            }

            #[test]
            fn rand_bytes_not_constant_wolf() {
                let mut backend = $new_wolf();
                let mut buf_a = [0u8; 32];
                let mut buf_b = [0u8; 32];
                backend.rand_bytes(&mut buf_a).unwrap();
                backend.rand_bytes(&mut buf_b).unwrap();
                assert_ne!(
                    buf_a, buf_b,
                    "{}: wolf two consecutive rand_bytes calls should produce different output",
                    $variant
                );
            }

            #[test]
            fn rand_bytes_not_constant_ref() {
                let mut backend = $new_ref();
                let mut buf_a = [0u8; 32];
                let mut buf_b = [0u8; 32];
                backend.rand_bytes(&mut buf_a).unwrap();
                backend.rand_bytes(&mut buf_b).unwrap();
                assert_ne!(
                    buf_a, buf_b,
                    "{}: ref two consecutive rand_bytes calls should produce different output",
                    $variant
                );
            }

            #[test]
            fn rand_bytes_various_sizes_wolf() {
                let mut backend = $new_wolf();
                for &size in &[1usize, 16, 32, 48, 64, 256, 1024] {
                    let mut buf = vec![0u8; size];
                    backend.rand_bytes(&mut buf).unwrap_or_else(|e| {
                        panic!(
                            "{}: wolf rand_bytes({}) should succeed, got {:?}",
                            $variant, size, e
                        )
                    });
                }
            }

            #[test]
            fn rand_bytes_various_sizes_ref() {
                let mut backend = $new_ref();
                for &size in &[1usize, 16, 32, 48, 64, 256, 1024] {
                    let mut buf = vec![0u8; size];
                    backend.rand_bytes(&mut buf).unwrap_or_else(|e| {
                        panic!(
                            "{}: ref rand_bytes({}) should succeed, got {:?}",
                            $variant, size, e
                        )
                    });
                }
            }

            #[test]
            fn rand_bytes_zero_size_wolf() {
                let mut backend = $new_wolf();
                let mut buf = [];
                backend
                    .rand_bytes(&mut buf)
                    .expect(concat!(
                        $variant,
                        ": wolf rand_bytes on empty buffer should succeed"
                    ));
            }

            #[test]
            fn rand_bytes_zero_size_ref() {
                let mut backend = $new_ref();
                let mut buf = [];
                backend
                    .rand_bytes(&mut buf)
                    .expect(concat!(
                        $variant,
                        ": ref rand_bytes on empty buffer should succeed"
                    ));
            }

            #[test]
            fn rand_bytes_fills_entire_wolf() {
                let mut backend = $new_wolf();
                let mut buf = [0xFFu8; 64];
                backend
                    .rand_bytes(&mut buf)
                    .expect("wolf rand_bytes should succeed");
                assert!(
                    buf.iter().any(|&b| b != 0xFF),
                    "{}: wolf rand_bytes should overwrite at least some 0xFF bytes in a 64-byte buffer",
                    $variant
                );
            }

            #[test]
            fn rand_bytes_fills_entire_ref() {
                let mut backend = $new_ref();
                let mut buf = [0xFFu8; 64];
                backend
                    .rand_bytes(&mut buf)
                    .expect("ref rand_bytes should succeed");
                assert!(
                    buf.iter().any(|&b| b != 0xFF),
                    "{}: ref rand_bytes should overwrite at least some 0xFF bytes in a 64-byte buffer",
                    $variant
                );
            }
        }
    };
}

rng_contract_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    "P-384"
);

rng_contract_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    "P-256"
);
