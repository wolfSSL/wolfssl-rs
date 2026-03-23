//! Hasher streaming trait contract tests.
//!
//! Verifies that the streaming hasher (hash_initialize/update/finish)
//! produces results consistent with the one-shot hash(), for both backends.

mod helpers;

macro_rules! hasher_contract_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $variant:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, Hasher};

            #[test]
            fn empty_finish_wolf() {
                let mut backend = $new_wolf();
                let hasher = backend
                    .hash_initialize()
                    .expect("hash_initialize should succeed");
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(b"").expect("hash(empty) should succeed");
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: wolf empty finish should equal hash(b\"\")",
                    $variant
                );
            }

            #[test]
            fn empty_finish_ref() {
                let mut backend = $new_ref();
                let hasher = backend
                    .hash_initialize()
                    .expect("hash_initialize should succeed");
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(b"").expect("hash(empty) should succeed");
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: ref empty finish should equal hash(b\"\")",
                    $variant
                );
            }

            #[test]
            fn single_update_wolf() {
                let mut backend = $new_wolf();
                let data = b"The quick brown fox jumps over the lazy dog";

                let mut hasher = backend.hash_initialize().unwrap();
                hasher.update(data).expect("update should succeed");
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(data).unwrap();
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: wolf single update should equal one-shot hash",
                    $variant
                );
            }

            #[test]
            fn single_update_ref() {
                let mut backend = $new_ref();
                let data = b"The quick brown fox jumps over the lazy dog";

                let mut hasher = backend.hash_initialize().unwrap();
                hasher.update(data).expect("update should succeed");
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(data).unwrap();
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: ref single update should equal one-shot hash",
                    $variant
                );
            }

            #[test]
            fn many_small_updates_wolf() {
                let mut backend = $new_wolf();
                let mut rng = rand::thread_rng();
                let data = helpers::random_info(&mut rng, 256);

                let mut hasher = backend.hash_initialize().unwrap();
                for &byte in &data {
                    hasher
                        .update(&[byte])
                        .expect("byte-by-byte update should succeed");
                }
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(&data).unwrap();
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: wolf byte-by-byte streaming should equal one-shot hash",
                    $variant
                );
            }

            #[test]
            fn many_small_updates_ref() {
                let mut backend = $new_ref();
                let mut rng = rand::thread_rng();
                let data = helpers::random_info(&mut rng, 256);

                let mut hasher = backend.hash_initialize().unwrap();
                for &byte in &data {
                    hasher
                        .update(&[byte])
                        .expect("byte-by-byte update should succeed");
                }
                let streamed = hasher.finish().expect("finish should succeed");

                let oneshot = backend.hash(&data).unwrap();
                assert_eq!(
                    streamed.as_slice(),
                    oneshot.as_slice(),
                    "{}: ref byte-by-byte streaming should equal one-shot hash",
                    $variant
                );
            }

            #[test]
            fn two_hashers_independent_wolf() {
                let mut backend = $new_wolf();
                let data_a = b"data for hasher A";
                let data_b = b"data for hasher B -- different";

                let mut hasher_a = backend.hash_initialize().unwrap();
                let mut hasher_b = backend.hash_initialize().unwrap();

                hasher_a.update(data_a).unwrap();
                hasher_b.update(data_b).unwrap();

                let result_a = hasher_a.finish().unwrap();
                let result_b = hasher_b.finish().unwrap();

                assert_ne!(
                    result_a.as_slice(),
                    result_b.as_slice(),
                    "{}: wolf two independent hashers with different data must produce different digests",
                    $variant
                );

                let oneshot_a = backend.hash(data_a).unwrap();
                let oneshot_b = backend.hash(data_b).unwrap();
                assert_eq!(
                    result_a.as_slice(),
                    oneshot_a.as_slice(),
                    "{}: wolf hasher A result should match one-shot of data A",
                    $variant
                );
                assert_eq!(
                    result_b.as_slice(),
                    oneshot_b.as_slice(),
                    "{}: wolf hasher B result should match one-shot of data B",
                    $variant
                );
            }

            #[test]
            fn two_hashers_independent_ref() {
                let mut backend = $new_ref();
                let data_a = b"data for hasher A";
                let data_b = b"data for hasher B -- different";

                let mut hasher_a = backend.hash_initialize().unwrap();
                let mut hasher_b = backend.hash_initialize().unwrap();

                hasher_a.update(data_a).unwrap();
                hasher_b.update(data_b).unwrap();

                let result_a = hasher_a.finish().unwrap();
                let result_b = hasher_b.finish().unwrap();

                assert_ne!(
                    result_a.as_slice(),
                    result_b.as_slice(),
                    "{}: ref two independent hashers with different data must produce different digests",
                    $variant
                );

                let oneshot_a = backend.hash(data_a).unwrap();
                let oneshot_b = backend.hash(data_b).unwrap();
                assert_eq!(
                    result_a.as_slice(),
                    oneshot_a.as_slice(),
                    "{}: ref hasher A result should match one-shot of data A",
                    $variant
                );
                assert_eq!(
                    result_b.as_slice(),
                    oneshot_b.as_slice(),
                    "{}: ref hasher B result should match one-shot of data B",
                    $variant
                );
            }

            #[test]
            fn hasher_update_empty_slice_wolf() {
                let mut backend = $new_wolf();
                let data = b"some data before empty update";

                let mut hasher = backend.hash_initialize().unwrap();
                hasher.update(data).unwrap();
                hasher
                    .update(b"")
                    .expect("wolf update with empty slice should succeed");
                let with_empty = hasher.finish().unwrap();

                let mut hasher2 = backend.hash_initialize().unwrap();
                hasher2.update(data).unwrap();
                let without_empty = hasher2.finish().unwrap();

                assert_eq!(
                    with_empty.as_slice(),
                    without_empty.as_slice(),
                    "{}: wolf empty update should not change digest",
                    $variant
                );
            }

            #[test]
            fn hasher_update_empty_slice_ref() {
                let mut backend = $new_ref();
                let data = b"some data before empty update";

                let mut hasher = backend.hash_initialize().unwrap();
                hasher.update(data).unwrap();
                hasher
                    .update(b"")
                    .expect("ref update with empty slice should succeed");
                let with_empty = hasher.finish().unwrap();

                let mut hasher2 = backend.hash_initialize().unwrap();
                hasher2.update(data).unwrap();
                let without_empty = hasher2.finish().unwrap();

                assert_eq!(
                    with_empty.as_slice(),
                    without_empty.as_slice(),
                    "{}: ref empty update should not change digest",
                    $variant
                );
            }
        }
    };
}

hasher_contract_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    "P-384/SHA-384"
);

hasher_contract_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    "P-256/SHA-256"
);
