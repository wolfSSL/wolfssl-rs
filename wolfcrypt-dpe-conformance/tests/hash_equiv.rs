//! Hash output equivalence tests between wolf and reference backends.
//! Each test is instantiated for both P-384/SHA-384 and P-256/SHA-256.

mod helpers;

macro_rules! hash_equiv_tests {
    ($mod_name:ident, $new_wolf:path, $new_ref:path, $make_meas:path, $variant:expr) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, Hasher};

            #[test]
            fn empty_input_equiv() {
                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_digest = wolf.hash(b"").unwrap();
                let ref_digest = refb.hash(b"").unwrap();

                assert_eq!(
                    wolf_digest.as_slice(),
                    ref_digest.as_slice(),
                    "{}: empty input hash mismatch between wolf and ref",
                    $variant
                );
            }

            #[test]
            fn abc_equiv() {
                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_digest = wolf.hash(b"abc").unwrap();
                let ref_digest = refb.hash(b"abc").unwrap();

                assert_eq!(
                    wolf_digest.as_slice(),
                    ref_digest.as_slice(),
                    "{}: hash of b\"abc\" mismatch between wolf and ref",
                    $variant
                );
            }

            #[test]
            fn random_inputs_equiv() {
                use rand::RngCore;
                let mut rng = rand::thread_rng();

                for len in [1, 55, 56, 64, 128, 1024, 65536] {
                    let data = helpers::random_info(&mut rng, len);

                    let mut wolf = $new_wolf();
                    let mut refb = $new_ref();

                    let wolf_digest = wolf.hash(&data).unwrap();
                    let ref_digest = refb.hash(&data).unwrap();

                    assert_eq!(
                        wolf_digest.as_slice(),
                        ref_digest.as_slice(),
                        "{}: random input hash mismatch at length {}",
                        $variant,
                        len
                    );
                }
            }

            #[test]
            fn streaming_matches_oneshot_wolf() {
                let data = b"The quick brown fox jumps over the lazy dog and keeps running";
                let mut wolf = $new_wolf();

                let oneshot = wolf.hash(data).unwrap();

                let mut hasher = wolf.hash_initialize().unwrap();
                hasher.update(data).unwrap();
                let streaming = hasher.finish().unwrap();

                assert_eq!(
                    oneshot.as_slice(),
                    streaming.as_slice(),
                    "{}: wolf streaming hash does not match oneshot",
                    $variant
                );
            }

            #[test]
            fn streaming_matches_oneshot_ref() {
                let data = b"The quick brown fox jumps over the lazy dog and keeps running";
                let mut refb = $new_ref();

                let oneshot = refb.hash(data).unwrap();

                let mut hasher = refb.hash_initialize().unwrap();
                hasher.update(data).unwrap();
                let streaming = hasher.finish().unwrap();

                assert_eq!(
                    oneshot.as_slice(),
                    streaming.as_slice(),
                    "{}: ref streaming hash does not match oneshot",
                    $variant
                );
            }

            #[test]
            fn streaming_equiv() {
                let data = b"Shared streaming data for cross-backend equivalence check";
                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let mut wolf_hasher = wolf.hash_initialize().unwrap();
                wolf_hasher.update(&data[..20]).unwrap();
                wolf_hasher.update(&data[20..]).unwrap();
                let wolf_digest = wolf_hasher.finish().unwrap();

                let mut ref_hasher = refb.hash_initialize().unwrap();
                ref_hasher.update(&data[..20]).unwrap();
                ref_hasher.update(&data[20..]).unwrap();
                let ref_digest = ref_hasher.finish().unwrap();

                assert_eq!(
                    wolf_digest.as_slice(),
                    ref_digest.as_slice(),
                    "{}: streaming hash mismatch between wolf and ref",
                    $variant
                );
            }

            #[test]
            fn many_small_updates_equiv() {
                use rand::RngCore;
                let mut rng = rand::thread_rng();
                let mut data = [0u8; 256];
                rng.fill_bytes(&mut data);

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let mut wolf_hasher = wolf.hash_initialize().unwrap();
                let mut ref_hasher = refb.hash_initialize().unwrap();

                for byte in &data {
                    wolf_hasher.update(core::slice::from_ref(byte)).unwrap();
                    ref_hasher.update(core::slice::from_ref(byte)).unwrap();
                }

                let wolf_digest = wolf_hasher.finish().unwrap();
                let ref_digest = ref_hasher.finish().unwrap();

                assert_eq!(
                    wolf_digest.as_slice(),
                    ref_digest.as_slice(),
                    "{}: many small updates hash mismatch between wolf and ref",
                    $variant
                );
            }

            #[test]
            fn canary_different_input() {
                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                let wolf_digest = wolf.hash(b"A").unwrap();
                let ref_digest = refb.hash(b"B").unwrap();

                assert_ne!(
                    wolf_digest.as_slice(),
                    ref_digest.as_slice(),
                    "{}: hash of different inputs should differ",
                    $variant
                );
            }
        }
    };
}

hash_equiv_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::random_measurement_384,
    "P-384/SHA-384"
);

hash_equiv_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::random_measurement_256,
    "P-256/SHA-256"
);
