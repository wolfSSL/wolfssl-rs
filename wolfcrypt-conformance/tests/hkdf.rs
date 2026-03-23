#![cfg(wolfssl_hkdf)]

mod helpers;

macro_rules! hkdf_equiv {
    ($mod_name:ident, $wolf:ty, $pure_hash:ty, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;
            use rand::Rng;

            type Wolf = $wolf;
            type PureHkdf = hkdf::Hkdf<$pure_hash>;

            #[test]
            fn extract_equiv() {
                let mut rng = rand::thread_rng();
                let salt = random_bytes(&mut rng, 32);
                let ikm = random_bytes(&mut rng, 64);

                let (wolf_prk, _wolf_hkdf) = Wolf::extract(Some(&salt), &ikm);
                let (pure_prk, _pure_hkdf) = PureHkdf::extract(Some(&salt), &ikm);

                assert_eq!(
                    wolf_prk.as_slice(),
                    pure_prk.as_slice(),
                    "{}: PRK mismatch after extract with same salt+IKM",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn expand_equiv() {
                let mut rng = rand::thread_rng();
                let salt = random_bytes(&mut rng, 32);
                let ikm = random_bytes(&mut rng, 64);
                let info = random_bytes(&mut rng, 16);

                let (wolf_prk, _) = Wolf::extract(Some(&salt), &ikm);
                let wolf_hkdf = Wolf::from_prk(wolf_prk.as_slice())
                    .expect("wolf: from_prk should succeed");

                let (pure_prk, _) = PureHkdf::extract(Some(&salt), &ikm);
                let pure_hkdf = PureHkdf::from_prk(pure_prk.as_slice())
                    .expect("pure: from_prk should succeed");

                let mut wolf_okm = vec![0u8; 48];
                let mut pure_okm = vec![0u8; 48];
                wolf_hkdf.expand(&info, &mut wolf_okm)
                    .expect("wolf: expand should succeed");
                pure_hkdf.expand(&info, &mut pure_okm)
                    .expect("pure: expand should succeed");

                assert_eq!(
                    wolf_okm, pure_okm,
                    "{}: OKM mismatch after expand with same PRK+info",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn extract_expand_equiv() {
                let mut rng = rand::thread_rng();
                let salt = random_bytes(&mut rng, 20);
                let ikm = random_bytes(&mut rng, 48);
                let info = random_bytes(&mut rng, 10);

                let wolf_hkdf = Wolf::new(Some(&salt), &ikm);
                let pure_hkdf = PureHkdf::new(Some(&salt), &ikm);

                let mut wolf_okm = vec![0u8; 64];
                let mut pure_okm = vec![0u8; 64];
                wolf_hkdf.expand(&info, &mut wolf_okm)
                    .expect("wolf: expand should succeed");
                pure_hkdf.expand(&info, &mut pure_okm)
                    .expect("pure: expand should succeed");

                assert_eq!(
                    wolf_okm, pure_okm,
                    "{}: full extract+expand pipeline OKM mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn no_salt_equiv() {
                let mut rng = rand::thread_rng();
                let ikm = random_bytes(&mut rng, 32);

                let (wolf_prk, _) = Wolf::extract(None, &ikm);
                let (pure_prk, _) = PureHkdf::extract(None, &ikm);

                assert_eq!(
                    wolf_prk.as_slice(),
                    pure_prk.as_slice(),
                    "{}: PRK mismatch with no salt (None)",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn various_okm_lengths() {
                let mut rng = rand::thread_rng();
                let salt = random_bytes(&mut rng, 16);
                let ikm = random_bytes(&mut rng, 32);
                let info = b"okm length test";

                let wolf_hkdf = Wolf::new(Some(&salt), &ikm);
                let pure_hkdf = PureHkdf::new(Some(&salt), &ikm);

                for &okm_len in &[16, 32, 48, 64, 128] {
                    let mut wolf_okm = vec![0u8; okm_len];
                    let mut pure_okm = vec![0u8; okm_len];

                    wolf_hkdf.expand(info, &mut wolf_okm)
                        .unwrap_or_else(|e| panic!(
                            "{}: wolf expand failed for OKM length {okm_len}: {e}",
                            stringify!($mod_name)
                        ));
                    pure_hkdf.expand(info, &mut pure_okm)
                        .unwrap_or_else(|e| panic!(
                            "{}: pure expand failed for OKM length {okm_len}: {e}",
                            stringify!($mod_name)
                        ));

                    assert_eq!(
                        wolf_okm, pure_okm,
                        "{}: OKM mismatch at length {okm_len}",
                        stringify!($mod_name)
                    );
                }
            }

            #[test]
            fn random_inputs_equiv() {
                let mut rng = rand::thread_rng();

                for i in 0..10 {
                    let ikm_len = rng.gen_range(16..=128);
                    let salt_len = rng.gen_range(0..=64);
                    let info_len = rng.gen_range(0..=64);
                    let okm_len = rng.gen_range(16..=128);

                    let ikm = random_bytes(&mut rng, ikm_len);
                    let salt = random_bytes(&mut rng, salt_len);
                    let info = random_bytes(&mut rng, info_len);

                    let salt_opt = if salt.is_empty() { None } else { Some(salt.as_slice()) };

                    let wolf_hkdf = Wolf::new(salt_opt, &ikm);
                    let pure_hkdf = PureHkdf::new(salt_opt, &ikm);

                    let mut wolf_okm = vec![0u8; okm_len];
                    let mut pure_okm = vec![0u8; okm_len];

                    wolf_hkdf.expand(&info, &mut wolf_okm)
                        .unwrap_or_else(|e| panic!(
                            "{} round {i}: wolf expand failed: {e}",
                            stringify!($mod_name)
                        ));
                    pure_hkdf.expand(&info, &mut pure_okm)
                        .unwrap_or_else(|e| panic!(
                            "{} round {i}: pure expand failed: {e}",
                            stringify!($mod_name)
                        ));

                    assert_eq!(
                        wolf_okm, pure_okm,
                        "{} round {i}: OKM mismatch with random inputs \
                         (ikm_len={ikm_len}, salt_len={salt_len}, info_len={info_len}, okm_len={okm_len})",
                        stringify!($mod_name)
                    );
                }
            }

            #[test]
            fn canary_different_ikm() {
                let mut rng = rand::thread_rng();
                let salt = random_bytes(&mut rng, 16);
                let ikm_a = random_bytes(&mut rng, 32);
                let ikm_b = random_bytes(&mut rng, 32);
                let info = b"canary different IKM";

                let wolf_a = Wolf::new(Some(&salt), &ikm_a);
                let wolf_b = Wolf::new(Some(&salt), &ikm_b);

                let mut okm_a = vec![0u8; 32];
                let mut okm_b = vec![0u8; 32];
                wolf_a.expand(info, &mut okm_a)
                    .expect("wolf: expand A should succeed");
                wolf_b.expand(info, &mut okm_b)
                    .expect("wolf: expand B should succeed");

                assert_ne!(
                    okm_a, okm_b,
                    "{}: different IKM must produce different OKM",
                    stringify!($mod_name)
                );
            }
        }
    };
}

// RFC 5869 Test Case 1 (SHA-256) — tested separately outside the macro
// because the known-answer vector is specific to SHA-256.
#[test]
fn rfc5869_vector_1() {
    use hex_literal::hex;
    use wolfcrypt::WolfHkdfSha256;

    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex!(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    );

    // Wolf
    let wolf_hkdf = WolfHkdfSha256::new(Some(&salt), &ikm);
    let mut wolf_okm = vec![0u8; 42];
    wolf_hkdf.expand(&info, &mut wolf_okm)
        .expect("wolf: RFC 5869 vector 1 expand should succeed");

    assert_eq!(
        wolf_okm,
        expected_okm.as_slice(),
        "wolf: RFC 5869 Test Case 1 OKM does not match known answer"
    );

    // Pure
    let pure_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm);
    let mut pure_okm = vec![0u8; 42];
    pure_hkdf.expand(&info, &mut pure_okm)
        .expect("pure: RFC 5869 vector 1 expand should succeed");

    assert_eq!(
        pure_okm,
        expected_okm.as_slice(),
        "pure: RFC 5869 Test Case 1 OKM does not match known answer"
    );

    assert_eq!(
        wolf_okm, pure_okm,
        "RFC 5869 Test Case 1: wolf and pure OKM must be identical"
    );
}

hkdf_equiv!(
    hkdf_sha256,
    wolfcrypt::WolfHkdfSha256,
    sha2::Sha256,
    [wolfssl_hkdf]
);

hkdf_equiv!(
    hkdf_sha384,
    wolfcrypt::WolfHkdfSha384,
    sha2::Sha384,
    [wolfssl_hkdf, wolfssl_sha384]
);

hkdf_equiv!(
    hkdf_sha512,
    wolfcrypt::WolfHkdfSha512,
    sha2::Sha512,
    [wolfssl_hkdf, wolfssl_sha512]
);
