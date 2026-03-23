#![cfg(wolfssl_pbkdf2)]

mod helpers;

macro_rules! pbkdf2_equiv {
    ($mod_name:ident, $wolf_fn:path, $pure_hash:ty, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;

            #[test]
            fn fixed_equiv() {
                let password = b"correct horse battery staple";
                let salt = b"sodium chloride 1234567890abcdef";
                let rounds = 1000u32;

                let mut wolf_out = vec![0u8; 32];
                $wolf_fn(password, salt, rounds, &mut wolf_out)
                    .expect("wolf: pbkdf2 should succeed");

                let mut pure_out = vec![0u8; 32];
                pbkdf2::pbkdf2_hmac::<$pure_hash>(password, salt, rounds, &mut pure_out);

                assert_eq!(
                    wolf_out, pure_out,
                    "{}: fixed password/salt/rounds=1000 DK mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn random_equiv() {
                let mut rng = rand::thread_rng();
                let password = random_bytes(&mut rng, 24);
                let salt = random_bytes(&mut rng, 16);

                for &rounds in &[1u32, 100, 1000] {
                    let mut wolf_out = vec![0u8; 32];
                    $wolf_fn(&password, &salt, rounds, &mut wolf_out)
                        .unwrap_or_else(|e| panic!(
                            "{}: wolf pbkdf2 failed at rounds={rounds}: {e}",
                            stringify!($mod_name)
                        ));

                    let mut pure_out = vec![0u8; 32];
                    pbkdf2::pbkdf2_hmac::<$pure_hash>(&password, &salt, rounds, &mut pure_out);

                    assert_eq!(
                        wolf_out, pure_out,
                        "{}: DK mismatch at rounds={rounds}",
                        stringify!($mod_name)
                    );
                }
            }

            #[test]
            fn various_output_lengths() {
                let mut rng = rand::thread_rng();
                let password = random_bytes(&mut rng, 20);
                let salt = random_bytes(&mut rng, 16);
                let rounds = 100u32;

                for &dk_len in &[16, 20, 32, 64] {
                    let mut wolf_out = vec![0u8; dk_len];
                    $wolf_fn(&password, &salt, rounds, &mut wolf_out)
                        .unwrap_or_else(|e| panic!(
                            "{}: wolf pbkdf2 failed at dk_len={dk_len}: {e}",
                            stringify!($mod_name)
                        ));

                    let mut pure_out = vec![0u8; dk_len];
                    pbkdf2::pbkdf2_hmac::<$pure_hash>(&password, &salt, rounds, &mut pure_out);

                    assert_eq!(
                        wolf_out, pure_out,
                        "{}: DK mismatch at output length {dk_len}",
                        stringify!($mod_name)
                    );
                }
            }

            #[test]
            fn single_round() {
                let mut rng = rand::thread_rng();
                let password = random_bytes(&mut rng, 16);
                let salt = random_bytes(&mut rng, 16);

                let mut wolf_out = vec![0u8; 32];
                $wolf_fn(&password, &salt, 1, &mut wolf_out)
                    .expect("wolf: pbkdf2 with 1 round should succeed");

                let mut pure_out = vec![0u8; 32];
                pbkdf2::pbkdf2_hmac::<$pure_hash>(&password, &salt, 1, &mut pure_out);

                assert_eq!(
                    wolf_out, pure_out,
                    "{}: DK mismatch with single round",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_different_password() {
                let mut rng = rand::thread_rng();
                let password_a = random_bytes(&mut rng, 16);
                let password_b = random_bytes(&mut rng, 16);
                let salt = random_bytes(&mut rng, 16);

                let mut dk_a = vec![0u8; 32];
                let mut dk_b = vec![0u8; 32];
                $wolf_fn(&password_a, &salt, 100, &mut dk_a)
                    .expect("wolf: pbkdf2 A should succeed");
                $wolf_fn(&password_b, &salt, 100, &mut dk_b)
                    .expect("wolf: pbkdf2 B should succeed");

                assert_ne!(
                    dk_a, dk_b,
                    "{}: different passwords must produce different DK",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_different_salt() {
                let mut rng = rand::thread_rng();
                let password = random_bytes(&mut rng, 16);
                let salt_a = random_bytes(&mut rng, 16);
                let salt_b = random_bytes(&mut rng, 16);

                let mut dk_a = vec![0u8; 32];
                let mut dk_b = vec![0u8; 32];
                $wolf_fn(&password, &salt_a, 100, &mut dk_a)
                    .expect("wolf: pbkdf2 with salt A should succeed");
                $wolf_fn(&password, &salt_b, 100, &mut dk_b)
                    .expect("wolf: pbkdf2 with salt B should succeed");

                assert_ne!(
                    dk_a, dk_b,
                    "{}: different salts must produce different DK",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_different_rounds() {
                let mut rng = rand::thread_rng();
                let password = random_bytes(&mut rng, 16);
                let salt = random_bytes(&mut rng, 16);

                let mut dk_100 = vec![0u8; 32];
                let mut dk_200 = vec![0u8; 32];
                $wolf_fn(&password, &salt, 100, &mut dk_100)
                    .expect("wolf: pbkdf2 with 100 rounds should succeed");
                $wolf_fn(&password, &salt, 200, &mut dk_200)
                    .expect("wolf: pbkdf2 with 200 rounds should succeed");

                assert_ne!(
                    dk_100, dk_200,
                    "{}: different iteration counts must produce different DK",
                    stringify!($mod_name)
                );
            }
        }
    };
}

pbkdf2_equiv!(
    pbkdf2_sha256,
    wolfcrypt::pbkdf2_hmac_sha256,
    sha2::Sha256,
    [wolfssl_pbkdf2]
);

pbkdf2_equiv!(
    pbkdf2_sha384,
    wolfcrypt::pbkdf2_hmac_sha384,
    sha2::Sha384,
    [wolfssl_pbkdf2, wolfssl_sha384]
);

pbkdf2_equiv!(
    pbkdf2_sha512,
    wolfcrypt::pbkdf2_hmac_sha512,
    sha2::Sha512,
    [wolfssl_pbkdf2, wolfssl_sha512]
);
