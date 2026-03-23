mod helpers;

macro_rules! cbc_equiv {
    ($mod_name:ident, $wolf_enc:ty, $wolf_dec:ty, $pure_enc:ty, $pure_dec:ty, $key_len:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            // CBC operates on whole blocks — use BLOCK_ALIGNED_LENGTHS
            // (contrast with CTR/CFB which accept arbitrary lengths).
            use super::helpers::{
                random_bytes, encrypt_blocks_with, decrypt_blocks_with,
                BLOCK_ALIGNED_LENGTHS,
            };
            use rand::thread_rng;

            const KEY_LEN: usize = $key_len;
            const BLOCK: usize = 16;
            const IV_LEN: usize = 16;

            #[test]
            fn single_block_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, BLOCK);

                let wolf_ct = encrypt_blocks_with::<$wolf_enc>(&key, &iv, &pt);
                let pure_ct = encrypt_blocks_with::<$pure_enc>(&key, &iv, &pt);

                assert_eq!(
                    wolf_ct, pure_ct,
                    "{}: single-block CBC encrypt mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn multi_block_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, BLOCK * 8);

                let wolf_ct = encrypt_blocks_with::<$wolf_enc>(&key, &iv, &pt);
                let pure_ct = encrypt_blocks_with::<$pure_enc>(&key, &iv, &pt);

                assert_eq!(
                    wolf_ct, pure_ct,
                    "{}: multi-block CBC encrypt mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn cross_round_trip() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, BLOCK * 4);

                // Wolf encrypts, pure decrypts
                let wolf_ct = encrypt_blocks_with::<$wolf_enc>(&key, &iv, &pt);
                let recovered_a = decrypt_blocks_with::<$pure_dec>(&key, &iv, &wolf_ct);
                assert_eq!(
                    recovered_a, pt,
                    "{}: pure must decrypt what wolf encrypted",
                    stringify!($mod_name)
                );

                // Pure encrypts, wolf decrypts
                let pure_ct = encrypt_blocks_with::<$pure_enc>(&key, &iv, &pt);
                let recovered_b = decrypt_blocks_with::<$wolf_dec>(&key, &iv, &pure_ct);
                assert_eq!(
                    recovered_b, pt,
                    "{}: wolf must decrypt what pure encrypted",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn random_data_equiv() {
                let mut rng = thread_rng();

                for &total_len in BLOCK_ALIGNED_LENGTHS {
                    let key = random_bytes(&mut rng, KEY_LEN);
                    let iv = random_bytes(&mut rng, IV_LEN);
                    let pt = random_bytes(&mut rng, total_len);

                    let wolf_ct = encrypt_blocks_with::<$wolf_enc>(&key, &iv, &pt);
                    let pure_ct = encrypt_blocks_with::<$pure_enc>(&key, &iv, &pt);

                    assert_eq!(
                        wolf_ct, pure_ct,
                        "{}: random data CBC mismatch at len={}",
                        stringify!($mod_name),
                        total_len
                    );
                }
            }

            #[test]
            fn iv_matters() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv_a = random_bytes(&mut rng, IV_LEN);
                let iv_b = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, BLOCK * 2);

                let ct_a = encrypt_blocks_with::<$wolf_enc>(&key, &iv_a, &pt);
                let ct_b = encrypt_blocks_with::<$wolf_enc>(&key, &iv_b, &pt);

                assert_ne!(
                    ct_a, ct_b,
                    "{}: same key+PT with different IVs must produce different CTs",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_wrong_iv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv_enc = random_bytes(&mut rng, IV_LEN);
                let iv_dec = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, BLOCK * 2);

                let ct = encrypt_blocks_with::<$wolf_enc>(&key, &iv_enc, &pt);
                let wrong_pt = decrypt_blocks_with::<$wolf_dec>(&key, &iv_dec, &ct);

                assert_ne!(
                    wrong_pt, pt,
                    "{}: decrypting with wrong IV must not recover original plaintext",
                    stringify!($mod_name)
                );
            }
        }
    };
}

cbc_equiv!(
    aes128_cbc,
    wolfcrypt::Aes128CbcEnc,
    wolfcrypt::Aes128CbcDec,
    cbc::Encryptor<aes::Aes128>,
    cbc::Decryptor<aes::Aes128>,
    16,
    [wolfssl_openssl_extra]
);

cbc_equiv!(
    aes192_cbc,
    wolfcrypt::Aes192CbcEnc,
    wolfcrypt::Aes192CbcDec,
    cbc::Encryptor<aes::Aes192>,
    cbc::Decryptor<aes::Aes192>,
    24,
    [wolfssl_openssl_extra, wolfssl_aes_192]
);

cbc_equiv!(
    aes256_cbc,
    wolfcrypt::Aes256CbcEnc,
    wolfcrypt::Aes256CbcDec,
    cbc::Encryptor<aes::Aes256>,
    cbc::Decryptor<aes::Aes256>,
    32,
    [wolfssl_openssl_extra]
);
