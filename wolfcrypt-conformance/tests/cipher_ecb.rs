mod helpers;

macro_rules! ecb_equiv {
    ($mod_name:ident, $wolf_enc:ty, $wolf_dec:ty, $pure:ty, $key_len:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::{random_bytes, BLOCK_ALIGNED_LENGTHS};
            use cipher::generic_array::GenericArray;
            use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
            use rand::thread_rng;

            const KEY_LEN: usize = $key_len;
            const BLOCK: usize = 16;

            #[test]
            fn single_block_encrypt_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let pt = random_bytes(&mut rng, BLOCK);

                let wolf = <$wolf_enc>::new(GenericArray::from_slice(&key));
                let mut wb = GenericArray::clone_from_slice(&pt);
                wolf.encrypt_block(&mut wb);

                let pure = <$pure>::new(GenericArray::from_slice(&key));
                let mut pb = GenericArray::clone_from_slice(&pt);
                pure.encrypt_block(&mut pb);

                assert_eq!(
                    wb, pb,
                    "{}: single-block ECB encrypt mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn single_block_decrypt_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let pt = random_bytes(&mut rng, BLOCK);

                // Create a valid ciphertext using pure
                let pure = <$pure>::new(GenericArray::from_slice(&key));
                let mut ct = GenericArray::clone_from_slice(&pt);
                pure.encrypt_block(&mut ct);

                // Decrypt with wolf
                let wolf = <$wolf_dec>::new(GenericArray::from_slice(&key));
                let mut wolf_pt = ct.clone();
                wolf.decrypt_block(&mut wolf_pt);

                // Decrypt with pure
                let pure2 = <$pure>::new(GenericArray::from_slice(&key));
                let mut pure_pt = ct.clone();
                pure2.decrypt_block(&mut pure_pt);

                assert_eq!(
                    wolf_pt, pure_pt,
                    "{}: single-block ECB decrypt mismatch",
                    stringify!($mod_name)
                );
                assert_eq!(
                    wolf_pt.as_slice(),
                    &pt[..],
                    "{}: decrypted block must match original plaintext",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn round_trip_cross() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let pt = random_bytes(&mut rng, BLOCK);

                // Wolf encrypts, pure decrypts
                let wolf_enc = <$wolf_enc>::new(GenericArray::from_slice(&key));
                let mut ct_a = GenericArray::clone_from_slice(&pt);
                wolf_enc.encrypt_block(&mut ct_a);

                let pure = <$pure>::new(GenericArray::from_slice(&key));
                let mut recovered_a = ct_a.clone();
                pure.decrypt_block(&mut recovered_a);

                assert_eq!(
                    recovered_a.as_slice(),
                    &pt[..],
                    "{}: pure must decrypt what wolf encrypted",
                    stringify!($mod_name)
                );

                // Pure encrypts, wolf decrypts
                let pure2 = <$pure>::new(GenericArray::from_slice(&key));
                let mut ct_b = GenericArray::clone_from_slice(&pt);
                pure2.encrypt_block(&mut ct_b);

                let wolf_dec = <$wolf_dec>::new(GenericArray::from_slice(&key));
                let mut recovered_b = ct_b.clone();
                wolf_dec.decrypt_block(&mut recovered_b);

                assert_eq!(
                    recovered_b.as_slice(),
                    &pt[..],
                    "{}: wolf must decrypt what pure encrypted",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn multi_block_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let num_blocks = 8;
                let pt = random_bytes(&mut rng, BLOCK * num_blocks);

                let wolf = <$wolf_enc>::new(GenericArray::from_slice(&key));
                let pure = <$pure>::new(GenericArray::from_slice(&key));

                for (i, chunk) in pt.chunks(BLOCK).enumerate() {
                    let mut wb = GenericArray::clone_from_slice(chunk);
                    wolf.encrypt_block(&mut wb);

                    let mut pb = GenericArray::clone_from_slice(chunk);
                    pure.encrypt_block(&mut pb);

                    assert_eq!(
                        wb, pb,
                        "{}: multi-block ECB encrypt mismatch at block {}",
                        stringify!($mod_name),
                        i
                    );
                }
            }

            #[test]
            fn random_blocks_equiv() {
                let mut rng = thread_rng();

                for &total_len in BLOCK_ALIGNED_LENGTHS {
                    let key = random_bytes(&mut rng, KEY_LEN);
                    let pt = random_bytes(&mut rng, total_len);

                    let wolf = <$wolf_enc>::new(GenericArray::from_slice(&key));
                    let pure = <$pure>::new(GenericArray::from_slice(&key));

                    for (i, chunk) in pt.chunks(BLOCK).enumerate() {
                        let mut wb = GenericArray::clone_from_slice(chunk);
                        wolf.encrypt_block(&mut wb);

                        let mut pb = GenericArray::clone_from_slice(chunk);
                        pure.encrypt_block(&mut pb);

                        assert_eq!(
                            wb, pb,
                            "{}: random blocks mismatch at len={} block={}",
                            stringify!($mod_name),
                            total_len,
                            i
                        );
                    }
                }
            }

            #[test]
            fn canary_wrong_key() {
                let mut rng = thread_rng();
                let key_a = random_bytes(&mut rng, KEY_LEN);
                let key_b = random_bytes(&mut rng, KEY_LEN);
                let pt = random_bytes(&mut rng, BLOCK);

                let enc_a = <$wolf_enc>::new(GenericArray::from_slice(&key_a));
                let mut ct_a = GenericArray::clone_from_slice(&pt);
                enc_a.encrypt_block(&mut ct_a);

                let enc_b = <$wolf_enc>::new(GenericArray::from_slice(&key_b));
                let mut ct_b = GenericArray::clone_from_slice(&pt);
                enc_b.encrypt_block(&mut ct_b);

                assert_ne!(
                    ct_a, ct_b,
                    "{}: different keys must produce different ECB ciphertexts",
                    stringify!($mod_name)
                );
            }
        }
    };
}

ecb_equiv!(
    aes128_ecb,
    wolfcrypt::Aes128EcbEnc,
    wolfcrypt::Aes128EcbDec,
    aes::Aes128,
    16,
    [wolfssl_openssl_extra, wolfssl_aes_ecb]
);

ecb_equiv!(
    aes192_ecb,
    wolfcrypt::Aes192EcbEnc,
    wolfcrypt::Aes192EcbDec,
    aes::Aes192,
    24,
    [wolfssl_openssl_extra, wolfssl_aes_ecb, wolfssl_aes_192]
);

ecb_equiv!(
    aes256_ecb,
    wolfcrypt::Aes256EcbEnc,
    wolfcrypt::Aes256EcbDec,
    aes::Aes256,
    32,
    [wolfssl_openssl_extra, wolfssl_aes_ecb]
);
