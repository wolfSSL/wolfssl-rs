mod helpers;

macro_rules! cfb_equiv {
    ($mod_name:ident, $wolf_enc:ty, $wolf_dec:ty, $pure_enc:ty, $pure_dec:ty, $key_len:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::{random_bytes, SYMMETRIC_LENGTHS};
            use cipher::generic_array::GenericArray;
            use cipher::{KeyIvInit, AsyncStreamCipher, StreamCipher};
            use rand::thread_rng;

            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = 16;

            // Wolf CFB types implement StreamCipher (apply_keystream).
            // Pure-Rust cfb-mode types implement AsyncStreamCipher (encrypt/decrypt).
            // We use the appropriate method for each.

            #[test]
            fn encrypt_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 64);

                let mut wolf_ct = pt.clone();
                let mut wolf = <$wolf_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                wolf.apply_keystream(&mut wolf_ct);

                let mut pure_ct = pt.clone();
                let pure = <$pure_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                pure.encrypt(&mut pure_ct);

                assert_eq!(
                    wolf_ct, pure_ct,
                    "{}: CFB encrypt must produce identical ciphertext",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn cross_round_trip() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 100);

                // Wolf encrypts, pure decrypts
                let mut ct = pt.clone();
                let mut wolf_enc = <$wolf_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                wolf_enc.apply_keystream(&mut ct);

                let mut recovered = ct.clone();
                let pure_dec = <$pure_dec>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                pure_dec.decrypt(&mut recovered);

                assert_eq!(
                    recovered, pt,
                    "{}: pure must decrypt what wolf encrypted in CFB",
                    stringify!($mod_name)
                );

                // Pure encrypts, wolf decrypts
                let mut ct2 = pt.clone();
                let pure_enc = <$pure_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                pure_enc.encrypt(&mut ct2);

                let mut recovered2 = ct2.clone();
                let mut wolf_dec = <$wolf_dec>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv),
                );
                wolf_dec.apply_keystream(&mut recovered2);

                assert_eq!(
                    recovered2, pt,
                    "{}: wolf must decrypt what pure encrypted in CFB",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn various_lengths() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);

                for &len in SYMMETRIC_LENGTHS {
                    // Fresh IV per length so each iteration exercises an
                    // independent keystream.
                    let iv = random_bytes(&mut rng, IV_LEN);
                    let pt = random_bytes(&mut rng, len);

                    let mut wolf_ct = pt.clone();
                    let mut wolf = <$wolf_enc>::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    wolf.apply_keystream(&mut wolf_ct);

                    let mut pure_ct = pt.clone();
                    let pure = <$pure_enc>::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    pure.encrypt(&mut pure_ct);

                    assert_eq!(
                        wolf_ct, pure_ct,
                        "{}: CFB mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn partial_block_equiv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv = random_bytes(&mut rng, IV_LEN);

                for &len in &[1usize, 7, 15] {
                    let pt = random_bytes(&mut rng, len);

                    let mut wolf_ct = pt.clone();
                    let mut wolf = <$wolf_enc>::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    wolf.apply_keystream(&mut wolf_ct);

                    let mut pure_ct = pt.clone();
                    let pure = <$pure_enc>::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    pure.encrypt(&mut pure_ct);

                    assert_eq!(
                        wolf_ct, pure_ct,
                        "{}: partial-block CFB mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn canary_different_iv() {
                let mut rng = thread_rng();
                let key = random_bytes(&mut rng, KEY_LEN);
                let iv_a = random_bytes(&mut rng, IV_LEN);
                let iv_b = random_bytes(&mut rng, IV_LEN);
                let pt = random_bytes(&mut rng, 32);

                let mut ct_a = pt.clone();
                let mut enc_a = <$wolf_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv_a),
                );
                enc_a.apply_keystream(&mut ct_a);

                let mut ct_b = pt.clone();
                let mut enc_b = <$wolf_enc>::new(
                    GenericArray::from_slice(&key),
                    GenericArray::from_slice(&iv_b),
                );
                enc_b.apply_keystream(&mut ct_b);

                assert_ne!(
                    ct_a, ct_b,
                    "{}: different IVs must produce different CFB ciphertexts",
                    stringify!($mod_name)
                );
            }
        }
    };
}

cfb_equiv!(
    aes128_cfb,
    wolfcrypt::Aes128CfbEnc,
    wolfcrypt::Aes128CfbDec,
    cfb_mode::Encryptor<aes::Aes128>,
    cfb_mode::Decryptor<aes::Aes128>,
    16,
    [wolfssl_aes_cfb]
);

cfb_equiv!(
    aes192_cfb,
    wolfcrypt::Aes192CfbEnc,
    wolfcrypt::Aes192CfbDec,
    cfb_mode::Encryptor<aes::Aes192>,
    cfb_mode::Decryptor<aes::Aes192>,
    24,
    [wolfssl_aes_cfb, wolfssl_aes_192]
);

cfb_equiv!(
    aes256_cfb,
    wolfcrypt::Aes256CfbEnc,
    wolfcrypt::Aes256CfbDec,
    cfb_mode::Encryptor<aes::Aes256>,
    cfb_mode::Decryptor<aes::Aes256>,
    32,
    [wolfssl_aes_cfb]
);
