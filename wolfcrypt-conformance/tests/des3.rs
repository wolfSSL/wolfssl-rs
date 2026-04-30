mod helpers;

#[cfg(all(wolfssl_openssl_extra, wolfssl_des3))]
mod des3_cbc {
    use super::helpers::{decrypt_blocks_with, encrypt_blocks_with, random_bytes};
    use rand::thread_rng;

    type WolfEnc = wolfcrypt::DesEde3CbcEnc;
    type WolfDec = wolfcrypt::DesEde3CbcDec;
    type PureEnc = cbc::Encryptor<des::TdesEde3>;
    type PureDec = cbc::Decryptor<des::TdesEde3>;

    const KEY_LEN: usize = 24;
    const IV_LEN: usize = 8;
    const BLOCK: usize = 8;

    /// Block-aligned lengths appropriate for 8-byte DES blocks.
    const DES_BLOCK_ALIGNED: &[usize] = &[8, 16, 24, 32, 64, 128, 256, 1024];

    #[test]
    fn single_block_equiv() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let iv = random_bytes(&mut rng, IV_LEN);
        let pt = random_bytes(&mut rng, BLOCK);

        let wolf_ct = encrypt_blocks_with::<WolfEnc>(&key, &iv, &pt);
        let pure_ct = encrypt_blocks_with::<PureEnc>(&key, &iv, &pt);

        assert_eq!(wolf_ct, pure_ct, "3DES-CBC single-block encrypt mismatch");
    }

    #[test]
    fn multi_block_equiv() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let iv = random_bytes(&mut rng, IV_LEN);
        let pt = random_bytes(&mut rng, BLOCK * 8);

        let wolf_ct = encrypt_blocks_with::<WolfEnc>(&key, &iv, &pt);
        let pure_ct = encrypt_blocks_with::<PureEnc>(&key, &iv, &pt);

        assert_eq!(wolf_ct, pure_ct, "3DES-CBC multi-block encrypt mismatch");
    }

    #[test]
    fn cross_round_trip() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let iv = random_bytes(&mut rng, IV_LEN);
        let pt = random_bytes(&mut rng, BLOCK * 4);

        // Wolf encrypts, pure decrypts
        let wolf_ct = encrypt_blocks_with::<WolfEnc>(&key, &iv, &pt);
        let recovered_a = decrypt_blocks_with::<PureDec>(&key, &iv, &wolf_ct);
        assert_eq!(
            recovered_a, pt,
            "Pure must decrypt what wolf encrypted in 3DES-CBC"
        );

        // Pure encrypts, wolf decrypts
        let pure_ct = encrypt_blocks_with::<PureEnc>(&key, &iv, &pt);
        let recovered_b = decrypt_blocks_with::<WolfDec>(&key, &iv, &pure_ct);
        assert_eq!(
            recovered_b, pt,
            "Wolf must decrypt what pure encrypted in 3DES-CBC"
        );
    }

    #[test]
    fn random_data_equiv() {
        let mut rng = thread_rng();

        for &total_len in DES_BLOCK_ALIGNED {
            let key = random_bytes(&mut rng, KEY_LEN);
            let iv = random_bytes(&mut rng, IV_LEN);
            let pt = random_bytes(&mut rng, total_len);

            let wolf_ct = encrypt_blocks_with::<WolfEnc>(&key, &iv, &pt);
            let pure_ct = encrypt_blocks_with::<PureEnc>(&key, &iv, &pt);

            assert_eq!(
                wolf_ct, pure_ct,
                "3DES-CBC random data mismatch at len={}",
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

        let ct_a = encrypt_blocks_with::<WolfEnc>(&key, &iv_a, &pt);
        let ct_b = encrypt_blocks_with::<WolfEnc>(&key, &iv_b, &pt);

        assert_ne!(
            ct_a, ct_b,
            "Same key+PT with different IVs must produce different 3DES-CBC CTs"
        );
    }

    #[test]
    fn canary_wrong_iv() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let iv_enc = random_bytes(&mut rng, IV_LEN);
        let iv_dec = random_bytes(&mut rng, IV_LEN);
        let pt = random_bytes(&mut rng, BLOCK * 2);

        let ct = encrypt_blocks_with::<WolfEnc>(&key, &iv_enc, &pt);
        let wrong_pt = decrypt_blocks_with::<WolfDec>(&key, &iv_dec, &ct);

        assert_ne!(
            wrong_pt, pt,
            "Decrypting 3DES-CBC with wrong IV must not recover original plaintext"
        );
    }
}
