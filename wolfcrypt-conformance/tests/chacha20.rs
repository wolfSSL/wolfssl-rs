mod helpers;

#[cfg(wolfssl_chacha)]
mod chacha20_equiv {
    use super::helpers::{random_bytes, SYMMETRIC_LENGTHS};
    use cipher::generic_array::GenericArray;
    use cipher::{KeyIvInit, StreamCipher};
    use rand::thread_rng;

    type Wolf = wolfcrypt::WolfChaCha20;
    type Pure = chacha20::ChaCha20;

    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    #[test]
    fn encrypt_equiv() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let nonce = random_bytes(&mut rng, NONCE_LEN);
        let pt = random_bytes(&mut rng, 64);

        let mut wolf_ct = pt.clone();
        let mut wolf = Wolf::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce),
        );
        wolf.apply_keystream(&mut wolf_ct);

        let mut pure_ct = pt.clone();
        let mut pure = Pure::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce),
        );
        pure.apply_keystream(&mut pure_ct);

        assert_eq!(
            wolf_ct, pure_ct,
            "ChaCha20 encrypt must produce identical ciphertext"
        );
    }

    #[test]
    fn cross_round_trip() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let nonce = random_bytes(&mut rng, NONCE_LEN);
        let pt = random_bytes(&mut rng, 100);

        // Wolf encrypts, pure decrypts
        let mut ct = pt.clone();
        let mut wolf = Wolf::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce),
        );
        wolf.apply_keystream(&mut ct);

        let mut recovered = ct.clone();
        let mut pure = Pure::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce),
        );
        pure.apply_keystream(&mut recovered);

        assert_eq!(
            recovered, pt,
            "Pure must decrypt what wolf encrypted (ChaCha20 is symmetric)"
        );
    }

    #[test]
    fn various_lengths() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);

        for &len in SYMMETRIC_LENGTHS {
            // Fresh nonce per length so each iteration exercises an
            // independent keystream.
            let nonce = random_bytes(&mut rng, NONCE_LEN);
            let pt = random_bytes(&mut rng, len);

            let mut wolf_ct = pt.clone();
            let mut wolf = Wolf::new(
                GenericArray::from_slice(&key),
                GenericArray::from_slice(&nonce),
            );
            wolf.apply_keystream(&mut wolf_ct);

            let mut pure_ct = pt.clone();
            let mut pure = Pure::new(
                GenericArray::from_slice(&key),
                GenericArray::from_slice(&nonce),
            );
            pure.apply_keystream(&mut pure_ct);

            assert_eq!(wolf_ct, pure_ct, "ChaCha20 mismatch at length {}", len);
        }
    }

    #[test]
    fn partial_block_equiv() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let nonce = random_bytes(&mut rng, NONCE_LEN);

        for &len in &[1usize, 7, 15] {
            let pt = random_bytes(&mut rng, len);

            let mut wolf_ct = pt.clone();
            let mut wolf = Wolf::new(
                GenericArray::from_slice(&key),
                GenericArray::from_slice(&nonce),
            );
            wolf.apply_keystream(&mut wolf_ct);

            let mut pure_ct = pt.clone();
            let mut pure = Pure::new(
                GenericArray::from_slice(&key),
                GenericArray::from_slice(&nonce),
            );
            pure.apply_keystream(&mut pure_ct);

            assert_eq!(
                wolf_ct, pure_ct,
                "ChaCha20 partial-block mismatch at length {}",
                len
            );
        }
    }

    #[test]
    fn canary_different_nonce() {
        let mut rng = thread_rng();
        let key = random_bytes(&mut rng, KEY_LEN);
        let nonce_a = random_bytes(&mut rng, NONCE_LEN);
        let nonce_b = random_bytes(&mut rng, NONCE_LEN);
        let pt = random_bytes(&mut rng, 32);

        let mut ct_a = pt.clone();
        let mut wolf_a = Wolf::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce_a),
        );
        wolf_a.apply_keystream(&mut ct_a);

        let mut ct_b = pt.clone();
        let mut wolf_b = Wolf::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&nonce_b),
        );
        wolf_b.apply_keystream(&mut ct_b);

        assert_ne!(
            ct_a, ct_b,
            "Different nonces must produce different ChaCha20 ciphertexts"
        );
    }
}
