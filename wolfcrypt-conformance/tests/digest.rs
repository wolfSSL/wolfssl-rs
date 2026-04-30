mod helpers;

macro_rules! digest_equiv {
    ($mod_name:ident, $wolf:ty, $pure:ty, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;
            use digest::Digest;
            use rand::Rng;

            type Wolf = $wolf;
            type Pure = $pure;

            #[test]
            fn empty_equiv() {
                let wolf_out = Wolf::digest(b"");
                let pure_out = Pure::digest(b"");
                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: empty input digest mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn abc_equiv() {
                let wolf_out = Wolf::digest(b"abc");
                let pure_out = Pure::digest(b"abc");
                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: digest of b\"abc\" mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn random_equiv() {
                let mut rng = rand::thread_rng();
                for &len in HASH_LENGTHS {
                    let input = random_bytes(&mut rng, len);
                    let wolf_out = Wolf::digest(&input);
                    let pure_out = Pure::digest(&input);
                    assert_eq!(
                        wolf_out.as_slice(),
                        pure_out.as_slice(),
                        "{}: random input digest mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn incremental_equiv() {
                let mut rng = rand::thread_rng();
                for &len in HASH_LENGTHS {
                    let input = random_bytes(&mut rng, len);

                    let mut wolf = Wolf::new();
                    let mut offset = 0;
                    while offset < input.len() {
                        let chunk_size = rng.gen_range(1..=std::cmp::min(64, input.len() - offset));
                        wolf.update(&input[offset..offset + chunk_size]);
                        offset += chunk_size;
                    }
                    let wolf_out = wolf.finalize();

                    let pure_out = Pure::digest(&input);
                    assert_eq!(
                        wolf_out.as_slice(),
                        pure_out.as_slice(),
                        "{}: incremental vs one-shot digest mismatch at length {}",
                        stringify!($mod_name),
                        len
                    );
                }
            }

            #[test]
            fn clone_midstream_equiv() {
                let mut wolf = Wolf::new();
                let mut pure = Pure::new();
                wolf.update(b"prefix");
                pure.update(b"prefix");

                let mut wolf_clone = wolf.clone();
                let mut pure_clone = pure.clone();

                wolf.update(b"A");
                pure.update(b"A");
                wolf_clone.update(b"B");
                pure_clone.update(b"B");

                let wolf_a = wolf.finalize();
                let pure_a = pure.finalize();
                let wolf_b = wolf_clone.finalize();
                let pure_b = pure_clone.finalize();

                assert_eq!(
                    wolf_a.as_slice(),
                    pure_a.as_slice(),
                    "{}: clone_midstream branch A mismatch",
                    stringify!($mod_name)
                );
                assert_eq!(
                    wolf_b.as_slice(),
                    pure_b.as_slice(),
                    "{}: clone_midstream branch B mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn reset_equiv() {
                let mut wolf = Wolf::new();
                let mut pure = Pure::new();

                wolf.update(b"discard");
                pure.update(b"discard");

                Digest::reset(&mut wolf);
                Digest::reset(&mut pure);

                wolf.update(b"keep");
                pure.update(b"keep");

                let wolf_out = wolf.finalize();
                let pure_out = pure.finalize();

                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: digest after reset mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn finalize_reset_equiv() {
                let mut wolf = Wolf::new();
                let mut pure = Pure::new();

                wolf.update(b"first data");
                pure.update(b"first data");

                let wolf_first = wolf.finalize_reset();
                let pure_first = pure.finalize_reset();

                assert_eq!(
                    wolf_first.as_slice(),
                    pure_first.as_slice(),
                    "{}: finalize_reset first pass mismatch",
                    stringify!($mod_name)
                );

                wolf.update(b"second data");
                pure.update(b"second data");

                let wolf_second = wolf.finalize();
                let pure_second = pure.finalize();

                assert_eq!(
                    wolf_second.as_slice(),
                    pure_second.as_slice(),
                    "{}: finalize_reset second pass mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn million_a_equiv() {
                let mut wolf = Wolf::new();
                let mut pure = Pure::new();

                for _ in 0..1_000_000 {
                    wolf.update(b"a");
                    pure.update(b"a");
                }

                let wolf_out = wolf.finalize();
                let pure_out = pure.finalize();

                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: million 'a' digest mismatch",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_wrong_output() {
                let wolf_out = Wolf::digest(b"canary test input");
                let pure_out = Pure::digest(b"canary test input");

                let mut flipped = wolf_out.to_vec();
                flipped[0] ^= 0xFF;

                assert_ne!(
                    flipped.as_slice(),
                    pure_out.as_slice(),
                    "{}: flipped byte should not match pure output",
                    stringify!($mod_name)
                );
            }

            #[test]
            fn canary_different_input() {
                let wolf_out = Wolf::digest(b"x");
                let pure_out = Pure::digest(b"y");

                assert_ne!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: different inputs should produce different digests",
                    stringify!($mod_name)
                );
            }
        }
    };
}

digest_equiv!(sha1, wolfcrypt::Sha1, sha1::Sha1, [wolfssl_openssl_extra]);

digest_equiv!(
    sha224,
    wolfcrypt::Sha224,
    sha2::Sha224,
    [wolfssl_openssl_extra, wolfssl_sha224]
);

digest_equiv!(
    sha256,
    wolfcrypt::Sha256,
    sha2::Sha256,
    [wolfssl_openssl_extra]
);

digest_equiv!(
    sha384,
    wolfcrypt::Sha384,
    sha2::Sha384,
    [wolfssl_openssl_extra, wolfssl_sha384]
);

digest_equiv!(
    sha512,
    wolfcrypt::Sha512,
    sha2::Sha512,
    [wolfssl_openssl_extra, wolfssl_sha512]
);

digest_equiv!(
    sha512_256,
    wolfcrypt::Sha512_256,
    sha2::Sha512_256,
    [wolfssl_openssl_extra, wolfssl_sha512]
);

digest_equiv!(
    sha3_256,
    wolfcrypt::Sha3_256,
    sha3::Sha3_256,
    [wolfssl_openssl_extra, wolfssl_sha3]
);

digest_equiv!(
    sha3_384,
    wolfcrypt::Sha3_384,
    sha3::Sha3_384,
    [wolfssl_openssl_extra, wolfssl_sha3]
);

digest_equiv!(
    sha3_512,
    wolfcrypt::Sha3_512,
    sha3::Sha3_512,
    [wolfssl_openssl_extra, wolfssl_sha3]
);
