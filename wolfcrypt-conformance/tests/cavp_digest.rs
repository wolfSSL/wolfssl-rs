#![cfg(wolfssl_openssl_extra)]

mod helpers;
use digest::Digest;
use helpers::cavp::parse_cavp;

// ---------------------------------------------------------------------------
// Macro: SHAVS Short-Message test
// ---------------------------------------------------------------------------
macro_rules! shavs_short_msg_test {
    ($name:ident, $wolf:ty, $file:expr, [$($cfg:meta),*]) => {
        #[test]
        $(#[cfg($cfg)])*
        fn $name() {
            let file_str = $file;
            let cases = parse_cavp(&file_str);
            let mut count = 0usize;

            for tc in &cases {
                if !tc.has_field("Len") || !tc.has_field("Msg") || !tc.has_field("MD") {
                    continue;
                }

                let len_bits = tc.usize_field("Len");
                let msg = tc.bytes("Msg");
                let expected = tc.bytes("MD");

                let digest = if len_bits == 0 {
                    <$wolf>::digest(b"")
                } else {
                    let len_bytes = len_bits / 8;
                    <$wolf>::digest(&msg[..len_bytes])
                };

                assert_eq!(
                    digest.as_slice(),
                    &expected[..],
                    "SHAVS ShortMsg mismatch at Len={} for {}",
                    len_bits,
                    stringify!($wolf)
                );
                count += 1;
            }

            assert!(
                count > 10,
                "Expected >10 ShortMsg test cases for {}, got {}",
                stringify!($wolf),
                count
            );

        }
    };
}

// ---------------------------------------------------------------------------
// Macro: SHAVS Long-Message test
// ---------------------------------------------------------------------------
macro_rules! shavs_long_msg_test {
    ($name:ident, $wolf:ty, $file:expr, [$($cfg:meta),*]) => {
        #[test]
        $(#[cfg($cfg)])*
        fn $name() {
            let file_str = $file;
            let cases = parse_cavp(&file_str);
            let mut count = 0usize;

            for tc in &cases {
                if !tc.has_field("Len") || !tc.has_field("Msg") || !tc.has_field("MD") {
                    continue;
                }

                let len_bits = tc.usize_field("Len");
                let msg = tc.bytes("Msg");
                let expected = tc.bytes("MD");

                let digest = if len_bits == 0 {
                    <$wolf>::digest(b"")
                } else {
                    let len_bytes = len_bits / 8;
                    <$wolf>::digest(&msg[..len_bytes])
                };

                assert_eq!(
                    digest.as_slice(),
                    &expected[..],
                    "SHAVS LongMsg mismatch at Len={} for {}",
                    len_bits,
                    stringify!($wolf)
                );
                count += 1;
            }

            assert!(
                count >= 5,
                "Expected >=5 LongMsg test cases for {}, got {}",
                stringify!($wolf),
                count
            );

        }
    };
}

// ---------------------------------------------------------------------------
// Macro: SHAVS Monte-Carlo test (SHA-2 variant)
//
// SHA-2 Monte Carlo algorithm:
//   md[0] = md[1] = md[2] = seed
//   for j in 0..100:
//     for i in 3..1003:
//       md[i] = SHA(md[i-3] || md[i-2] || md[i-1])
//     assert md[1002] == checkpoint[j]
//     md[0] = md[1] = md[2] = md[1002]
// ---------------------------------------------------------------------------
macro_rules! shavs_monte_test_sha2 {
    ($name:ident, $wolf:ty, $file:expr, [$($cfg:meta),*]) => {
        #[test]
        $(#[cfg($cfg)])*
        fn $name() {
            let file_str = $file;
            let cases = parse_cavp(&file_str);

            // First case has the Seed field.
            let seed_case = cases
                .iter()
                .find(|c| c.has_field("Seed"))
                .expect("Monte Carlo file must contain a Seed case");
            let seed = seed_case.bytes("Seed");

            // Remaining cases with COUNT field are the 100 checkpoints.
            let checkpoints: Vec<_> = cases
                .iter()
                .filter(|c| c.has_field("COUNT"))
                .collect();

            assert_eq!(
                checkpoints.len(),
                100,
                "Expected 100 Monte Carlo checkpoints for {}, got {}",
                stringify!($wolf),
                checkpoints.len()
            );

            let digest_len = seed.len();
            // We keep a ring buffer of 3 + 1000 = 1003 entries, but we only
            // need the last three at any time.  Use a sliding window.
            let mut md0 = seed.clone();
            let mut md1 = seed.clone();
            let mut md2 = seed.clone();

            let mut checkpoint_count = 0usize;

            for j in 0..100 {
                for _i in 3..1003 {
                    let mut hasher = <$wolf>::new();
                    hasher.update(&md0);
                    hasher.update(&md1);
                    hasher.update(&md2);
                    let result = hasher.finalize();

                    md0 = md1;
                    md1 = md2;
                    md2 = result[..digest_len].to_vec();
                }

                let expected = checkpoints[j].bytes("MD");
                assert_eq!(
                    md2,
                    expected,
                    "SHAVS Monte checkpoint {} mismatch for {}",
                    j,
                    stringify!($wolf)
                );
                checkpoint_count += 1;

                // Reset: md[0] = md[1] = md[2] = md[1002]
                md0 = md2.clone();
                md1 = md2.clone();
            }

            assert_eq!(
                checkpoint_count, 100,
                "Expected 100 Monte Carlo checkpoints verified for {}, got {}",
                stringify!($wolf),
                checkpoint_count
            );

        }
    };
}

// ---------------------------------------------------------------------------
// Macro: SHAVS Monte-Carlo test (SHA-3 variant)
//
// SHA-3 Monte Carlo algorithm (simpler, single-chain):
//   md[0] = seed
//   for j in 0..100:
//     for i in 1..1001:
//       md[i] = SHA3(md[i-1])
//     assert md[1000] == checkpoint[j]
//     md[0] = md[1000]
// ---------------------------------------------------------------------------
macro_rules! shavs_monte_test_sha3 {
    ($name:ident, $wolf:ty, $file:expr, [$($cfg:meta),*]) => {
        #[test]
        $(#[cfg($cfg)])*
        fn $name() {
            let file_str = $file;
            let cases = parse_cavp(&file_str);

            // First case has the Seed field.
            let seed_case = cases
                .iter()
                .find(|c| c.has_field("Seed"))
                .expect("Monte Carlo file must contain a Seed case");
            let seed = seed_case.bytes("Seed");

            // Remaining cases with COUNT field are the 100 checkpoints.
            let checkpoints: Vec<_> = cases
                .iter()
                .filter(|c| c.has_field("COUNT"))
                .collect();

            assert_eq!(
                checkpoints.len(),
                100,
                "Expected 100 Monte Carlo checkpoints for {}, got {}",
                stringify!($wolf),
                checkpoints.len()
            );

            let mut md = seed;
            let mut checkpoint_count = 0usize;

            for j in 0..100 {
                for _i in 1..1001 {
                    md = <$wolf>::digest(&md).to_vec();
                }

                let expected = checkpoints[j].bytes("MD");
                assert_eq!(
                    md,
                    expected,
                    "SHAVS Monte checkpoint {} mismatch for {}",
                    j,
                    stringify!($wolf)
                );
                checkpoint_count += 1;

                // md[0] = md[1000] (already assigned)
            }

            assert_eq!(
                checkpoint_count, 100,
                "Expected 100 Monte Carlo checkpoints verified for {}, got {}",
                stringify!($wolf),
                checkpoint_count
            );

        }
    };
}

// ===========================================================================
// SHA-1
// ===========================================================================
shavs_short_msg_test!(
    sha1_short_msg,
    wolfcrypt::Sha1,
    helpers::load_vectors("shavs/SHA1ShortMsg.rsp"),
    [wolfssl_openssl_extra]
);
shavs_long_msg_test!(
    sha1_long_msg,
    wolfcrypt::Sha1,
    helpers::load_vectors("shavs/SHA1LongMsg.rsp"),
    [wolfssl_openssl_extra]
);
shavs_monte_test_sha2!(
    sha1_monte,
    wolfcrypt::Sha1,
    helpers::load_vectors("shavs/SHA1Monte.rsp"),
    [wolfssl_openssl_extra]
);

// ===========================================================================
// SHA-224
// ===========================================================================
shavs_short_msg_test!(
    sha224_short_msg,
    wolfcrypt::Sha224,
    helpers::load_vectors("shavs/SHA224ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha224]
);
shavs_long_msg_test!(
    sha224_long_msg,
    wolfcrypt::Sha224,
    helpers::load_vectors("shavs/SHA224LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha224]
);
shavs_monte_test_sha2!(
    sha224_monte,
    wolfcrypt::Sha224,
    helpers::load_vectors("shavs/SHA224Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha224]
);

// ===========================================================================
// SHA-256
// ===========================================================================
shavs_short_msg_test!(
    sha256_short_msg,
    wolfcrypt::Sha256,
    helpers::load_vectors("shavs/SHA256ShortMsg.rsp"),
    [wolfssl_openssl_extra]
);
shavs_long_msg_test!(
    sha256_long_msg,
    wolfcrypt::Sha256,
    helpers::load_vectors("shavs/SHA256LongMsg.rsp"),
    [wolfssl_openssl_extra]
);
shavs_monte_test_sha2!(
    sha256_monte,
    wolfcrypt::Sha256,
    helpers::load_vectors("shavs/SHA256Monte.rsp"),
    [wolfssl_openssl_extra]
);

// ===========================================================================
// SHA-384
// ===========================================================================
shavs_short_msg_test!(
    sha384_short_msg,
    wolfcrypt::Sha384,
    helpers::load_vectors("shavs/SHA384ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha384]
);
shavs_long_msg_test!(
    sha384_long_msg,
    wolfcrypt::Sha384,
    helpers::load_vectors("shavs/SHA384LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha384]
);
shavs_monte_test_sha2!(
    sha384_monte,
    wolfcrypt::Sha384,
    helpers::load_vectors("shavs/SHA384Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha384]
);

// ===========================================================================
// SHA-512
// ===========================================================================
shavs_short_msg_test!(
    sha512_short_msg,
    wolfcrypt::Sha512,
    helpers::load_vectors("shavs/SHA512ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha512]
);
shavs_long_msg_test!(
    sha512_long_msg,
    wolfcrypt::Sha512,
    helpers::load_vectors("shavs/SHA512LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha512]
);
shavs_monte_test_sha2!(
    sha512_monte,
    wolfcrypt::Sha512,
    helpers::load_vectors("shavs/SHA512Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha512]
);

// ===========================================================================
// SHA3-256
// ===========================================================================
shavs_short_msg_test!(
    sha3_256_short_msg,
    wolfcrypt::Sha3_256,
    helpers::load_vectors("shavs/SHA3_256ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_long_msg_test!(
    sha3_256_long_msg,
    wolfcrypt::Sha3_256,
    helpers::load_vectors("shavs/SHA3_256LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_monte_test_sha3!(
    sha3_256_monte,
    wolfcrypt::Sha3_256,
    helpers::load_vectors("shavs/SHA3_256Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);

// ===========================================================================
// SHA3-384
// ===========================================================================
shavs_short_msg_test!(
    sha3_384_short_msg,
    wolfcrypt::Sha3_384,
    helpers::load_vectors("shavs/SHA3_384ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_long_msg_test!(
    sha3_384_long_msg,
    wolfcrypt::Sha3_384,
    helpers::load_vectors("shavs/SHA3_384LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_monte_test_sha3!(
    sha3_384_monte,
    wolfcrypt::Sha3_384,
    helpers::load_vectors("shavs/SHA3_384Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);

// ===========================================================================
// SHA3-512
// ===========================================================================
shavs_short_msg_test!(
    sha3_512_short_msg,
    wolfcrypt::Sha3_512,
    helpers::load_vectors("shavs/SHA3_512ShortMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_long_msg_test!(
    sha3_512_long_msg,
    wolfcrypt::Sha3_512,
    helpers::load_vectors("shavs/SHA3_512LongMsg.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
shavs_monte_test_sha3!(
    sha3_512_monte,
    wolfcrypt::Sha3_512,
    helpers::load_vectors("shavs/SHA3_512Monte.rsp"),
    [wolfssl_openssl_extra, wolfssl_sha3]
);
