#![cfg(all(wolfssl_openssl_extra, wolfssl_hmac))]

mod helpers;
use helpers::wycheproof::*;

use hmac::Mac;

/// Run a Wycheproof MAC test for one HMAC variant.
///
/// Computes the full MAC, then truncates to `tag_size/8` bytes before comparing
/// against the expected tag. Valid vectors must match; invalid vectors must not.
macro_rules! wycheproof_hmac_test {
    ($name:ident, $json:expr, $wolf_type:ty, [$($cfg:meta),*]) => {
        #[cfg(all($($cfg),*))]
        #[test]
        fn $name() {
            let json_str = $json;
            let file: WycheproofFile<MacTestGroup> =
                serde_json::from_str(&json_str).expect("failed to parse Wycheproof MAC JSON");
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;

            for group in &file.test_groups {
                let tag_bytes = group.tag_size / 8;

                for tc in &group.tests {
                    let key = hex_decode(&tc.key, "key");
                    let msg = hex_decode(&tc.msg, "msg");
                    let expected_tag = hex_decode(&tc.tag, "tag");

                    let mac_result = <$wolf_type>::new_from_slice(&key);
                    let mut mac = match mac_result {
                        Ok(m) => m,
                        Err(_) => {
                            // Key rejected (e.g. zero-length key on some impls).
                            // For invalid vectors this is acceptable; for valid
                            // vectors it is a test failure.
                            assert!(
                                tc.result == WycheproofResult::Invalid
                                    || tc.result == WycheproofResult::Acceptable,
                                "tc {}: key init failed for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            if tc.result == WycheproofResult::Invalid {
                                invalid_count += 1;
                            } else {
                                _acceptable_count += 1;
                            }
                            continue;
                        }
                    };

                    mac.update(&msg);
                    let computed = mac.finalize().into_bytes();
                    let computed_truncated = &computed[..tag_bytes];

                    match tc.result {
                        WycheproofResult::Valid => {
                            assert_eq!(
                                computed_truncated,
                                expected_tag.as_slice(),
                                "tc {}: HMAC mismatch for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            valid_count += 1;
                        }
                        WycheproofResult::Acceptable => {
                            // Acceptable: both match and mismatch are fine.
                            _acceptable_count += 1;
                        }
                        WycheproofResult::Invalid => {
                            assert_ne!(
                                computed_truncated,
                                expected_tag.as_slice(),
                                "tc {}: HMAC matched for invalid vector! flags: {:?}, comment: {}",
                                tc.tc_id,
                                tc.flags,
                                tc.comment,
                            );
                            invalid_count += 1;
                        }
                    }
                }
            }

            assert!(
                valid_count > 0,
                "no valid vectors were exercised for {}",
                stringify!($name),
            );
            assert!(
                invalid_count > 0,
                "no invalid vectors were exercised for {}",
                stringify!($name),
            );

        }
    };
}

wycheproof_hmac_test!(
    hmac_sha1,
    helpers::load_wycheproof("hmac_sha1_test.json"),
    wolfcrypt::WolfHmacSha1,
    [wolfssl_openssl_extra, wolfssl_hmac]
);

wycheproof_hmac_test!(
    hmac_sha256,
    helpers::load_wycheproof("hmac_sha256_test.json"),
    wolfcrypt::WolfHmacSha256,
    [wolfssl_openssl_extra, wolfssl_hmac]
);

wycheproof_hmac_test!(
    hmac_sha384,
    helpers::load_wycheproof("hmac_sha384_test.json"),
    wolfcrypt::WolfHmacSha384,
    [wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha384]
);

wycheproof_hmac_test!(
    hmac_sha512,
    helpers::load_wycheproof("hmac_sha512_test.json"),
    wolfcrypt::WolfHmacSha512,
    [wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha512]
);

// ---------------------------------------------------------------------------
// CMAC (AES-CMAC)
// ---------------------------------------------------------------------------

/// Wycheproof CMAC test. The aes_cmac_test.json file contains groups with
/// varying key sizes (128, 192, 256 bits) and tag sizes. We filter by key
/// size to match the wolf type and truncate the computed tag for comparison.
macro_rules! wycheproof_cmac_test {
    ($name:ident, $json:expr, $wolf_type:ty, $key_len:expr, [$($cfg:meta),*]) => {
        #[cfg(all($($cfg),*))]
        #[test]
        fn $name() {
            let json_str = $json;
            let file: WycheproofFile<MacTestGroup> =
                serde_json::from_str(&json_str).expect("failed to parse Wycheproof CMAC JSON");
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;
            let mut skip_count: usize = 0;

            for group in &file.test_groups {
                if group.key_size / 8 != $key_len {
                    skip_count += group.tests.len();
                    continue;
                }
                let tag_bytes = group.tag_size / 8;

                for tc in &group.tests {
                    let key = hex_decode(&tc.key, "key");
                    let msg = hex_decode(&tc.msg, "msg");
                    let expected_tag = hex_decode(&tc.tag, "tag");

                    let mac_result = <$wolf_type>::new_from_slice(&key);
                    let mut mac = match mac_result {
                        Ok(m) => m,
                        Err(_) => {
                            assert!(
                                tc.result == WycheproofResult::Invalid
                                    || tc.result == WycheproofResult::Acceptable,
                                "tc {}: CMAC key init failed for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            if tc.result == WycheproofResult::Invalid {
                                invalid_count += 1;
                            } else {
                                _acceptable_count += 1;
                            }
                            continue;
                        }
                    };

                    mac.update(&msg);
                    let computed = mac.finalize().into_bytes();
                    let computed_truncated = &computed[..tag_bytes];

                    match tc.result {
                        WycheproofResult::Valid => {
                            assert_eq!(
                                computed_truncated,
                                expected_tag.as_slice(),
                                "tc {}: CMAC mismatch for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            valid_count += 1;
                        }
                        WycheproofResult::Acceptable => {
                            _acceptable_count += 1;
                        }
                        WycheproofResult::Invalid => {
                            assert_ne!(
                                computed_truncated,
                                expected_tag.as_slice(),
                                "tc {}: CMAC matched for invalid vector! flags: {:?}, comment: {}",
                                tc.tc_id,
                                tc.flags,
                                tc.comment,
                            );
                            invalid_count += 1;
                        }
                    }
                }
            }

            assert!(
                valid_count > 0,
                "no valid CMAC vectors were exercised for {} (skipped {})",
                stringify!($name),
                skip_count,
            );
            assert!(
                invalid_count > 0,
                "no invalid CMAC vectors were exercised for {} (skipped {})",
                stringify!($name),
                skip_count,
            );

            if skip_count > 0 {
                eprintln!(
                    "  wycheproof: skipped {skip_count} test vectors with non-matching key size"
                );
            }

        }
    };
}

#[cfg(all(wolfssl_openssl_extra, wolfssl_cmac))]
wycheproof_cmac_test!(
    cmac_aes128,
    helpers::load_wycheproof("aes_cmac_test.json"),
    wolfcrypt::WolfCmacAes128,
    16,
    [wolfssl_openssl_extra, wolfssl_cmac]
);

#[cfg(all(wolfssl_openssl_extra, wolfssl_cmac))]
wycheproof_cmac_test!(
    cmac_aes256,
    helpers::load_wycheproof("aes_cmac_test.json"),
    wolfcrypt::WolfCmacAes256,
    32,
    [wolfssl_openssl_extra, wolfssl_cmac]
);
