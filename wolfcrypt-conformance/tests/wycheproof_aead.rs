#![cfg(wolfssl_aes_gcm)] // At least AES-GCM needed

mod helpers;
use helpers::wycheproof::*;

use aead::{AeadInPlace, KeyInit};
use generic_array::GenericArray;

/// Generate a Wycheproof AEAD test for a given algorithm.
///
/// The macro:
/// 1. Parses the JSON as `WycheproofFile<AeadTestGroup>`.
/// 2. Asserts the declared vector count matches the file.
/// 3. Skips groups whose `iv_size`, `tag_size`, or `key_size` don't match
///    the algorithm's expected parameters.
/// 4. For valid/acceptable vectors: encrypts and checks CT+tag, then decrypts
///    and checks PT recovery.
/// 5. For invalid vectors: asserts that decryption fails.
/// 6. Asserts at least 1 valid and 1 invalid vector were exercised.
macro_rules! wycheproof_aead_test {
    ($name:ident, $json:expr, $wolf_type:ty, $key_len:expr, $iv_len:expr, [$($cfg:meta),*]) => {
        #[cfg(all($($cfg),*))]
        #[test]
        fn $name() {
            let json_str = $json;
            let file: WycheproofFile<AeadTestGroup> =
                serde_json::from_str(&json_str).expect("failed to parse Wycheproof AEAD JSON");
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;
            let mut skip_count: usize = 0;

            for group in &file.test_groups {
                // Skip groups with non-standard IV or tag sizes, or wrong key size.
                if group.iv_size != $iv_len * 8
                    || group.tag_size != 128
                    || group.key_size / 8 != $key_len
                {
                    skip_count += group.tests.len();
                    continue;
                }

                for tc in &group.tests {
                    let key = hex_decode(&tc.key, "key");
                    let iv = hex_decode(&tc.iv, "iv");
                    let aad = hex_decode(&tc.aad, "aad");
                    let pt = hex_decode(&tc.msg, "msg");
                    let ct = hex_decode(&tc.ct, "ct");
                    let tag = hex_decode(&tc.tag, "tag");

                    let key_ga = GenericArray::clone_from_slice(&key);
                    let cipher = <$wolf_type as KeyInit>::new(&key_ga);

                    match tc.result {
                        WycheproofResult::Valid | WycheproofResult::Acceptable => {
                            let label = match tc.result {
                                WycheproofResult::Valid => "valid",
                                WycheproofResult::Acceptable => "acceptable",
                                _ => unreachable!(),
                            };

                            // --- Encrypt and check CT + tag ---
                            let mut enc_buf = pt.clone();
                            let enc_result = cipher
                                .encrypt_in_place_detached(
                                    GenericArray::from_slice(&iv),
                                    &aad,
                                    &mut enc_buf,
                                );
                            let enc_tag = enc_result.unwrap_or_else(|_| panic!(
                                "tc {}: encrypt failed for {label} vector, comment: {}",
                                tc.tc_id, tc.comment,
                            ));

                            assert_eq!(
                                enc_buf, ct,
                                "tc {}: ciphertext mismatch for {label} vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );
                            assert_eq!(
                                enc_tag.as_slice(),
                                tag.as_slice(),
                                "tc {}: tag mismatch for {label} vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );

                            // --- Decrypt and check PT recovery ---
                            let mut dec_buf = ct.clone();
                            let tag_ga = aead::Tag::<$wolf_type>::from_slice(&tag);
                            let result = cipher.decrypt_in_place_detached(
                                GenericArray::from_slice(&iv),
                                &aad,
                                &mut dec_buf,
                                tag_ga,
                            );
                            assert!(
                                result.is_ok(),
                                "tc {}: decrypt failed for {label} vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );
                            assert_eq!(
                                dec_buf, pt,
                                "tc {}: plaintext mismatch after decrypt for {label} vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );

                            if tc.result == WycheproofResult::Valid {
                                valid_count += 1;
                            } else {
                                _acceptable_count += 1;
                            }
                        }
                        WycheproofResult::Invalid => {
                            // Decrypt must fail.
                            let mut buf = ct.clone();
                            let tag_ga = aead::Tag::<$wolf_type>::from_slice(&tag);
                            let result = cipher.decrypt_in_place_detached(
                                GenericArray::from_slice(&iv),
                                &aad,
                                &mut buf,
                                tag_ga,
                            );
                            assert!(
                                result.is_err(),
                                "tc {}: decrypt SUCCEEDED for invalid vector! flags: {:?}, comment: {}",
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
                "no valid vectors were exercised (skipped {})",
                skip_count,
            );
            assert!(
                invalid_count > 0,
                "no invalid vectors were exercised (skipped {})",
                skip_count,
            );

            if skip_count > 0 {
                eprintln!(
                    "  wycheproof: skipped {skip_count} test vectors with non-standard IV/tag/key sizes"
                );
            }

        }
    };
}

wycheproof_aead_test!(
    aes_128_gcm,
    helpers::load_wycheproof("aes_gcm_test.json"),
    wolfcrypt::Aes128Gcm,
    16,
    12,
    [wolfssl_aes_gcm]
);

wycheproof_aead_test!(
    aes_256_gcm,
    helpers::load_wycheproof("aes_gcm_test.json"),
    wolfcrypt::Aes256Gcm,
    32,
    12,
    [wolfssl_aes_gcm]
);

wycheproof_aead_test!(
    chacha20_poly1305,
    helpers::load_wycheproof("chacha20_poly1305_test.json"),
    wolfcrypt::ChaCha20Poly1305,
    32,
    12,
    [wolfssl_chacha20_poly1305]
);
