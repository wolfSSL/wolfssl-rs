#![cfg(wolfssl_hkdf)]

mod helpers;
use helpers::wycheproof::*;

/// Run a Wycheproof HKDF test for one hash variant.
///
/// For each vector:
/// - Valid: `expand` must succeed and the output keying material must match.
/// - Invalid: `expand` must return an error OR the OKM must not match.
/// - Acceptable: either outcome is fine.
macro_rules! wycheproof_hkdf_test {
    ($name:ident, $json:expr, $wolf_type:ty, [$($cfg:meta),*]) => {
        #[cfg(all($($cfg),*))]
        #[test]
        fn $name() {
            let json_str = $json;
            let file: WycheproofFile<HkdfTestGroup> =
                serde_json::from_str(&json_str).expect("failed to parse Wycheproof HKDF JSON");
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;

            for group in &file.test_groups {
                for tc in &group.tests {
                    let ikm = hex_decode(&tc.ikm, "ikm");
                    let salt = hex_decode(&tc.salt, "salt");
                    let info = hex_decode(&tc.info, "info");
                    let expected_okm = hex_decode(&tc.okm, "okm");

                    let hkdf = <$wolf_type>::new(
                        if salt.is_empty() { None } else { Some(&salt) },
                        &ikm,
                    );

                    let mut okm = vec![0u8; tc.size];
                    let result = hkdf.expand(&info, &mut okm);

                    match tc.result {
                        WycheproofResult::Valid => {
                            assert!(
                                result.is_ok(),
                                "tc {}: HKDF expand failed for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            assert_eq!(
                                okm,
                                expected_okm,
                                "tc {}: OKM mismatch for valid vector, comment: {}",
                                tc.tc_id,
                                tc.comment,
                            );
                            valid_count += 1;
                        }
                        WycheproofResult::Acceptable => {
                            // Either success-with-match or failure is fine.
                            _acceptable_count += 1;
                        }
                        WycheproofResult::Invalid => {
                            // expand must fail, or if it succeeds the output
                            // must not match.
                            let failed = result.is_err() || okm != expected_okm;
                            assert!(
                                failed,
                                "tc {}: HKDF expand SUCCEEDED and matched for invalid vector! \
                                 flags: {:?}, comment: {}",
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
                "no valid HKDF vectors were exercised for {}",
                stringify!($name),
            );
            assert!(
                invalid_count > 0,
                "no invalid HKDF vectors were exercised for {}",
                stringify!($name),
            );

        }
    };
}

wycheproof_hkdf_test!(
    hkdf_sha256,
    helpers::load_wycheproof("hkdf_sha256_test.json"),
    wolfcrypt::WolfHkdfSha256,
    [wolfssl_hkdf]
);

#[cfg(wolfssl_sha384)]
wycheproof_hkdf_test!(
    hkdf_sha384,
    helpers::load_wycheproof("hkdf_sha384_test.json"),
    wolfcrypt::WolfHkdfSha384,
    [wolfssl_hkdf, wolfssl_sha384]
);

#[cfg(wolfssl_sha512)]
wycheproof_hkdf_test!(
    hkdf_sha512,
    helpers::load_wycheproof("hkdf_sha512_test.json"),
    wolfcrypt::WolfHkdfSha512,
    [wolfssl_hkdf, wolfssl_sha512]
);
