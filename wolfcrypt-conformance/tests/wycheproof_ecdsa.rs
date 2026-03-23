#![cfg(all(wolfssl_openssl_extra, wolfssl_ecc))]

mod helpers;
use helpers::wycheproof::*;

use signature::Verifier;

// P-256 with SHA-256 (the curve's canonical hash).
const P256_SHA256: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json");

// P-384 with SHA-384 (the curve's canonical hash).
#[cfg(wolfssl_ecc_p384)]
const P384_SHA384: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json");

// P-521 with SHA-512 (the curve's canonical hash).
#[cfg(wolfssl_ecc_p521)]
const P521_SHA512: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/ecdsa_secp521r1_sha512_p1363_test.json");

/// Run a Wycheproof ECDSA P1363 verification test for one curve/hash combo.
///
/// Wolf's `Verifier::verify(msg, &sig)` hashes the message internally using the
/// curve's canonical hash. We filter groups by both `curve` and `sha` to ensure
/// the vector's hash matches what wolf will use.
macro_rules! wycheproof_ecdsa_test {
    (
        $name:ident,
        $json:expr,
        $curve_type:ty,
        $vk_type:ty,
        $sig_type:ty,
        $expected_curve:expr,
        $expected_sha:expr,
        [$($cfg:meta),*]
    ) => {
        #[cfg(all($($cfg),*))]
        #[test]
        fn $name() {
            let file: WycheproofFile<EcdsaP1363TestGroup> =
                serde_json::from_str($json)
                    .expect("failed to parse Wycheproof ECDSA P1363 JSON");
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;
            let mut skip_count: usize = 0;

            for group in &file.test_groups {
                // Only process groups that match the expected curve and hash.
                if group.public_key.curve != $expected_curve || group.sha != $expected_sha {
                    skip_count += group.tests.len();
                    continue;
                }

                let uncompressed = hex_decode(&group.public_key.uncompressed, "uncompressed");
                let vk = <$vk_type>::from_uncompressed_point(&uncompressed);

                for tc in &group.tests {
                    let msg = hex_decode(&tc.msg, "msg");
                    let sig_bytes = hex_decode(&tc.sig, "sig");

                    let sig = <$sig_type>::from_bytes(&sig_bytes);

                    match (&vk, &sig) {
                        (Ok(vk), Ok(sig)) => {
                            let result = vk.verify(&msg, sig);

                            match tc.result {
                                WycheproofResult::Valid => {
                                    assert!(
                                        result.is_ok(),
                                        "tc {}: ECDSA verify failed for valid vector, \
                                         comment: {}",
                                        tc.tc_id,
                                        tc.comment,
                                    );
                                    valid_count += 1;
                                }
                                WycheproofResult::Acceptable => {
                                    // Either pass or fail is fine.
                                    _acceptable_count += 1;
                                }
                                WycheproofResult::Invalid => {
                                    assert!(
                                        result.is_err(),
                                        "tc {}: ECDSA verify SUCCEEDED for invalid vector! \
                                         flags: {:?}, comment: {}",
                                        tc.tc_id,
                                        tc.flags,
                                        tc.comment,
                                    );
                                    invalid_count += 1;
                                }
                            }
                        }
                        _ => {
                            // Key or signature parsing failed.
                            match tc.result {
                                WycheproofResult::Valid => {
                                    panic!(
                                        "tc {}: ECDSA key/sig parse failed for valid vector \
                                         (vk err: {}, sig err: {}), comment: {}",
                                        tc.tc_id,
                                        vk.is_err(),
                                        sig.is_err(),
                                        tc.comment,
                                    );
                                }
                                WycheproofResult::Acceptable => {
                                    _acceptable_count += 1;
                                }
                                WycheproofResult::Invalid => {
                                    // Rejection at parse time is a valid way
                                    // to reject an invalid vector.
                                    invalid_count += 1;
                                }
                            }
                        }
                    }
                }
            }

            assert!(
                valid_count > 0,
                "no valid ECDSA vectors were exercised for {} (skipped {})",
                stringify!($name),
                skip_count,
            );
            assert!(
                invalid_count > 0,
                "no invalid ECDSA vectors were exercised for {} (skipped {})",
                stringify!($name),
                skip_count,
            );

            if skip_count > 0 {
                eprintln!(
                    "  wycheproof: skipped {skip_count} test vectors with non-matching curve/hash"
                );
            }

        }
    };
}

wycheproof_ecdsa_test!(
    ecdsa_p256_sha256,
    P256_SHA256,
    wolfcrypt::P256,
    wolfcrypt::EcdsaVerifyingKey<wolfcrypt::P256>,
    wolfcrypt::EcdsaSignature<wolfcrypt::P256>,
    "secp256r1",
    "SHA-256",
    [wolfssl_openssl_extra, wolfssl_ecc]
);

wycheproof_ecdsa_test!(
    ecdsa_p384_sha384,
    P384_SHA384,
    wolfcrypt::P384,
    wolfcrypt::EcdsaVerifyingKey<wolfcrypt::P384>,
    wolfcrypt::EcdsaSignature<wolfcrypt::P384>,
    "secp384r1",
    "SHA-384",
    [wolfssl_openssl_extra, wolfssl_ecc, wolfssl_ecc_p384]
);

wycheproof_ecdsa_test!(
    ecdsa_p521_sha512,
    P521_SHA512,
    wolfcrypt::P521,
    wolfcrypt::EcdsaVerifyingKey<wolfcrypt::P521>,
    wolfcrypt::EcdsaSignature<wolfcrypt::P521>,
    "secp521r1",
    "SHA-512",
    [wolfssl_openssl_extra, wolfssl_ecc, wolfssl_ecc_p521]
);
