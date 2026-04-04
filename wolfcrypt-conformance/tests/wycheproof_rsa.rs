#![cfg(wolfssl_rsa)]

mod helpers;
use helpers::wycheproof::*;

use wolfcrypt::rsa::{
    RsaDigest, RsaPublicKey, RsaPkcs1v15Signature, RsaPssSignature,
};

// ---------------------------------------------------------------------------
// PKCS#1 v1.5 signature verification
// ---------------------------------------------------------------------------

// --- SHA-256 ---

#[test]
fn rsa_pkcs1v15_2048_sha256() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_2048_sha256_test.json"), "SHA-256", RsaDigest::Sha256);
}

#[test]
fn rsa_pkcs1v15_3072_sha256() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_3072_sha256_test.json"), "SHA-256", RsaDigest::Sha256);
}

// --- SHA-384 ---

#[cfg(wolfssl_sha384)]
#[test]
fn rsa_pkcs1v15_2048_sha384() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_2048_sha384_test.json"), "SHA-384", RsaDigest::Sha384);
}

#[cfg(wolfssl_sha384)]
#[test]
fn rsa_pkcs1v15_3072_sha384() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_3072_sha384_test.json"), "SHA-384", RsaDigest::Sha384);
}

#[cfg(wolfssl_sha384)]
#[test]
fn rsa_pkcs1v15_4096_sha384() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_4096_sha384_test.json"), "SHA-384", RsaDigest::Sha384);
}

// --- SHA-512 ---

#[cfg(wolfssl_sha512)]
#[test]
fn rsa_pkcs1v15_2048_sha512() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_2048_sha512_test.json"), "SHA-512", RsaDigest::Sha512);
}

#[cfg(wolfssl_sha512)]
#[test]
fn rsa_pkcs1v15_3072_sha512() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_3072_sha512_test.json"), "SHA-512", RsaDigest::Sha512);
}

#[cfg(wolfssl_sha512)]
#[test]
fn rsa_pkcs1v15_4096_sha512() {
    run_wycheproof_pkcs1v15(&helpers::load_wycheproof("rsa_signature_4096_sha512_test.json"), "SHA-512", RsaDigest::Sha512);
}

fn run_wycheproof_pkcs1v15(json: &str, expected_sha: &str, digest: RsaDigest) {
    let file: WycheproofFile<RsaSigTestGroup> =
        serde_json::from_str(json).expect("failed to parse Wycheproof RSA JSON");
    file.assert_vector_count();

    let mut valid_count: usize = 0;
    let mut invalid_count: usize = 0;
    let mut _acceptable_count: usize = 0;
    let mut skip_count: usize = 0;

    for group in &file.test_groups {
        if group.sha != expected_sha {
            skip_count += group.tests.len();
            continue;
        }

        let der = hex_decode(&group.public_key_der, "publicKeyDer");
        let pk = match RsaPublicKey::from_der(&der) {
            Ok(pk) => pk,
            Err(_) => {
                skip_count += group.tests.len();
                continue;
            }
        };

        for tc in &group.tests {
            let msg = hex_decode(&tc.msg, "msg");
            let sig_bytes = hex_decode(&tc.sig, "sig");

            let sig = match RsaPkcs1v15Signature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => {
                    match tc.result {
                        WycheproofResult::Valid => {
                            panic!(
                                "tc {}: RSA PKCS#1v1.5 sig parse failed for valid vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );
                        }
                        _ => {
                            if tc.result == WycheproofResult::Invalid {
                                invalid_count += 1;
                            } else {
                                _acceptable_count += 1;
                            }
                            continue;
                        }
                    }
                }
            };

            let result = pk.verify_pkcs1v15_with_digest(&msg, &sig, digest);

            match tc.result {
                WycheproofResult::Valid => {
                    assert!(
                        result.is_ok(),
                        "tc {}: RSA PKCS#1v1.5 ({:?}) verify failed for valid vector, comment: {}",
                        tc.tc_id, digest, tc.comment,
                    );
                    valid_count += 1;
                }
                WycheproofResult::Acceptable => {
                    _acceptable_count += 1;
                }
                WycheproofResult::Invalid => {
                    assert!(
                        result.is_err(),
                        "tc {}: RSA PKCS#1v1.5 ({:?}) verify SUCCEEDED for invalid vector! \
                         flags: {:?}, comment: {}",
                        tc.tc_id, digest, tc.flags, tc.comment,
                    );
                    invalid_count += 1;
                }
            }
        }
    }

    assert!(
        valid_count > 0,
        "no valid RSA PKCS#1v1.5 vectors were exercised (skipped {})",
        skip_count,
    );
    assert!(
        invalid_count > 0,
        "no invalid RSA PKCS#1v1.5 vectors were exercised (skipped {})",
        skip_count,
    );

    if skip_count > 0 {
        eprintln!(
            "  wycheproof: skipped {skip_count} test vectors with non-matching hash/key"
        );
    }

}

// ---------------------------------------------------------------------------
// PSS signature verification (salt_len = digest_len, MGF1 hash = digest)
// ---------------------------------------------------------------------------

// --- SHA-256 ---

#[test]
fn rsa_pss_2048_sha256_mgf1_32() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_2048_sha256_mgf1_32_test.json"), "SHA-256", RsaDigest::Sha256);
}

#[test]
fn rsa_pss_3072_sha256_mgf1_32() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_3072_sha256_mgf1_32_test.json"), "SHA-256", RsaDigest::Sha256);
}

#[test]
fn rsa_pss_4096_sha256_mgf1_32() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_4096_sha256_mgf1_32_test.json"), "SHA-256", RsaDigest::Sha256);
}

// --- SHA-384 ---

#[cfg(wolfssl_sha384)]
#[test]
fn rsa_pss_2048_sha384_mgf1_48() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_2048_sha384_mgf1_48_test.json"), "SHA-384", RsaDigest::Sha384);
}

#[cfg(wolfssl_sha384)]
#[test]
fn rsa_pss_4096_sha384_mgf1_48() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_4096_sha384_mgf1_48_test.json"), "SHA-384", RsaDigest::Sha384);
}

// --- SHA-512 ---

#[cfg(wolfssl_sha512)]
#[test]
fn rsa_pss_4096_sha512_mgf1_64() {
    run_wycheproof_pss(&helpers::load_wycheproof("rsa_pss_4096_sha512_mgf1_64_test.json"), "SHA-512", RsaDigest::Sha512);
}

/// Wycheproof RSA-PSS test. Uses `verify_pss_with_digest` so the digest,
/// salt length (= digest length), and MGF1 hash all match the vector file's
/// parameters.
///
/// The PSS JSON schema uses the same top-level structure as PKCS#1 but adds
/// `mgf`, `mgfSha`, and `sLen` fields to the group. We parse the same
/// `RsaSigTestGroup` structure (which ignores extra fields via serde's
/// default behavior) and filter by the expected `sha` value.
fn run_wycheproof_pss(json: &str, expected_sha: &str, digest: RsaDigest) {
    let file: WycheproofFile<RsaSigTestGroup> =
        serde_json::from_str(json).expect("failed to parse Wycheproof RSA PSS JSON");
    file.assert_vector_count();

    let mut valid_count: usize = 0;
    let mut invalid_count: usize = 0;
    let mut _acceptable_count: usize = 0;
    let mut skip_count: usize = 0;

    for group in &file.test_groups {
        if group.sha != expected_sha {
            skip_count += group.tests.len();
            continue;
        }

        let der = hex_decode(&group.public_key_der, "publicKeyDer");
        let pk = match RsaPublicKey::from_der(&der) {
            Ok(pk) => pk,
            Err(_) => {
                skip_count += group.tests.len();
                continue;
            }
        };

        for tc in &group.tests {
            let msg = hex_decode(&tc.msg, "msg");
            let sig_bytes = hex_decode(&tc.sig, "sig");

            let sig = match RsaPssSignature::try_from(sig_bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => {
                    match tc.result {
                        WycheproofResult::Valid => {
                            panic!(
                                "tc {}: RSA PSS sig parse failed for valid vector, comment: {}",
                                tc.tc_id, tc.comment,
                            );
                        }
                        _ => {
                            if tc.result == WycheproofResult::Invalid {
                                invalid_count += 1;
                            } else {
                                _acceptable_count += 1;
                            }
                            continue;
                        }
                    }
                }
            };

            let result = pk.verify_pss_with_digest(&msg, &sig, digest);

            match tc.result {
                WycheproofResult::Valid => {
                    assert!(
                        result.is_ok(),
                        "tc {}: RSA PSS ({:?}) verify failed for valid vector, comment: {}",
                        tc.tc_id, digest, tc.comment,
                    );
                    valid_count += 1;
                }
                WycheproofResult::Acceptable => {
                    _acceptable_count += 1;
                }
                WycheproofResult::Invalid => {
                    assert!(
                        result.is_err(),
                        "tc {}: RSA PSS ({:?}) verify SUCCEEDED for invalid vector! \
                         flags: {:?}, comment: {}",
                        tc.tc_id, digest, tc.flags, tc.comment,
                    );
                    invalid_count += 1;
                }
            }
        }
    }

    assert!(
        valid_count > 0,
        "no valid RSA PSS vectors were exercised (skipped {})",
        skip_count,
    );
    assert!(
        invalid_count > 0,
        "no invalid RSA PSS vectors were exercised (skipped {})",
        skip_count,
    );

    if skip_count > 0 {
        eprintln!(
            "  wycheproof: skipped {skip_count} test vectors with non-matching hash/key"
        );
    }

}
