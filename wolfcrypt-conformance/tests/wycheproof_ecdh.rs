//! Wycheproof ECDH conformance tests (ecpoint format).
//!
//! Verifies that `NistEcdhSecret::from_private_scalar` + `diffie_hellman`
//! correctly handles the Wycheproof ECDH ecpoint test vectors for P-256,
//! P-384, and P-521.
//!
//! The ecpoint vector format carries the private key as a raw big-endian
//! scalar and the peer public key as an uncompressed EC point (04 || x || y).
//! No DER/PKCS#8 parsing is required.
//!
//! For each valid vector the computed shared secret must equal the expected
//! x-coordinate exactly.  For each invalid vector the operation must return
//! an error.  Acceptable vectors are skipped.

#![cfg(wolfssl_ecc)]

mod helpers;
use helpers::wycheproof::*;

use wolfcrypt::ecdh::{NistEcdhPublicKey, NistEcdhSecret, NistP256};

#[cfg(wolfssl_ecc_p384)]
use wolfcrypt::ecdh::NistP384;

#[cfg(wolfssl_ecc_p521)]
use wolfcrypt::ecdh::NistP521;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize a big-endian integer to exactly `field_size` bytes.
///
/// Wycheproof private scalars are sometimes DER-padded with a leading `00`
/// byte to indicate a positive integer (e.g. 33 bytes for a P-256 scalar).
/// This strips leading zeros and re-pads to `field_size`, returning `None`
/// if the value is wider than `field_size` (out of range).
fn normalize_scalar(bytes: &[u8], field_size: usize) -> Option<Vec<u8>> {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[first_nonzero..];
    if stripped.len() > field_size {
        return None; // wider than field element encoding; treat as invalid
    }
    let mut padded = vec![0u8; field_size];
    padded[field_size - stripped.len()..].copy_from_slice(stripped);
    Some(padded)
}

// ---------------------------------------------------------------------------
// Core runner
// ---------------------------------------------------------------------------

fn run_wycheproof_ecdh_ecpoint<C>(json: &str, expected_curve: &str)
where
    C: wolfcrypt::ecdh::NistCurve,
{
    let file: WycheproofFile<EcdhEcpointTestGroup> =
        serde_json::from_str(json).expect("failed to parse Wycheproof ECDH ecpoint JSON");
    file.assert_vector_count();

    let mut valid_count: usize = 0;
    let mut invalid_count: usize = 0;
    let mut skip_count: usize = 0;

    for group in &file.test_groups {
        if group.curve != expected_curve {
            skip_count += group.tests.len();
            continue;
        }

        for tc in &group.tests {
            let pub_bytes = hex_decode(&tc.public, "public");
            let priv_bytes = hex_decode(&tc.private, "private");
            let expected_shared = hex_decode(&tc.shared, "shared");

            // --- Parse the peer public key ---
            let peer_pub = match NistEcdhPublicKey::<C>::from_bytes(&pub_bytes) {
                Ok(pk) => pk,
                Err(e) => match tc.result {
                    WycheproofResult::Valid => panic!(
                        "tc {}: key import failed for valid vector \
                             (flags: {:?}, error: {:?}), comment: {}",
                        tc.tc_id, tc.flags, e, tc.comment
                    ),
                    WycheproofResult::Invalid => {
                        invalid_count += 1;
                        continue;
                    }
                    WycheproofResult::Acceptable => {
                        skip_count += 1;
                        continue;
                    }
                },
            };

            // --- Normalize private scalar (Wycheproof may DER-pad with leading 00) ---
            let priv_normalized = match normalize_scalar(&priv_bytes, C::FIELD_SIZE) {
                Some(v) => v,
                None => {
                    // Scalar wider than field — definitively invalid.
                    match tc.result {
                        WycheproofResult::Valid => panic!(
                            "tc {}: scalar wider than field for valid vector, comment: {}",
                            tc.tc_id, tc.comment
                        ),
                        _ => {
                            invalid_count += 1;
                            continue;
                        }
                    }
                }
            };

            // --- Import the private scalar ---
            let sk = match NistEcdhSecret::<C>::from_private_scalar(&priv_normalized) {
                Ok(k) => k,
                Err(_) => match tc.result {
                    WycheproofResult::Valid => panic!(
                        "tc {}: private scalar import failed for valid vector, comment: {}",
                        tc.tc_id, tc.comment
                    ),
                    WycheproofResult::Invalid => {
                        invalid_count += 1;
                        continue;
                    }
                    WycheproofResult::Acceptable => {
                        skip_count += 1;
                        continue;
                    }
                },
            };

            // --- Compute shared secret ---
            let result = sk.diffie_hellman(&peer_pub);

            match tc.result {
                WycheproofResult::Valid => {
                    let shared = result.unwrap_or_else(|e| {
                        panic!(
                            "tc {}: ECDH failed for valid vector (flags: {:?}): {e:?}\n\
                             comment: {}",
                            tc.tc_id, tc.flags, tc.comment
                        )
                    });
                    assert_eq!(
                        shared.as_bytes(),
                        expected_shared.as_slice(),
                        "tc {}: shared secret mismatch (comment: {})",
                        tc.tc_id,
                        tc.comment
                    );
                    valid_count += 1;
                }
                WycheproofResult::Invalid => {
                    assert!(
                        result.is_err(),
                        "tc {}: ECDH SUCCEEDED for invalid vector! \
                         flags: {:?}, comment: {}",
                        tc.tc_id,
                        tc.flags,
                        tc.comment
                    );
                    invalid_count += 1;
                }
                WycheproofResult::Acceptable => {
                    skip_count += 1;
                }
            }
        }
    }

    assert!(
        valid_count > 0,
        "no valid ECDH vectors were exercised (curve={expected_curve}, skipped={skip_count})"
    );
    assert!(
        invalid_count > 0,
        "no invalid ECDH vectors were exercised (curve={expected_curve}, skipped={skip_count})"
    );

    if skip_count > 0 {
        eprintln!(
            "  wycheproof_ecdh: skipped {skip_count} vectors \
             (non-matching curve or acceptable)"
        );
    }
    eprintln!(
        "  wycheproof_ecdh ({expected_curve}): {valid_count} valid, \
         {invalid_count} invalid passed"
    );
}

// ---------------------------------------------------------------------------
// P-256 tests
// ---------------------------------------------------------------------------

#[test]
fn ecdh_p256_ecpoint() {
    run_wycheproof_ecdh_ecpoint::<NistP256>(
        &helpers::load_wycheproof("ecdh_secp256r1_ecpoint_test.json"),
        "secp256r1",
    );
}

// ---------------------------------------------------------------------------
// P-384 tests
// ---------------------------------------------------------------------------

#[cfg(wolfssl_ecc_p384)]
#[test]
fn ecdh_p384_ecpoint() {
    run_wycheproof_ecdh_ecpoint::<NistP384>(
        &helpers::load_wycheproof("ecdh_secp384r1_ecpoint_test.json"),
        "secp384r1",
    );
}

// ---------------------------------------------------------------------------
// P-521 tests
// ---------------------------------------------------------------------------

#[cfg(wolfssl_ecc_p521)]
#[test]
fn ecdh_p521_ecpoint() {
    run_wycheproof_ecdh_ecpoint::<NistP521>(
        &helpers::load_wycheproof("ecdh_secp521r1_ecpoint_test.json"),
        "secp521r1",
    );
}
