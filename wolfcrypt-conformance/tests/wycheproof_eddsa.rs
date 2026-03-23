#![cfg(wolfssl_ed25519)]

mod helpers;
use helpers::wycheproof::*;

use signature::Verifier;

const ED25519_VECTORS: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/ed25519_test.json");

#[cfg(wolfssl_ed448)]
const ED448_VECTORS: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/ed448_test.json");

/// Generate a Wycheproof EdDSA verification test.
///
/// Parameters:
/// - `$name`: test function name
/// - `$json`: JSON vector constant
/// - `$curve`: expected curve string in the JSON ("edwards25519" or "edwards448")
/// - `$pk_len`: public key byte length (32 for Ed25519, 57 for Ed448)
/// - `$vk_from_bytes`: expression to construct a verifying key from a fixed-size array
/// - `$sig_from_slice`: expression to construct a signature from a byte slice
/// - `$label`: human-readable algorithm name for error messages
macro_rules! wycheproof_eddsa_test {
    (
        $name:ident, $json:expr, $curve:expr, $pk_len:expr,
        $vk_from_bytes:expr, $sig_from_slice:expr, $label:expr,
        [$($cfg:meta),*]
    ) => {
        $(#[cfg($cfg)])*
        #[test]
        fn $name() {
            let file: WycheproofFile<EddsaTestGroup> =
                serde_json::from_str($json)
                    .expect(concat!("failed to parse Wycheproof ", $label, " JSON"));
            file.assert_vector_count();

            let mut valid_count: usize = 0;
            let mut invalid_count: usize = 0;
            let mut _acceptable_count: usize = 0;
            let mut skip_count: usize = 0;

            for group in &file.test_groups {
                if group.public_key.curve != $curve {
                    skip_count += group.tests.len();
                    continue;
                }

                let pk_bytes = hex_decode(&group.public_key.pk, "pk");
                let pk_arr: Result<[u8; $pk_len], _> = pk_bytes.as_slice().try_into();

                let vk = pk_arr.ok().and_then(|arr| ($vk_from_bytes)(arr));

                for tc in &group.tests {
                    let msg = hex_decode(&tc.msg, "msg");
                    let sig_bytes = hex_decode(&tc.sig, "sig");

                    let sig = ($sig_from_slice)(sig_bytes.as_slice());

                    match (&vk, sig) {
                        (Some(vk), Ok(sig)) => {
                            let result = vk.verify(&msg, &sig);

                            match tc.result {
                                WycheproofResult::Valid => {
                                    assert!(
                                        result.is_ok(),
                                        "tc {}: {} verify failed for valid vector, comment: {}",
                                        tc.tc_id, $label, tc.comment,
                                    );
                                    valid_count += 1;
                                }
                                WycheproofResult::Acceptable => {
                                    _acceptable_count += 1;
                                }
                                WycheproofResult::Invalid => {
                                    assert!(
                                        result.is_err(),
                                        "tc {}: {} verify SUCCEEDED for invalid vector! \
                                         flags: {:?}, comment: {}",
                                        tc.tc_id, $label, tc.flags, tc.comment,
                                    );
                                    invalid_count += 1;
                                }
                            }
                        }
                        _ => {
                            match tc.result {
                                WycheproofResult::Valid => {
                                    panic!(
                                        "tc {}: {} key/sig parse failed for valid vector, comment: {}",
                                        tc.tc_id, $label, tc.comment,
                                    );
                                }
                                WycheproofResult::Acceptable => {
                                    _acceptable_count += 1;
                                }
                                WycheproofResult::Invalid => {
                                    invalid_count += 1;
                                }
                            }
                        }
                    }
                }
            }

            assert!(
                valid_count > 0,
                "no valid {} vectors were exercised (skipped {})",
                $label, skip_count,
            );
            assert!(
                invalid_count > 0,
                "no invalid {} vectors were exercised (skipped {})",
                $label, skip_count,
            );

            if skip_count > 0 {
                eprintln!(
                    "  wycheproof: skipped {skip_count} test vectors with non-matching curve"
                );
            }

        }
    };
}

wycheproof_eddsa_test!(
    ed25519,
    ED25519_VECTORS,
    "edwards25519",
    32,
    |arr: [u8; 32]| wolfcrypt::Ed25519VerifyingKey::from_bytes(&arr).ok(),
    |bytes: &[u8]| ed25519::Signature::try_from(bytes),
    "Ed25519",
    [wolfssl_ed25519]
);

wycheproof_eddsa_test!(
    ed448,
    ED448_VECTORS,
    "edwards448",
    57,
    |arr: [u8; 57]| wolfcrypt::Ed448VerifyingKey::from_bytes(&arr).ok(),
    |bytes: &[u8]| wolfcrypt::Ed448Signature::try_from(bytes),
    "Ed448",
    [wolfssl_ed448]
);
