#![cfg(all(wolfssl_openssl_extra, wolfssl_aes_keywrap))]

mod helpers;
use helpers::wycheproof::*;

use wolfcrypt::keywrap::{aes_unwrap_key, aes_wrap_key};

const AES_WRAP_VECTORS: &str =
    include_str!("../third_party/wycheproof/testvectors_v1/aes_wrap_test.json");

#[test]
fn aes_keywrap() {
    let file: WycheproofFile<KeyWrapTestGroup> =
        serde_json::from_str(AES_WRAP_VECTORS).expect("failed to parse Wycheproof AES-WRAP JSON");
    file.assert_vector_count();

    let mut valid_count: usize = 0;
    let mut invalid_count: usize = 0;
    let mut _acceptable_count: usize = 0;

    for group in &file.test_groups {
        for tc in &group.tests {
            let key = hex_decode(&tc.key, "key");
            let msg = hex_decode(&tc.msg, "msg");
            let ct = hex_decode(&tc.ct, "ct");

            match tc.result {
                WycheproofResult::Valid => {
                    // Wrap must produce the expected ciphertext.
                    let wrapped = aes_wrap_key(&key, &msg);
                    assert!(
                        wrapped.is_ok(),
                        "tc {}: aes_wrap_key failed for valid vector, comment: {}",
                        tc.tc_id,
                        tc.comment,
                    );
                    assert_eq!(
                        wrapped.unwrap(), ct,
                        "tc {}: wrapped ciphertext mismatch for valid vector, comment: {}",
                        tc.tc_id,
                        tc.comment,
                    );

                    // Unwrap must recover the original message.
                    let unwrapped = aes_unwrap_key(&key, &ct);
                    assert!(
                        unwrapped.is_ok(),
                        "tc {}: aes_unwrap_key failed for valid vector, comment: {}",
                        tc.tc_id,
                        tc.comment,
                    );
                    assert_eq!(
                        unwrapped.unwrap(),
                        msg,
                        "tc {}: unwrapped plaintext mismatch for valid vector, comment: {}",
                        tc.tc_id,
                        tc.comment,
                    );
                    valid_count += 1;
                }
                WycheproofResult::Acceptable => {
                    // Acceptable: both accept and reject are fine.
                    // Just exercise the API without asserting success.
                    let _wrapped = aes_wrap_key(&key, &msg);
                    let _unwrapped = aes_unwrap_key(&key, &ct);
                    _acceptable_count += 1;
                }
                WycheproofResult::Invalid => {
                    // Unwrap must fail.
                    let unwrapped = aes_unwrap_key(&key, &ct);
                    assert!(
                        unwrapped.is_err(),
                        "tc {}: aes_unwrap_key SUCCEEDED for invalid vector! \
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
        "no valid AES-WRAP vectors were exercised",
    );
    assert!(
        invalid_count > 0,
        "no invalid AES-WRAP vectors were exercised",
    );

}
