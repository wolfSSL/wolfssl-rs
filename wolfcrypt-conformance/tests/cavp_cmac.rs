#![cfg(all(wolfssl_openssl_extra, wolfssl_cmac))]

mod helpers;
use helpers::cavp::parse_cavp;
use digest::Mac;

const AES128_CMAC: &str = include_str!("../vectors/cavp/cavp_aes128_cmac_tests.txt");
const AES256_CMAC: &str = include_str!("../vectors/cavp/cavp_aes256_cmac_tests.txt");

/// Run CAVP CMAC verification tests for a given AES key size.
///
/// Each test case specifies `Key`, `Msg`, `Mac`, `Tlen` (truncation length in
/// bytes), and `Result` (`"P"` for pass, `"F ..."` for expected-fail).
/// We compute the CMAC, truncate to `Tlen` bytes, and check whether the
/// truncated tag matches the expected value.
macro_rules! cavp_cmac_test {
    ($name:ident, $wolf_type:ty, $klen:expr, $file:expr) => {
        #[test]
        fn $name() {
            let cases = parse_cavp($file);
            let mut pass_count = 0usize;
            let mut fail_count = 0usize;

            for tc in &cases {
                if !tc.has_field("Key") || !tc.has_field("Mac") || !tc.has_field("Result") {
                    continue;
                }

                let klen = tc.usize_field("Klen");
                if klen != $klen {
                    continue;
                }

                let key = tc.bytes("Key");
                let mlen = tc.usize_field("Mlen");
                let tlen = tc.usize_field("Tlen");
                let expected_mac = tc.bytes("Mac");
                let result_str = tc.string_field("Result");
                let should_pass = result_str == "P";

                // When Mlen == 0 the Msg field is typically "00" (placeholder),
                // but we should hash zero bytes of input.
                let msg_bytes = tc.bytes("Msg");
                let msg = if mlen == 0 { &[][..] } else { &msg_bytes[..mlen] };

                let mut mac = <$wolf_type>::new_from_slice(&key)
                    .expect(concat!(stringify!($name), ": new_from_slice failed"));
                mac.update(msg);
                let tag = mac.finalize().into_bytes();

                let tags_match = tag[..tlen] == expected_mac[..tlen];

                if should_pass {
                    assert!(
                        tags_match,
                        "{} CAVP: expected PASS but tags differ (Count={}, Tlen={})",
                        stringify!($name),
                        tc.string_field("Count"),
                        tlen
                    );
                    pass_count += 1;
                } else {
                    assert!(
                        !tags_match,
                        "{} CAVP: expected FAIL but tags matched (Count={}, Tlen={})",
                        stringify!($name),
                        tc.string_field("Count"),
                        tlen
                    );
                    fail_count += 1;
                }
            }

            assert!(
                pass_count > 0,
                "{} CAVP: zero passing test cases processed",
                stringify!($name)
            );
            assert!(
                fail_count > 0,
                "{} CAVP: zero failing test cases processed",
                stringify!($name)
            );
        }
    };
}

cavp_cmac_test!(aes128_cmac_cavp, wolfcrypt::WolfCmacAes128, 16, AES128_CMAC);
cavp_cmac_test!(aes256_cmac_cavp, wolfcrypt::WolfCmacAes256, 32, AES256_CMAC);
