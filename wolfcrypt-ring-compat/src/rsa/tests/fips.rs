#![cfg(debug_assertions)]

use crate::fips::{assert_fips_status_indicator, FipsServiceStatus};
use crate::rsa::{KeyPair, KeySize};

macro_rules! generate_key {
    ($name:ident, KeyPair, $size:expr) => {
        #[test]
        fn $name() {
            // Using the non-fips generator will not set the indicator
            #[cfg(not(feature = "fips"))]
            let _ =
                assert_fips_status_indicator!(KeyPair::generate($size), FipsServiceStatus::Unset)
                    .expect("key generated");

            // Using the fips generator should set the indicator
            #[cfg(feature = "fips")]
            let _ = assert_fips_status_indicator!(
                KeyPair::generate($size),
                FipsServiceStatus::Approved
            )
            .expect("key generated");
        }
    };
    ($name:ident, KeyPair, $size:expr, false) => {
        #[test]
        fn $name() {
            // Using the non-fips generator will not set the indicator
            let _ =
                assert_fips_status_indicator!(KeyPair::generate($size), FipsServiceStatus::Unset);

            // Using the fips generator should set the indicator
            let _ = assert_fips_status_indicator!(
                KeyPair::generate_fips($size),
                FipsServiceStatus::NonApproved
            )
            .expect_err("key size not allowed");
        }
    };
}

generate_key!(rsa2048_signing_generate_key, KeyPair, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_key!(rsa3072_signing_generate_key, KeyPair, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_key!(rsa4096_signing_generate_key, KeyPair, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_key!(rsa8192_signing_generate_key, KeyPair, KeySize::Rsa8192);
