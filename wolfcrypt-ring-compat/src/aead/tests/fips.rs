#![cfg(debug_assertions)]

mod chacha20_poly1305_openssh;
mod quic;

use crate::aead::nonce_sequence::Counter64Builder;
use crate::aead::{
    Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use crate::fips::{assert_fips_status_indicator, FipsServiceStatus};

const TEST_KEY_128_BIT: [u8; 16] = [
    0x9f, 0xd9, 0x41, 0xc3, 0xa6, 0xfe, 0xb9, 0x26, 0x2a, 0x35, 0xa7, 0x44, 0xbb, 0xc0, 0x3a, 0x6a,
];

const TEST_KEY_256_BIT: [u8; 32] = [
    0xd8, 0x32, 0x58, 0xa9, 0x5a, 0x62, 0x6c, 0x99, 0xc4, 0xe6, 0xb5, 0x3f, 0x97, 0x90, 0x62, 0xbe,
    0x71, 0x0f, 0xd5, 0xe1, 0xd4, 0xfe, 0x95, 0xb3, 0x03, 0x46, 0xa5, 0x8e, 0x36, 0xad, 0x18, 0xe3,
];

const TEST_MESSAGE: &[u8] = "test message".as_bytes();

macro_rules! nonce_sequence_api {
    ($name:ident, $alg:expr, $key:expr, $seal_expect:path, $open_expect:path) => {
        #[test]
        fn $name() {
            {
                let mut key = SealingKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let mut in_out = Vec::from(TEST_MESSAGE);

                assert_fips_status_indicator!(
                    key.seal_in_place_append_tag(Aad::empty(), &mut in_out),
                    $seal_expect
                )
                .unwrap();

                let mut key = OpeningKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let result = assert_fips_status_indicator!(
                    key.open_in_place(Aad::empty(), &mut in_out),
                    $open_expect
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE, result);
            }

            {
                let mut key = SealingKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let mut in_out = Vec::from(TEST_MESSAGE);

                let tag = assert_fips_status_indicator!(
                    key.seal_in_place_separate_tag(Aad::empty(), &mut in_out),
                    $seal_expect
                )
                .unwrap();

                in_out.extend(tag.as_ref().iter());

                let mut key = OpeningKey::new(
                    UnboundKey::new($alg, $key).unwrap(),
                    Counter64Builder::new().build(),
                );

                let result = assert_fips_status_indicator!(
                    key.open_in_place(Aad::empty(), &mut in_out),
                    $open_expect
                )
                .unwrap();

                assert_eq!(TEST_MESSAGE, result);
            }
        }
    };
}

nonce_sequence_api!(
    aes_gcm_128_nonce_sequence_api,
    &AES_128_GCM,
    &TEST_KEY_128_BIT[..],
    FipsServiceStatus::NonApproved,
    FipsServiceStatus::Approved
);
nonce_sequence_api!(
    aes_gcm_256_nonce_sequence_api,
    &AES_256_GCM,
    &TEST_KEY_256_BIT[..],
    FipsServiceStatus::NonApproved,
    FipsServiceStatus::Approved
);
nonce_sequence_api!(
    chacha20_poly1305_nonce_sequence_api,
    &CHACHA20_POLY1305,
    &TEST_KEY_256_BIT[..],
    FipsServiceStatus::NonApproved,
    FipsServiceStatus::NonApproved
);
