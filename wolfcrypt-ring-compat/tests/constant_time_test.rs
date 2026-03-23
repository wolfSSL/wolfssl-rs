// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

use ring::{constant_time, error, rand};

#[test]
fn constant_time_verify_slices_equal() {
    let a = b"hello world";
    let b = b"hello world";
    assert!(constant_time::verify_slices_are_equal(a, b).is_ok());
}

#[test]
fn constant_time_verify_slices_not_equal() {
    let a = b"hello world";
    let b = b"hello worle";
    assert!(constant_time::verify_slices_are_equal(a, b).is_err());
}

#[test]
fn constant_time_verify_empty_slices_equal() {
    assert!(constant_time::verify_slices_are_equal(&[], &[]).is_ok());
}

#[test]
fn constant_time_verify_different_lengths() {
    let a = b"short";
    let b = b"longer";
    assert!(constant_time::verify_slices_are_equal(a, b).is_err());
}

#[test]
fn constant_time_verify_single_byte_equal() {
    assert!(constant_time::verify_slices_are_equal(&[0x42], &[0x42]).is_ok());
}

#[test]
fn constant_time_verify_single_byte_not_equal() {
    assert!(constant_time::verify_slices_are_equal(&[0x42], &[0x43]).is_err());
}

#[test]
fn constant_time_verify_one_bit_difference() {
    // Test that a single bit flip is detected at every position
    let original = [0x00u8; 32];

    for byte_pos in 0..32 {
        for bit_pos in 0..8 {
            let mut modified = original;
            modified[byte_pos] ^= 1 << bit_pos;
            assert!(
                constant_time::verify_slices_are_equal(&original, &modified).is_err(),
                "Failed to detect bit flip at byte {} bit {}",
                byte_pos,
                bit_pos
            );
        }
    }
}

#[test]
fn constant_time_verify_random_equal() {
    // Generate random data and verify it equals itself
    let rng = rand::SystemRandom::new();
    let mut buf = [0u8; 64];
    rand::SecureRandom::fill(&rng, &mut buf).unwrap();

    assert!(
        constant_time::verify_slices_are_equal(&buf, &buf).is_ok(),
        "Random buffer should equal itself"
    );
}

#[test]
fn constant_time_verify_random_not_equal() {
    // Generate two different random buffers
    let rng = rand::SystemRandom::new();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rand::SecureRandom::fill(&rng, &mut a).unwrap();
    rand::SecureRandom::fill(&rng, &mut b).unwrap();

    // Overwhelmingly likely to differ
    // (probability of collision is 2^-256)
    assert!(
        constant_time::verify_slices_are_equal(&a, &b).is_err(),
        "Two random 32-byte buffers should not be equal"
    );
}

#[test]
fn constant_time_verify_all_byte_values() {
    // Verify that comparison works for all byte values
    for i in 0..=255u8 {
        let a = [i; 1];
        let b = [i; 1];
        assert!(
            constant_time::verify_slices_are_equal(&a, &b).is_ok(),
            "Byte value {i} should equal itself"
        );

        if i < 255 {
            let c = [i + 1; 1];
            assert!(
                constant_time::verify_slices_are_equal(&a, &c).is_err(),
                "Byte value {i} should not equal {}",
                i + 1
            );
        }
    }
}

#[test]
fn constant_time_verify_various_lengths() {
    for len in [1, 2, 3, 4, 8, 15, 16, 17, 31, 32, 33, 48, 64, 128, 256] {
        let a = vec![0xABu8; len];
        let b = vec![0xABu8; len];
        assert!(
            constant_time::verify_slices_are_equal(&a, &b).is_ok(),
            "Equal buffers of length {len} should match"
        );

        let mut c = vec![0xABu8; len];
        c[len - 1] ^= 0x01; // Flip last byte
        assert!(
            constant_time::verify_slices_are_equal(&a, &c).is_err(),
            "Buffers of length {len} with flipped last byte should not match"
        );
    }
}

#[test]
fn constant_time_returns_unspecified_error() {
    // Verify the error type is error::Unspecified
    let result = constant_time::verify_slices_are_equal(&[0], &[1]);
    assert_eq!(result.unwrap_err(), error::Unspecified);
}
