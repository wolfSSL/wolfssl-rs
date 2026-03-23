// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

use ring::key_wrap::{AesKek, BlockCipher, BlockCipherId, KeyWrap, KeyWrapPadded, AES_128, AES_256};

// NIST SP 800-38F / RFC 3394 Test Vectors

#[test]
fn aes_128_key_wrap_round_trip() {
    let kek_bytes: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let plaintext: &[u8] = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    let kek = AesKek::new(&AES_128, kek_bytes).expect("KEK creation failed");
    let mut wrap_buf = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(plaintext, &mut wrap_buf).expect("Wrap failed");

    let kek = AesKek::new(&AES_128, kek_bytes).expect("KEK creation failed");
    let mut unwrap_buf = vec![0u8; ciphertext.len()];
    let recovered = kek.unwrap(ciphertext, &mut unwrap_buf).expect("Unwrap failed");

    assert_eq!(plaintext, recovered, "AES-128 key wrap round trip failed");
}

#[test]
fn aes_256_key_wrap_round_trip() {
    let kek_bytes: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];
    let plaintext: &[u8] = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    let kek = AesKek::new(&AES_256, kek_bytes).expect("KEK creation failed");
    let mut wrap_buf = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(plaintext, &mut wrap_buf).expect("Wrap failed");

    let kek = AesKek::new(&AES_256, kek_bytes).expect("KEK creation failed");
    let mut unwrap_buf = vec![0u8; ciphertext.len()];
    let recovered = kek.unwrap(ciphertext, &mut unwrap_buf).expect("Unwrap failed");

    assert_eq!(plaintext, recovered, "AES-256 key wrap round trip failed");
}

#[test]
fn aes_128_key_wrap_nist_vector() {
    // NIST SP 800-38F Section F.2.1: AES-128 KEK, 128-bit data
    let kek_bytes = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
    let plaintext = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
    let expected_ct = hex_to_bytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

    let kek = AesKek::new(&AES_128, &kek_bytes).unwrap();
    let mut output = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(&plaintext, &mut output).unwrap();
    assert_eq!(ciphertext, &expected_ct[..], "AES-128 wrap NIST vector mismatch");

    let kek = AesKek::new(&AES_128, &kek_bytes).unwrap();
    let mut output = vec![0u8; expected_ct.len()];
    let recovered = kek.unwrap(&expected_ct, &mut output).unwrap();
    assert_eq!(recovered, &plaintext[..], "AES-128 unwrap NIST vector mismatch");
}

#[test]
fn aes_256_key_wrap_nist_vector() {
    // NIST SP 800-38F Section F.2.5: AES-256 KEK, 128-bit data
    let kek_bytes = hex_to_bytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let plaintext = hex_to_bytes("00112233445566778899AABBCCDDEEFF");
    let expected_ct = hex_to_bytes("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");

    let kek = AesKek::new(&AES_256, &kek_bytes).unwrap();
    let mut output = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(&plaintext, &mut output).unwrap();
    assert_eq!(ciphertext, &expected_ct[..], "AES-256 wrap NIST vector mismatch");

    let kek = AesKek::new(&AES_256, &kek_bytes).unwrap();
    let mut output = vec![0u8; expected_ct.len()];
    let recovered = kek.unwrap(&expected_ct, &mut output).unwrap();
    assert_eq!(recovered, &plaintext[..], "AES-256 unwrap NIST vector mismatch");
}

#[test]
fn key_wrap_with_padding_round_trip() {
    let kek_bytes: &[u8] = &[
        0xa8, 0xe0, 0x6d, 0xa6, 0x25, 0xa6, 0x5b, 0x25,
        0xcf, 0x50, 0x30, 0x82, 0x68, 0x30, 0xb6, 0x61,
    ];
    // Non-block-aligned plaintext (8 bytes, requires padding)
    let plaintext: &[u8] = &[0x43, 0xac, 0xff, 0x29, 0x31, 0x20, 0xdd, 0x5d];

    let kek = AesKek::new(&AES_128, kek_bytes).unwrap();
    let mut wrap_buf = vec![0u8; plaintext.len() + 15];
    let ciphertext = kek.wrap_with_padding(plaintext, &mut wrap_buf).unwrap();

    let kek = AesKek::new(&AES_128, kek_bytes).unwrap();
    let mut unwrap_buf = vec![0u8; ciphertext.len()];
    let recovered = kek.unwrap_with_padding(ciphertext, &mut unwrap_buf).unwrap();

    assert_eq!(plaintext, recovered, "Key wrap with padding round trip failed");
}

#[test]
fn key_wrap_tampered_ciphertext_fails() {
    let kek_bytes = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
    let plaintext = hex_to_bytes("00112233445566778899AABBCCDDEEFF");

    let kek = AesKek::new(&AES_128, &kek_bytes).unwrap();
    let mut output = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(&plaintext, &mut output).unwrap();

    // Tamper with ciphertext
    let mut tampered = ciphertext.to_vec();
    tampered[0] ^= 0x01;

    let kek = AesKek::new(&AES_128, &kek_bytes).unwrap();
    let mut unwrap_buf = vec![0u8; tampered.len()];
    assert!(
        kek.unwrap(&tampered, &mut unwrap_buf).is_err(),
        "Unwrap should fail for tampered ciphertext"
    );
}

#[test]
fn key_wrap_wrong_key_fails() {
    let kek1 = hex_to_bytes("000102030405060708090A0B0C0D0E0F");
    let kek2 = hex_to_bytes("FF0102030405060708090A0B0C0D0E0F");
    let plaintext = hex_to_bytes("00112233445566778899AABBCCDDEEFF");

    let kek = AesKek::new(&AES_128, &kek1).unwrap();
    let mut output = vec![0u8; plaintext.len() + 8];
    let ciphertext = kek.wrap(&plaintext, &mut output).unwrap();

    let wrong_kek = AesKek::new(&AES_128, &kek2).unwrap();
    let mut unwrap_buf = vec![0u8; ciphertext.len()];
    assert!(
        wrong_kek.unwrap(ciphertext, &mut unwrap_buf).is_err(),
        "Unwrap should fail with wrong KEK"
    );
}

#[test]
fn block_cipher_properties() {
    assert_eq!(AES_128.id(), BlockCipherId::Aes128);
    assert_eq!(AES_128.key_len(), 16);
    assert_eq!(AES_256.id(), BlockCipherId::Aes256);
    assert_eq!(AES_256.key_len(), 32);
}

#[test]
fn invalid_kek_length_fails() {
    // 15 bytes — not a valid AES key length
    let bad_kek = &[0u8; 15];
    assert!(AesKek::new(&AES_128, bad_kek).is_err());
    assert!(AesKek::new(&AES_256, bad_kek).is_err());
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
