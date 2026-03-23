//! AES-CCM tests using NIST SP 800-38C test vectors.
#![cfg(all(feature = "aead", wolfssl_aes_ccm))]

use hex_literal::hex;

// ---------------------------------------------------------------------------
// Standalone API — variable nonce/tag sizes (NIST SP 800-38C)
// ---------------------------------------------------------------------------

mod standalone {
    use super::*;
    use wolfcrypt::cipher::{aes_ccm_decrypt, aes_ccm_encrypt};

    /// NIST SP 800-38C, Section C.1 — Example 1 (AES-128-CCM).
    ///
    /// Key:        404142434445464748494a4b4c4d4e4f
    /// Nonce:      10111213141516 (7 bytes)
    /// AAD:        0001020304050607
    /// Plaintext:  20212223
    /// Ciphertext: 7162015b
    /// Tag:        4dac255d (4 bytes)
    #[test]
    fn nist_c1_example1_encrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("10111213141516");
        let aad = hex!("0001020304050607");
        let plaintext = hex!("20212223");
        let expected_ct = hex!("7162015b");
        let expected_tag = hex!("4dac255d");

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 4];
        aes_ccm_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag)
            .expect("CCM encrypt failed");
        assert_eq!(ct, expected_ct, "ciphertext mismatch (C.1)");
        assert_eq!(tag, expected_tag, "tag mismatch (C.1)");
    }

    #[test]
    fn nist_c1_example1_decrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("10111213141516");
        let aad = hex!("0001020304050607");
        let ciphertext = hex!("7162015b");
        let tag = hex!("4dac255d");
        let expected_pt = hex!("20212223");

        let mut pt = vec![0u8; ciphertext.len()];
        aes_ccm_decrypt(&key, &nonce, &aad, &ciphertext, &mut pt, &tag)
            .expect("CCM decrypt failed");
        assert_eq!(pt, expected_pt, "plaintext mismatch (C.1)");
    }

    /// NIST SP 800-38C, Section C.2 — Example 2 (AES-128-CCM).
    ///
    /// Key:   404142434445464748494a4b4c4d4e4f
    /// Nonce: 1011121314151617 (8 bytes)
    /// AAD:   000102030405060708090a0b0c0d0e0f (16 bytes)
    /// PT:    202122232425262728292a2b2c2d2e2f (16 bytes)
    /// CT:    d2a1f0e051ea5f62081a7792073d593d
    /// Tag:   1fc64fbfaccd (6 bytes)
    #[test]
    fn nist_c2_example2_encrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("1011121314151617");
        let aad = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex!("202122232425262728292a2b2c2d2e2f");
        let expected_ct = hex!("d2a1f0e051ea5f62081a7792073d593d");
        let expected_tag = hex!("1fc64fbfaccd");

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 6];
        aes_ccm_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag)
            .expect("CCM encrypt failed");
        assert_eq!(ct, expected_ct, "ciphertext mismatch (C.2)");
        assert_eq!(tag, expected_tag, "tag mismatch (C.2)");
    }

    #[test]
    fn nist_c2_example2_decrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("1011121314151617");
        let aad = hex!("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex!("d2a1f0e051ea5f62081a7792073d593d");
        let tag = hex!("1fc64fbfaccd");
        let expected_pt = hex!("202122232425262728292a2b2c2d2e2f");

        let mut pt = vec![0u8; ciphertext.len()];
        aes_ccm_decrypt(&key, &nonce, &aad, &ciphertext, &mut pt, &tag)
            .expect("CCM decrypt failed");
        assert_eq!(pt, expected_pt, "plaintext mismatch (C.2)");
    }

    /// NIST SP 800-38C, Section C.3 — Example 3 (AES-128-CCM).
    ///
    /// Key:   404142434445464748494a4b4c4d4e4f
    /// Nonce: 101112131415161718191a1b (12 bytes)
    /// AAD:   000102030405060708090a0b0c0d0e0f10111213 (20 bytes)
    /// PT:    202122232425262728292a2b2c2d2e2f3031323334353637 (24 bytes)
    /// CT:    e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5
    /// Tag:   484392fbc1b09951 (8 bytes)
    #[test]
    fn nist_c3_example3_encrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("101112131415161718191a1b");
        let aad = hex!("000102030405060708090a0b0c0d0e0f10111213");
        let plaintext = hex!("202122232425262728292a2b2c2d2e2f3031323334353637");
        let expected_ct = hex!("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5");
        let expected_tag = hex!("484392fbc1b09951");

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 8];
        aes_ccm_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag)
            .expect("CCM encrypt failed");
        assert_eq!(ct, expected_ct, "ciphertext mismatch (C.3)");
        assert_eq!(tag, expected_tag, "tag mismatch (C.3)");
    }

    #[test]
    fn nist_c3_example3_decrypt() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("101112131415161718191a1b");
        let aad = hex!("000102030405060708090a0b0c0d0e0f10111213");
        let ciphertext = hex!("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5");
        let tag = hex!("484392fbc1b09951");
        let expected_pt = hex!("202122232425262728292a2b2c2d2e2f3031323334353637");

        let mut pt = vec![0u8; ciphertext.len()];
        aes_ccm_decrypt(&key, &nonce, &aad, &ciphertext, &mut pt, &tag)
            .expect("CCM decrypt failed");
        assert_eq!(pt, expected_pt, "plaintext mismatch (C.3)");
    }

    /// A corrupted tag must cause decryption to fail.
    #[test]
    fn bad_tag_rejected() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("10111213141516");
        let aad = hex!("0001020304050607");
        let plaintext = hex!("20212223");

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 4];
        aes_ccm_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag).unwrap();

        // Flip a bit in the tag.
        tag[0] ^= 0x01;
        let mut pt = vec![0u8; ct.len()];
        assert!(
            aes_ccm_decrypt(&key, &nonce, &aad, &ct, &mut pt, &tag).is_err(),
            "corrupted tag must be rejected"
        );
    }

    /// Invalid nonce length must be rejected.
    #[test]
    fn bad_nonce_len_rejected() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let plaintext = hex!("20212223");
        let mut ct = vec![0u8; 4];
        let mut tag = vec![0u8; 16];

        // Too short (6 bytes).
        let short_nonce = [0u8; 6];
        assert!(aes_ccm_encrypt(&key, &short_nonce, &[], &plaintext, &mut ct, &mut tag).is_err());

        // Too long (14 bytes).
        let long_nonce = [0u8; 14];
        assert!(aes_ccm_encrypt(&key, &long_nonce, &[], &plaintext, &mut ct, &mut tag).is_err());
    }
}

// ---------------------------------------------------------------------------
// Trait-based API (AeadInPlace) — round-trip with 13-byte nonce / 16-byte tag
// ---------------------------------------------------------------------------

mod trait_api {
    use super::*;
    use aead_trait::{AeadInPlace, KeyInit};
    use wolfcrypt::cipher::Aes128Ccm;

    /// Round-trip encrypt/decrypt through the AeadInPlace trait.
    #[test]
    fn aes128_ccm_trait_round_trip() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("101112131415161718191a1b0c"); // 13 bytes
        let aad = hex!("0001020304050607");
        let plaintext = b"Hello, AES-CCM trait API!";

        let cipher = Aes128Ccm::new((&key).into());

        // Encrypt in-place.
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, &mut buf)
            .expect("encrypt failed");
        assert_ne!(&buf[..], &plaintext[..], "ciphertext must differ from plaintext");

        // Decrypt in-place.
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad, &mut buf, &tag)
            .expect("decrypt failed");
        assert_eq!(&buf[..], &plaintext[..], "round-trip mismatch");
    }

    /// Verify that a corrupted tag is rejected by the trait API.
    #[test]
    fn aes128_ccm_trait_bad_tag() {
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("101112131415161718191a1b0c"); // 13 bytes
        let aad = hex!("0001020304050607");
        let plaintext = b"Tag verification test";

        let cipher = Aes128Ccm::new((&key).into());

        let mut buf = plaintext.to_vec();
        let mut tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, &mut buf)
            .expect("encrypt failed");

        // Corrupt the tag.
        tag[0] ^= 0xff;
        assert!(
            cipher
                .decrypt_in_place_detached((&nonce).into(), &aad, &mut buf, &tag)
                .is_err(),
            "corrupted tag must be rejected"
        );
    }

    /// AES-256-CCM round-trip via the trait API.
    #[test]
    fn aes256_ccm_trait_round_trip() {
        use wolfcrypt::cipher::Aes256Ccm;

        let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let nonce = hex!("101112131415161718191a1b0c"); // 13 bytes
        let aad = b"extra data";
        let plaintext = b"AES-256-CCM round-trip test!";

        let cipher = Aes256Ccm::new((&key).into());

        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), aad, &mut buf)
            .expect("encrypt failed");

        cipher
            .decrypt_in_place_detached((&nonce).into(), aad, &mut buf, &tag)
            .expect("decrypt failed");
        assert_eq!(&buf[..], &plaintext[..], "AES-256-CCM round-trip mismatch");
    }
}
