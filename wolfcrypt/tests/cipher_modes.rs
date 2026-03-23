//! Tests for AES-OFB, AES-XTS, and AES-EAX cipher modes.
//!
//! All test vectors are drawn from published standards:
//! - AES-OFB: NIST SP 800-38A, Section F.4.1 / F.4.2
//! - AES-XTS: IEEE 1619-2007 / NIST XTS-AES test vector #1
//! - AES-EAX: Bellare, Rogaway, Wagner — "The EAX Mode of Operation" (2004)

// ============================================================
// AES-OFB — NIST SP 800-38A F.4.1 (AES-128-OFB encrypt)
// ============================================================

#[cfg(wolfssl_aes_ofb)]
mod ofb {
    use cipher_trait::{KeyIvInit, StreamCipher};
    use hex_literal::hex;
    use wolfcrypt::cipher::Aes128Ofb;

    /// NIST SP 800-38A, Section F.4.1: AES-128-OFB Encrypt
    /// Key:       2b7e151628aed2a6abf7158809cf4f3c
    /// IV:        000102030405060708090a0b0c0d0e0f
    /// Plaintext: 6bc1bee22e409f96e93d7e117393172a
    ///            ae2d8a571e03ac9c9eb76fac45af8e51
    ///            30c81c46a35ce411e5fbc1191a0a52ef
    ///            f69f2445df4f9b17ad2b417be66c3710
    /// Ciphertext:3b3fd92eb72dad20333449f8e83cfb4a
    ///            7789508d16918f03f53c52dac54ed825
    ///            9740051e9c5fecf64344f7a82260edcc
    ///            304c6528f659c77866a510d9c1d6ae5e
    #[test]
    fn aes128_ofb_nist_sp800_38a_f41() {
        let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex!(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        let expected_ct = hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e"
        );

        // Encrypt
        let mut cipher = Aes128Ofb::new((&key).into(), (&iv).into());
        let mut buf = plaintext.to_vec();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected_ct, "AES-128-OFB encrypt mismatch");

        // Decrypt (OFB is symmetric: apply keystream to ciphertext recovers plaintext)
        let mut cipher = Aes128Ofb::new((&key).into(), (&iv).into());
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, plaintext, "AES-128-OFB decrypt mismatch");
    }

    /// Round-trip test: encrypt then decrypt with AES-256-OFB.
    #[test]
    fn aes256_ofb_round_trip() {
        use wolfcrypt::cipher::Aes256Ofb;

        let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = b"Round-trip test for AES-256-OFB!";

        let mut ct = plaintext.to_vec();
        let mut cipher = Aes256Ofb::new((&key).into(), (&iv).into());
        cipher.apply_keystream(&mut ct);
        assert_ne!(&ct[..], &plaintext[..], "ciphertext must differ from plaintext");

        let mut pt = ct.clone();
        let mut cipher = Aes256Ofb::new((&key).into(), (&iv).into());
        cipher.apply_keystream(&mut pt);
        assert_eq!(&pt[..], &plaintext[..], "round-trip failed");
    }
}

// ============================================================
// AES-XTS — IEEE 1619-2007 / NIST XTS-AES test vector #1
// ============================================================

#[cfg(wolfssl_aes_xts)]
mod xts {
    use hex_literal::hex;
    use wolfcrypt::cipher::AesXts;

    /// IEEE 1619-2007 XTS-AES test vector #1 (AES-128-XTS).
    ///
    /// Key1 = 00000000000000000000000000000000
    /// Key2 = 00000000000000000000000000000000
    /// Data unit sequence number (tweak) = 0
    /// Plaintext  = 00000000000000000000000000000000
    ///              00000000000000000000000000000000
    /// Ciphertext = 917cf69ebd68b2ec9b9fe9a3eadda692
    ///              cd43d2f59598ed858c02c2652fbf922e
    #[test]
    fn aes128_xts_ieee1619_vector1() {
        // Combined key = Key1 || Key2 (32 bytes for AES-128-XTS)
        let key = hex!(
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
        );
        // Data unit sequence number = 0 → 16-byte little-endian tweak
        let tweak = hex!("00000000000000000000000000000000");
        let plaintext = hex!(
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
        );
        let expected_ct = hex!(
            "917cf69ebd68b2ec9b9fe9a3eadda692"
            "cd43d2f59598ed858c02c2652fbf922e"
        );

        // Encrypt
        let mut enc = AesXts::new_encrypt(&key).expect("new_encrypt failed");
        let mut ct = vec![0u8; plaintext.len()];
        enc.encrypt(&mut ct, &plaintext, &tweak).expect("encrypt failed");
        assert_eq!(ct, expected_ct, "AES-128-XTS encrypt mismatch");

        // Decrypt
        let mut dec = AesXts::new_decrypt(&key).expect("new_decrypt failed");
        let mut pt = vec![0u8; ct.len()];
        dec.decrypt(&mut pt, &ct, &tweak).expect("decrypt failed");
        assert_eq!(pt, plaintext, "AES-128-XTS decrypt mismatch");
    }

    /// IEEE 1619-2007 XTS-AES test vector #4 (AES-128-XTS).
    ///
    /// Key1 = 27182818284590452353602874713526
    /// Key2 = 31415926535897932384626433832795
    /// Tweak (data unit seq number) = 0
    /// Plaintext  = 000102030405060708090a0b0c0d0e0f
    ///              101112131415161718191a1b1c1d1e1f
    /// Ciphertext = 27a7479befa1d476489f308cd4cfa6e2
    ///              a96e4bbe3208ff25287dd3819616e89c
    #[test]
    fn aes128_xts_ieee1619_vector4() {
        let key = hex!(
            "27182818284590452353602874713526"
            "31415926535897932384626433832795"
        );
        let tweak = hex!("00000000000000000000000000000000");
        let plaintext = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        );
        let expected_ct = hex!(
            "27a7479befa1d476489f308cd4cfa6e2"
            "a96e4bbe3208ff25287dd3819616e89c"
        );

        let mut enc = AesXts::new_encrypt(&key).expect("new_encrypt");
        let mut ct = vec![0u8; plaintext.len()];
        enc.encrypt(&mut ct, &plaintext, &tweak).expect("encrypt");
        assert_eq!(ct, expected_ct, "AES-128-XTS vector 4 encrypt mismatch");

        let mut dec = AesXts::new_decrypt(&key).expect("new_decrypt");
        let mut pt = vec![0u8; ct.len()];
        dec.decrypt(&mut pt, &ct, &tweak).expect("decrypt");
        assert_eq!(pt, plaintext, "AES-128-XTS vector 4 decrypt mismatch");
    }

    /// Guard: encrypt instance cannot be used for decrypt.
    #[test]
    fn xts_direction_guard() {
        let key = [0u8; 32];
        let tweak = [0u8; 16];
        let data = [0u8; 32];
        let mut out = [0u8; 32];

        let mut enc = AesXts::new_encrypt(&key).unwrap();
        assert!(enc.decrypt(&mut out, &data, &tweak).is_err());

        let mut dec = AesXts::new_decrypt(&key).unwrap();
        assert!(dec.encrypt(&mut out, &data, &tweak).is_err());
    }

    /// Invalid key length must be rejected.
    #[test]
    fn xts_bad_key_len() {
        assert!(AesXts::new_encrypt(&[0u8; 16]).is_err());
        assert!(AesXts::new_encrypt(&[0u8; 48]).is_err());
    }
}

// ============================================================
// AES-EAX — Bellare, Rogaway, Wagner test vectors
// ============================================================

#[cfg(wolfssl_aes_eax)]
mod eax {
    use hex_literal::hex;
    use wolfcrypt::cipher::{aes_eax_decrypt, aes_eax_encrypt};

    /// EAX test vector #1 from Bellare, Rogaway, Wagner (2004).
    ///
    /// Key   = 233952DEE4D5ED5F9B9C6D6FF80FF478
    /// Nonce = 62EC67F9C3A4A407FCB2A8C49483B026
    /// Header (AAD) = 6BFB914FD07EAE6B
    /// Plaintext  = (empty)
    /// Ciphertext = (empty)
    /// Tag   = E037830E8389F27B025A2D6527E79D01
    #[test]
    fn aes_eax_bellare_vector1() {
        let key = hex!("233952DEE4D5ED5F9B9C6D6FF80FF478");
        let nonce = hex!("62EC67F9C3A4A407FCB2A8C49483B026");
        let aad = hex!("6BFB914FD07EAE6B");
        let plaintext = b"";
        let expected_tag = hex!("E037830E8389F27B025A2D6527E79D01");

        // Encrypt
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 16];
        aes_eax_encrypt(&key, &nonce, &aad, plaintext, &mut ct, &mut tag)
            .expect("EAX encrypt failed");
        assert_eq!(tag, expected_tag, "EAX tag mismatch on vector 1");

        // Decrypt
        let mut pt = vec![0u8; ct.len()];
        aes_eax_decrypt(&key, &nonce, &aad, &ct, &mut pt, &tag)
            .expect("EAX decrypt failed");
        assert_eq!(pt, plaintext, "EAX plaintext mismatch on vector 1");
    }

    /// EAX test vector #2 from Bellare, Rogaway, Wagner (2004).
    ///
    /// Key   = 91945D3F4DCBEE0BF45EF52255F095A4
    /// Nonce = BECAF043B0A23D843194BA972C66DEBD
    /// Header (AAD) = FA3BFD4806EB53FA
    /// Plaintext  = F7FB
    /// Ciphertext = 19DD
    /// Tag   = 5C4C9331049D0BDAB0277408F67967E5
    #[test]
    fn aes_eax_bellare_vector2() {
        let key = hex!("91945D3F4DCBEE0BF45EF52255F095A4");
        let nonce = hex!("BECAF043B0A23D843194BA972C66DEBD");
        let aad = hex!("FA3BFD4806EB53FA");
        let plaintext = hex!("F7FB");
        let expected_ct = hex!("19DD");
        let expected_tag = hex!("5C4C9331049D0BDAB0277408F67967E5");

        // Encrypt
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 16];
        aes_eax_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag)
            .expect("EAX encrypt failed");
        assert_eq!(ct, expected_ct, "EAX ciphertext mismatch on vector 2");
        assert_eq!(tag, expected_tag, "EAX tag mismatch on vector 2");

        // Decrypt
        let mut pt = vec![0u8; ct.len()];
        aes_eax_decrypt(&key, &nonce, &aad, &ct, &mut pt, &tag)
            .expect("EAX decrypt failed");
        assert_eq!(pt.as_slice(), plaintext.as_slice(), "EAX plaintext mismatch on vector 2");
    }

    /// EAX test vector #4 from Bellare, Rogaway, Wagner (2004).
    ///
    /// Key   = 01F74AD64077F2E704C0F60ADA3DD523
    /// Nonce = 70C3DB4F0D26368400A10ED05D2BFF5E
    /// Header (AAD) = 234A3463C1264AC6
    /// Plaintext  = 1A47CB4933
    /// Ciphertext = D851D5BAE0
    /// Tag   = 3A59F238A23E39199DC9266626C40F80
    #[test]
    fn aes_eax_bellare_vector4() {
        let key = hex!("01F74AD64077F2E704C0F60ADA3DD523");
        let nonce = hex!("70C3DB4F0D26368400A10ED05D2BFF5E");
        let aad = hex!("234A3463C1264AC6");
        let plaintext = hex!("1A47CB4933");
        let expected_ct = hex!("D851D5BAE0");
        let expected_tag = hex!("3A59F238A23E39199DC9266626C40F80");

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 16];
        aes_eax_encrypt(&key, &nonce, &aad, &plaintext, &mut ct, &mut tag)
            .expect("EAX encrypt failed");
        assert_eq!(ct, expected_ct, "EAX ciphertext mismatch on vector 4");
        assert_eq!(tag, expected_tag, "EAX tag mismatch on vector 4");

        let mut pt = vec![0u8; ct.len()];
        aes_eax_decrypt(&key, &nonce, &aad, &ct, &mut pt, &tag)
            .expect("EAX decrypt failed");
        assert_eq!(pt.as_slice(), plaintext.as_slice(), "EAX plaintext mismatch on vector 4");
    }

    /// Verify that a corrupted tag causes decryption to fail.
    #[test]
    fn aes_eax_bad_tag() {
        let key = hex!("233952DEE4D5ED5F9B9C6D6FF80FF478");
        let nonce = hex!("62EC67F9C3A4A407FCB2A8C49483B026");
        let aad = hex!("6BFB914FD07EAE6B");
        let plaintext = b"";

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = vec![0u8; 16];
        aes_eax_encrypt(&key, &nonce, &aad, plaintext, &mut ct, &mut tag).unwrap();

        // Flip a bit in the tag
        tag[0] ^= 0x01;
        let mut pt = vec![0u8; ct.len()];
        assert!(aes_eax_decrypt(&key, &nonce, &aad, &ct, &mut pt, &tag).is_err());
    }
}
