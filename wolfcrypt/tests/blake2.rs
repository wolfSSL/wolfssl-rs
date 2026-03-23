//! Tests for Blake2b and Blake2s hash functions.
//!
//! Test vectors sourced from:
//! - RFC 7693 Appendix A (unkeyed Blake2b-512 and Blake2s-256)
//! - Official BLAKE2 KAT vectors (keyed Blake2b, from blake2b-kat.txt
//!   in the BLAKE2 reference implementation by Aumasson, Neves, Wilcox-O'Hearn, Winnerlein)

// Blake2b tests — only compiled when both the feature and the wolfSSL cfg are set.
#[cfg(all(feature = "blake2", wolfssl_blake2b))]
mod blake2b_tests {
    use hex_literal::hex;
    use wolfcrypt::blake2::Blake2b;

    /// RFC 7693 Appendix A: BLAKE2b-512("abc") unkeyed.
    #[test]
    fn blake2b_512_abc_rfc7693() {
        let mut h = Blake2b::new(64).unwrap();
        h.update(b"abc").unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            ),
        );
    }

    /// Blake2b-512 with empty input.
    /// Vector from the BLAKE2 reference KAT (blake2b-kat.txt, entry 0, unkeyed).
    /// This is the "hash of nothing" at full 64-byte output.
    #[test]
    fn blake2b_512_empty() {
        let h = Blake2b::new(64).unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            ),
        );
    }

    /// Incremental update: split "abc" across two update() calls and verify
    /// the result matches a single-call update.
    #[test]
    fn blake2b_incremental_update() {
        // Single call
        let mut h1 = Blake2b::new(64).unwrap();
        h1.update(b"abc").unwrap();
        let d1 = h1.finalize().unwrap();

        // Split across two calls
        let mut h2 = Blake2b::new(64).unwrap();
        h2.update(b"a").unwrap();
        h2.update(b"bc").unwrap();
        let d2 = h2.finalize().unwrap();

        assert_eq!(d1, d2);

        // Verify against RFC 7693 vector too
        assert_eq!(
            d1.as_slice(),
            &hex!(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            ),
        );
    }

    /// Keyed BLAKE2b: key = 000102…3f (64 bytes), input = empty, 64-byte output.
    /// Vector from the official BLAKE2 reference implementation KAT file
    /// (blake2b-kat.txt, first entry: in="" key=000102…3f).
    #[test]
    fn blake2b_keyed_empty_input() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let h = Blake2b::new_keyed(&key, 64).unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!(
                "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
                "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"
            ),
        );
    }

    /// Invalid digest size (0) returns an error.
    #[test]
    fn blake2b_invalid_digest_size_zero() {
        assert!(Blake2b::new(0).is_err());
    }

    /// Invalid digest size (65) returns an error.
    #[test]
    fn blake2b_invalid_digest_size_too_large() {
        assert!(Blake2b::new(65).is_err());
    }
}

// Blake2s tests — only compiled when both the feature and the wolfSSL cfg are set.
#[cfg(all(feature = "blake2", wolfssl_blake2s))]
mod blake2s_tests {
    use hex_literal::hex;
    use wolfcrypt::blake2::Blake2s;

    /// RFC 7693 Appendix A: BLAKE2s-256("abc") unkeyed.
    #[test]
    fn blake2s_256_abc_rfc7693() {
        let mut h = Blake2s::new(32).unwrap();
        h.update(b"abc").unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
        );
    }

    /// Blake2s-256 with empty input.
    /// Vector from the BLAKE2 reference KAT (blake2s-kat.txt, entry 0, unkeyed).
    #[test]
    fn blake2s_256_empty() {
        let h = Blake2s::new(32).unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
        );
    }

    /// Incremental update: split "abc" across two update() calls and verify
    /// the result matches a single-call update.
    #[test]
    fn blake2s_incremental_update() {
        // Single call
        let mut h1 = Blake2s::new(32).unwrap();
        h1.update(b"abc").unwrap();
        let d1 = h1.finalize().unwrap();

        // Split across two calls
        let mut h2 = Blake2s::new(32).unwrap();
        h2.update(b"ab").unwrap();
        h2.update(b"c").unwrap();
        let d2 = h2.finalize().unwrap();

        assert_eq!(d1, d2);

        // Verify against RFC 7693 vector
        assert_eq!(
            d1.as_slice(),
            &hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
        );
    }

    /// Keyed BLAKE2s: key = 000102…1f (32 bytes), input = empty, 32-byte output.
    /// Vector from the official BLAKE2 reference implementation KAT file
    /// (blake2s-kat.txt, first entry: in="" key=000102…1f).
    #[test]
    fn blake2s_keyed_empty_input() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let h = Blake2s::new_keyed(&key, 32).unwrap();
        let digest = h.finalize().unwrap();
        assert_eq!(
            digest.as_slice(),
            &hex!("48a8997da407876b3d79c0d92325ad3b89cdb8f0b8dad7c0d6a5a7af45b46b28"),
        );
    }

    /// Invalid digest size (0) returns an error.
    #[test]
    fn blake2s_invalid_digest_size_zero() {
        assert!(Blake2s::new(0).is_err());
    }

    /// Invalid digest size (33) returns an error.
    #[test]
    fn blake2s_invalid_digest_size_too_large() {
        assert!(Blake2s::new(33).is_err());
    }
}
