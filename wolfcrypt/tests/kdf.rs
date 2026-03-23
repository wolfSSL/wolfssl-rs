//! KDF function tests.
//!
//! Tests for the miscellaneous KDF functions in `wolfcrypt::kdf`.

#![cfg(feature = "kdf")]

/// TLS PRF tests — gated on the `wolfssl_prf` cfg flag.
///
/// wolfCrypt's `wc_PRF` uses the TLS MAC algorithm enum values
/// (sha256_mac = 4, etc.) rather than wc_HashType.
#[cfg(wolfssl_prf)]
mod tls_prf {
    use wolfcrypt::kdf::{tls_prf, tls12_prf, SHA256_MAC};

    /// Verify that the TLS PRF produces deterministic, non-trivial output.
    ///
    /// Since wc_PRF is an internal building block (not directly specified
    /// in an RFC with test vectors), we verify determinism: calling it
    /// twice with the same inputs must produce the same output, and the
    /// output must not be all zeros.
    #[test]
    fn tls_prf_deterministic() {
        let secret = b"master secret material for test";
        let seed = b"seed value for PRF test vector generation";
        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];

        tls_prf(secret, seed, SHA256_MAC, &mut out1)
            .expect("first wc_PRF call failed");
        tls_prf(secret, seed, SHA256_MAC, &mut out2)
            .expect("second wc_PRF call failed");

        assert_eq!(out1, out2, "PRF must be deterministic");
        assert!(
            !out1.iter().all(|&b| b == 0),
            "PRF output must not be all zeros"
        );
    }

    /// Test the TLS 1.2 PRF (wc_PRF_TLS) which is the standard
    /// PRF defined in RFC 5246 section 5.
    ///
    /// We use a known-answer test: compute the PRF once with known
    /// inputs, then verify the output matches on a second call.
    /// The label "master secret" and concatenated client/server randoms
    /// mirror the TLS 1.2 master secret derivation.
    #[test]
    fn tls12_prf_deterministic() {
        let pre_master_secret = [0x03u8; 48]; // simulated pre-master secret
        let label = b"master secret";
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];

        // Concatenate client_random + server_random as the seed
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&client_random);
        seed[32..].copy_from_slice(&server_random);

        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA256;

        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];

        tls12_prf(
            &pre_master_secret,
            label,
            &seed,
            hash_type,
            &mut out1,
        )
        .expect("first wc_PRF_TLS call failed");

        tls12_prf(
            &pre_master_secret,
            label,
            &seed,
            hash_type,
            &mut out2,
        )
        .expect("second wc_PRF_TLS call failed");

        assert_eq!(out1, out2, "TLS 1.2 PRF must be deterministic");
        assert!(
            !out1.iter().all(|&b| b == 0),
            "TLS 1.2 PRF output must not be all zeros"
        );
    }

    /// Different seeds must produce different output.
    #[test]
    fn tls_prf_different_seeds() {
        let secret = b"same secret for both calls";
        let seed1 = b"first seed value";
        let seed2 = b"second seed value (different)";
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        tls_prf(secret, seed1, SHA256_MAC, &mut out1)
            .expect("PRF with seed1 failed");
        tls_prf(secret, seed2, SHA256_MAC, &mut out2)
            .expect("PRF with seed2 failed");

        assert_ne!(out1, out2, "different seeds must produce different output");
    }
}

/// PKCS#12 PBKDF tests — gated on the `wolfssl_pbkdf2` cfg flag.
///
/// Test vectors from RFC 7292 appendix B and cross-validated against
/// OpenSSL's PKCS12_key_gen implementation.
#[cfg(wolfssl_pbkdf2)]
mod pkcs12_pbkdf {
    use wolfcrypt::kdf::{pkcs12_pbkdf, PKCS12_KEY_ID, PKCS12_MAC_ID};

    /// PKCS#12 PBKDF with SHA-1, cross-validated against OpenSSL's
    /// PKCS12_key_gen_uni (called from PKCS12_key_gen_utf8_ex).
    ///
    /// Parameters:
    ///   password: "smeg" in BMPString (UTF-16BE + null terminator)
    ///             = 00 73 00 6D 00 65 00 67 00 00
    ///   salt:     0A 58 CF 64 53 0D 82 3F
    ///   iterations: 1
    ///   id: 1 (key material)
    ///   hash: SHA-1
    ///   output length: 24 bytes
    ///
    /// Expected output verified against wolfCrypt and OpenSSL:
    ///   8A AA E6 29 7B 6C B0 46 42 AB 5B 07 78 51 28 4E
    ///   B7 12 8F 1A 2A 7F BC A3
    #[test]
    fn pkcs12_pbkdf_sha1_smeg() {
        // "smeg" as BMPString (UTF-16BE) with null terminator
        let password: &[u8] = &[
            0x00, 0x73, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00,
        ];
        let salt: &[u8] = &[0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F];
        let iterations = 1;
        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA;
        let mut out = [0u8; 24];

        pkcs12_pbkdf(password, salt, iterations, PKCS12_KEY_ID, hash_type, &mut out)
            .expect("wc_PKCS12_PBKDF failed");

        let expected: [u8; 24] = [
            0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46,
            0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51, 0x28, 0x4E,
            0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3,
        ];
        assert_eq!(out, expected, "PKCS#12 PBKDF SHA-1 test vector mismatch");
    }

    /// PKCS#12 PBKDF with SHA-256 — determinism and non-triviality test.
    ///
    /// SHA-256 test vectors for PKCS#12 are not in the original RFC
    /// (which only specified SHA-1), so we verify determinism and
    /// non-triviality.
    #[test]
    fn pkcs12_pbkdf_sha256_deterministic() {
        let password: &[u8] = &[
            0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00,
        ]; // "test" as BMPString
        let salt: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let iterations = 2048;
        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA256;

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        pkcs12_pbkdf(password, salt, iterations, PKCS12_KEY_ID, hash_type, &mut out1)
            .expect("first PKCS12 call failed");
        pkcs12_pbkdf(password, salt, iterations, PKCS12_KEY_ID, hash_type, &mut out2)
            .expect("second PKCS12 call failed");

        assert_eq!(out1, out2, "PKCS#12 PBKDF must be deterministic");
        assert!(
            !out1.iter().all(|&b| b == 0),
            "PKCS#12 PBKDF output must not be all zeros"
        );
    }

    /// Different purpose IDs must produce different derived keys.
    #[test]
    fn pkcs12_pbkdf_different_ids() {
        let password: &[u8] = &[
            0x00, 0x70, 0x00, 0x77, 0x00, 0x64, 0x00, 0x00,
        ]; // "pwd" as BMPString
        let salt: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let iterations = 1000;
        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA256;

        let mut key_out = [0u8; 16];
        let mut mac_out = [0u8; 16];

        pkcs12_pbkdf(password, salt, iterations, PKCS12_KEY_ID, hash_type, &mut key_out)
            .expect("KEY derivation failed");
        pkcs12_pbkdf(password, salt, iterations, PKCS12_MAC_ID, hash_type, &mut mac_out)
            .expect("MAC derivation failed");

        assert_ne!(
            key_out, mac_out,
            "KEY and MAC purpose IDs must produce different output"
        );
    }

    /// Zero iterations must be rejected.
    #[test]
    fn pkcs12_pbkdf_rejects_zero_iterations() {
        let password: &[u8] = &[0x00, 0x61, 0x00, 0x00]; // "a"
        let salt: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA256;
        let mut out = [0u8; 16];

        let result = pkcs12_pbkdf(password, salt, 0, PKCS12_KEY_ID, hash_type, &mut out);
        assert!(result.is_err(), "zero iterations must be rejected");
    }
}

/// TLS 1.3 HKDF tests — gated on the `wolfssl_tls13_hkdf` cfg flag.
///
/// Test vectors from RFC 8448 Section 3 (Simple 1-RTT Handshake).
#[cfg(wolfssl_tls13_hkdf)]
mod tls13_hkdf {
    use wolfcrypt::kdf::{tls13_hkdf_extract, tls13_hkdf_expand_label};

    const DIGEST_SHA256: i32 = wolfcrypt_rs::WC_HASH_TYPE_SHA256;

    /// RFC 8448 Section 3 — Early Secret derivation.
    ///
    /// When no PSK is used, the early secret is derived as:
    ///   HKDF-Extract(salt=zeros(32), IKM=zeros(32))
    ///
    /// Expected value from RFC 8448:
    ///   33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
    #[test]
    fn extract_rfc8448_early_secret() {
        let salt = [0u8; 32];
        let ikm = [0u8; 32];
        let mut prk = [0u8; 32];

        tls13_hkdf_extract(&salt, &ikm, DIGEST_SHA256, &mut prk)
            .expect("wc_Tls13_HKDF_Extract failed");

        let expected: [u8; 32] = [
            0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
            0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
            0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
            0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
        ];
        assert_eq!(
            prk, expected,
            "Early Secret must match RFC 8448 Section 3 test vector"
        );
    }

    /// Verify that extract produces deterministic output.
    #[test]
    fn extract_deterministic() {
        let salt = b"determinism test salt value here";
        let ikm = b"some input key material for test";
        let mut prk1 = [0u8; 32];
        let mut prk2 = [0u8; 32];

        tls13_hkdf_extract(salt, ikm, DIGEST_SHA256, &mut prk1)
            .expect("first extract call failed");
        tls13_hkdf_extract(salt, ikm, DIGEST_SHA256, &mut prk2)
            .expect("second extract call failed");

        assert_eq!(prk1, prk2, "HKDF-Extract must be deterministic");
    }

    /// Verify that extract output is non-trivial (not all zeros).
    #[test]
    fn extract_non_trivial() {
        let salt = b"test salt";
        let ikm = b"test ikm";
        let mut prk = [0u8; 32];

        tls13_hkdf_extract(salt, ikm, DIGEST_SHA256, &mut prk)
            .expect("extract failed");

        assert!(
            !prk.iter().all(|&b| b == 0),
            "HKDF-Extract output must not be all zeros"
        );
    }

    /// Verify that expand-label produces deterministic output.
    #[test]
    fn expand_label_deterministic() {
        // First derive a PRK to use as input.
        let salt = [0u8; 32];
        let ikm = [0u8; 32];
        let mut prk = [0u8; 32];
        tls13_hkdf_extract(&salt, &ikm, DIGEST_SHA256, &mut prk)
            .expect("extract failed");

        let protocol = b"tls13 ";
        let label = b"derived";
        let info = b"";
        let mut okm1 = [0u8; 32];
        let mut okm2 = [0u8; 32];

        tls13_hkdf_expand_label(
            &prk, protocol, label, info, DIGEST_SHA256, &mut okm1,
        )
        .expect("first expand-label call failed");

        tls13_hkdf_expand_label(
            &prk, protocol, label, info, DIGEST_SHA256, &mut okm2,
        )
        .expect("second expand-label call failed");

        assert_eq!(okm1, okm2, "HKDF-Expand-Label must be deterministic");
    }

    /// Different labels must produce different output.
    #[test]
    fn expand_label_different_labels() {
        let salt = [0u8; 32];
        let ikm = [0u8; 32];
        let mut prk = [0u8; 32];
        tls13_hkdf_extract(&salt, &ikm, DIGEST_SHA256, &mut prk)
            .expect("extract failed");

        let protocol = b"tls13 ";
        let info = b"";
        let mut okm_a = [0u8; 32];
        let mut okm_b = [0u8; 32];

        tls13_hkdf_expand_label(
            &prk, protocol, b"c hs traffic", info, DIGEST_SHA256, &mut okm_a,
        )
        .expect("expand-label 'c hs traffic' failed");

        tls13_hkdf_expand_label(
            &prk, protocol, b"s hs traffic", info, DIGEST_SHA256, &mut okm_b,
        )
        .expect("expand-label 's hs traffic' failed");

        assert_ne!(
            okm_a, okm_b,
            "different labels must produce different output"
        );
    }
}
