//! TLS PRF conformance tests.
//!
//! Tests the wolfcrypt::kdf::tls_prf and tls12_prf functions.
//! These are gated on `wolfssl_prf` (WOLFSSL_HAVE_PRF in user_settings.h).

#[cfg(wolfssl_prf)]
mod tls_prf_tests {
    use wolfcrypt::kdf::{tls12_prf, tls_prf, SHA256_MAC, SHA384_MAC};

    // Basic smoke test: tls_prf produces non-zero output
    #[test]
    fn tls_prf_sha256_produces_output() {
        let secret = [0x42u8; 48];
        let seed = [0x01u8; 64];
        let mut out = [0u8; 48];

        tls_prf(&secret, &seed, SHA256_MAC, &mut out).unwrap();
        assert!(
            out.iter().any(|&b| b != 0),
            "PRF output must not be all zeros"
        );
    }

    // Same inputs always produce same output (determinism)
    #[test]
    fn tls_prf_sha256_deterministic() {
        let secret = [0xAB; 32];
        let seed = [0xCD; 32];

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];

        tls_prf(&secret, &seed, SHA256_MAC, &mut out1).unwrap();
        tls_prf(&secret, &seed, SHA256_MAC, &mut out2).unwrap();

        assert_eq!(out1, out2, "PRF must be deterministic");
    }

    // Different secrets produce different output
    #[test]
    fn tls_prf_different_secrets() {
        let seed = [0x01u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        tls_prf(&[0x01; 32], &seed, SHA256_MAC, &mut out1).unwrap();
        tls_prf(&[0x02; 32], &seed, SHA256_MAC, &mut out2).unwrap();

        assert_ne!(
            out1, out2,
            "different secrets must produce different output"
        );
    }

    // Different seeds produce different output
    #[test]
    fn tls_prf_different_seeds() {
        let secret = [0x42u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        tls_prf(&secret, &[0x01; 32], SHA256_MAC, &mut out1).unwrap();
        tls_prf(&secret, &[0x02; 32], SHA256_MAC, &mut out2).unwrap();

        assert_ne!(out1, out2, "different seeds must produce different output");
    }

    // SHA-384 variant works
    #[test]
    fn tls_prf_sha384_produces_output() {
        let secret = [0x42u8; 48];
        let seed = [0x01u8; 64];
        let mut out = [0u8; 48];

        tls_prf(&secret, &seed, SHA384_MAC, &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }

    // SHA-256 and SHA-384 produce different output for the same input
    #[test]
    fn tls_prf_sha256_vs_sha384_differ() {
        let secret = [0x42u8; 48];
        let seed = [0x01u8; 64];
        let mut out256 = [0u8; 48];
        let mut out384 = [0u8; 48];

        tls_prf(&secret, &seed, SHA256_MAC, &mut out256).unwrap();
        tls_prf(&secret, &seed, SHA384_MAC, &mut out384).unwrap();

        assert_ne!(out256, out384, "SHA-256 and SHA-384 PRFs must differ");
    }

    // tls12_prf with label
    #[test]
    fn tls12_prf_with_label() {
        let secret = [0x42u8; 48];
        let label = b"master secret";
        let seed = [0x01u8; 64];
        let mut out = [0u8; 48];

        tls12_prf(
            &secret,
            label,
            &seed,
            wolfcrypt_rs::WC_HASH_TYPE_SHA256 as i32,
            &mut out,
        )
        .unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }

    // tls12_prf: different labels produce different output
    #[test]
    fn tls12_prf_different_labels() {
        let secret = [0x42u8; 48];
        let seed = [0x01u8; 64];
        let hash_type = wolfcrypt_rs::WC_HASH_TYPE_SHA256 as i32;

        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];

        tls12_prf(&secret, b"key expansion", &seed, hash_type, &mut out1).unwrap();
        tls12_prf(&secret, b"master secret", &seed, hash_type, &mut out2).unwrap();

        assert_ne!(out1, out2, "different labels must produce different output");
    }

    // Variable output length
    #[test]
    fn tls_prf_variable_output_length() {
        let secret = [0x42u8; 32];
        let seed = [0x01u8; 32];

        let mut short = [0u8; 16];
        let mut long = [0u8; 128];

        tls_prf(&secret, &seed, SHA256_MAC, &mut short).unwrap();
        tls_prf(&secret, &seed, SHA256_MAC, &mut long).unwrap();

        // The first 16 bytes of the long output must equal the short output
        assert_eq!(&short[..], &long[..16], "PRF must be prefix-consistent");
    }
}
