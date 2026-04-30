//! Integration tests for the wolfcrypt crypto backend.
//!
//! These tests verify that signing and verification work correctly when
//! backed by wolfcrypt rather than the original pure-Rust RustCrypto
//! implementations.
//!
//! Tests use pre-existing OpenSSH key files from `tests/examples/` rather than
//! `PrivateKey::random()` for deterministic, reproducible test vectors.
//!
//! Note: cfg gates use only Cargo feature flags (e.g. `feature = "ed25519"`)
//! rather than `wolfssl_*` build-script flags, because ssh-key-wolfcrypt does
//! not have a build.rs that propagates wolfcrypt-sys cfg metadata to test
//! binaries. The wolfcrypt dependency handles those gates internally.

use signature::{Signer, Verifier};
use ssh_key::{Algorithm, PrivateKey, Signature};

/// A fixed message used across all test cases.
const TEST_MESSAGE: &[u8] = b"wolfcrypt backend integration test message";

/// Helper: sign a message and verify with the public key data.
///
/// Uses `key_data()` for verification to avoid name collision with
/// `PublicKey::verify` (which is for the higher-level SshSig format).
fn sign_and_verify(private_key: &PrivateKey, message: &[u8]) -> Signature {
    let signature: Signature = private_key
        .try_sign(message)
        .expect("signing should succeed");

    private_key
        .public_key()
        .key_data()
        .verify(message, &signature)
        .expect("verification should succeed");

    signature
}

/// Helper: assert that a signature does NOT verify against a different message.
fn assert_wrong_message_rejected(private_key: &PrivateKey, signature: &Signature) {
    let result = private_key
        .public_key()
        .key_data()
        .verify(b"wrong message", signature);
    assert!(
        result.is_err(),
        "verification should fail with wrong message",
    );
}

// ---------------------------------------------------------------------------
// Ed25519 tests
// ---------------------------------------------------------------------------

#[cfg(feature = "ed25519")]
mod ed25519_tests {
    use super::*;

    /// Known Ed25519 private key in OpenSSH format.
    const ED25519_OPENSSH_KEY: &str = include_str!("examples/id_ed25519");

    #[test]
    fn parse_and_sign_verify() {
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");

        assert_eq!(private_key.algorithm(), Algorithm::Ed25519);
        assert_eq!(private_key.comment().as_bytes(), b"user@example.com");

        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn tampered_signature_rejected() {
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");

        let signature = sign_and_verify(&private_key, TEST_MESSAGE);

        // Flip a bit in the raw signature bytes.
        let mut bad_bytes = signature.as_bytes().to_vec();
        bad_bytes[0] ^= 0x01;
        let bad_signature =
            Signature::new(Algorithm::Ed25519, bad_bytes).expect("construct tampered signature");

        let result = private_key
            .public_key()
            .key_data()
            .verify(TEST_MESSAGE, &bad_signature);
        assert!(
            result.is_err(),
            "verification should fail with tampered Ed25519 signature",
        );
    }

    #[test]
    fn wrong_message_rejected() {
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);
        assert_wrong_message_rejected(&private_key, &signature);
    }

    #[test]
    fn deterministic_signatures() {
        // Ed25519 signatures are deterministic (RFC 8032). Two calls with the
        // same key and message must produce identical output.
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");

        let sig1: Signature = private_key.try_sign(TEST_MESSAGE).expect("sign 1");
        let sig2: Signature = private_key.try_sign(TEST_MESSAGE).expect("sign 2");
        assert_eq!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "Ed25519 signatures should be deterministic",
        );
    }

    #[test]
    fn sign_empty_message() {
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");
        sign_and_verify(&private_key, b"");
    }

    #[test]
    fn sign_large_message() {
        let private_key =
            PrivateKey::from_openssh(ED25519_OPENSSH_KEY).expect("parse Ed25519 private key");
        let large_msg = vec![0xAB_u8; 1024 * 64]; // 64 KB
        sign_and_verify(&private_key, &large_msg);
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256 tests
// ---------------------------------------------------------------------------

#[cfg(feature = "p256")]
mod ecdsa_p256_tests {
    use super::*;
    use ssh_key::EcdsaCurve;

    const ECDSA_P256_KEY: &str = include_str!("examples/id_ecdsa_p256");

    #[test]
    fn parse_and_sign_verify() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P256_KEY).expect("parse P-256 private key");

        assert_eq!(
            private_key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        );

        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn tampered_signature_rejected() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P256_KEY).expect("parse P-256 private key");

        let signature = sign_and_verify(&private_key, TEST_MESSAGE);

        // ECDSA signatures are Mpint-encoded (r || s). Flip a bit in the
        // middle of the raw data to corrupt the signature.
        let mut bad_bytes = signature.as_bytes().to_vec();
        let midpoint = bad_bytes.len() / 2;
        bad_bytes[midpoint] ^= 0x01;

        // The tampered bytes may not be valid SSH ECDSA encoding, so
        // construction might fail. Either way, verification must not succeed.
        let alg = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        };
        if let Ok(bad_signature) = Signature::new(alg, bad_bytes) {
            let result = private_key
                .public_key()
                .key_data()
                .verify(TEST_MESSAGE, &bad_signature);
            assert!(
                result.is_err(),
                "verification should fail with tampered P-256 signature",
            );
        }
        // If Signature::new rejected the tampered bytes, that is also correct.
    }

    #[test]
    fn wrong_message_rejected() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P256_KEY).expect("parse P-256 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);
        assert_wrong_message_rejected(&private_key, &signature);
    }

    #[test]
    fn sign_empty_message() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P256_KEY).expect("parse P-256 private key");
        sign_and_verify(&private_key, b"");
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-384 tests
// ---------------------------------------------------------------------------

#[cfg(feature = "p384")]
mod ecdsa_p384_tests {
    use super::*;
    use ssh_key::EcdsaCurve;

    const ECDSA_P384_KEY: &str = include_str!("examples/id_ecdsa_p384");

    #[test]
    fn parse_and_sign_verify() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P384_KEY).expect("parse P-384 private key");

        assert_eq!(
            private_key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        );

        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn wrong_message_rejected() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P384_KEY).expect("parse P-384 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);
        assert_wrong_message_rejected(&private_key, &signature);
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-521 tests
// ---------------------------------------------------------------------------

#[cfg(feature = "p521")]
mod ecdsa_p521_tests {
    use super::*;
    use ssh_key::EcdsaCurve;

    const ECDSA_P521_KEY: &str = include_str!("examples/id_ecdsa_p521");

    #[test]
    fn parse_and_sign_verify() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P521_KEY).expect("parse P-521 private key");

        assert_eq!(
            private_key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        );

        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn wrong_message_rejected() {
        let private_key =
            PrivateKey::from_openssh(ECDSA_P521_KEY).expect("parse P-521 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);
        assert_wrong_message_rejected(&private_key, &signature);
    }
}

// ---------------------------------------------------------------------------
// RSA tests
// ---------------------------------------------------------------------------

#[cfg(feature = "rsa")]
mod rsa_tests {
    use super::*;

    const RSA_3072_KEY: &str = include_str!("examples/id_rsa_3072");
    const RSA_4096_KEY: &str = include_str!("examples/id_rsa_4096");

    #[test]
    fn parse_rsa_3072_key() {
        let private_key =
            PrivateKey::from_openssh(RSA_3072_KEY).expect("parse RSA 3072 private key");
        assert!(matches!(private_key.algorithm(), Algorithm::Rsa { .. }));
    }

    #[test]
    fn parse_rsa_4096_key() {
        let private_key =
            PrivateKey::from_openssh(RSA_4096_KEY).expect("parse RSA 4096 private key");
        assert!(matches!(private_key.algorithm(), Algorithm::Rsa { .. }));
    }

    #[test]
    fn sign_and_verify_rsa_3072() {
        let private_key =
            PrivateKey::from_openssh(RSA_3072_KEY).expect("parse RSA 3072 private key");
        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn sign_and_verify_rsa_4096() {
        let private_key =
            PrivateKey::from_openssh(RSA_4096_KEY).expect("parse RSA 4096 private key");
        sign_and_verify(&private_key, TEST_MESSAGE);
    }

    #[test]
    fn tampered_signature_rejected() {
        let private_key =
            PrivateKey::from_openssh(RSA_3072_KEY).expect("parse RSA 3072 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);

        // Flip a bit in the raw signature bytes.
        let mut bad_bytes = signature.as_bytes().to_vec();
        bad_bytes[0] ^= 0x01;
        let bad_signature = Signature::new(
            Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha512),
            },
            bad_bytes,
        )
        .expect("construct tampered signature");

        let result = private_key
            .public_key()
            .key_data()
            .verify(TEST_MESSAGE, &bad_signature);
        assert!(
            result.is_err(),
            "verification should fail with tampered RSA signature",
        );
    }

    #[test]
    fn wrong_message_rejected() {
        let private_key =
            PrivateKey::from_openssh(RSA_3072_KEY).expect("parse RSA 3072 private key");
        let signature = sign_and_verify(&private_key, TEST_MESSAGE);
        assert_wrong_message_rejected(&private_key, &signature);
    }
}

// ---------------------------------------------------------------------------
// Cross-algorithm negative test
// ---------------------------------------------------------------------------

/// Verify that a signature from one key type cannot be verified with a
/// different key type's public key.
#[cfg(all(feature = "ed25519", feature = "p256"))]
#[test]
fn cross_algorithm_verification_fails() {
    let ed25519_key =
        PrivateKey::from_openssh(include_str!("examples/id_ed25519")).expect("parse Ed25519 key");
    let p256_key =
        PrivateKey::from_openssh(include_str!("examples/id_ecdsa_p256")).expect("parse P-256 key");

    // Sign with Ed25519
    let ed25519_sig: Signature = ed25519_key.try_sign(TEST_MESSAGE).expect("Ed25519 signing");

    // Attempt to verify Ed25519 signature with P-256 public key -- must fail.
    let result = p256_key
        .public_key()
        .key_data()
        .verify(TEST_MESSAGE, &ed25519_sig);
    assert!(
        result.is_err(),
        "P-256 public key should not verify an Ed25519 signature",
    );
}
