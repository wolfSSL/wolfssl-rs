//! Smoke tests for the wolfcrypt-dpe `Crypto` implementation.
//!
//! Verifies that `WolfCryptDpe` satisfies the `Crypto` trait bound
//! and that core cryptographic operations succeed or fail as expected.

use caliptra_dpe_crypto::{Crypto, Digest, Sha384, SignData};
use wolfcrypt_dpe::WolfCryptDpe;

#[test]
fn implements_crypto_trait() {
    fn assert_impl<T: Crypto>() {}
    assert_impl::<WolfCryptDpe>();
}

#[test]
fn basic_operations_work() {
    let mut dpe = WolfCryptDpe::new_p384();

    // RNG: filling a buffer with random bytes should succeed
    assert!(dpe.rand_bytes(&mut [0u8; 32]).is_ok());

    // SHA-384: one-shot hash and streaming initialisation should succeed
    assert!(dpe.hash(b"test").is_ok());
    assert!(dpe.hash_initialize().is_ok());

    // CDI derivation from a measurement and info string should succeed
    let measurement = Digest::Sha384(Sha384([0u8; 48]));
    assert!(dpe.derive_cdi(&measurement, b"info").is_ok());

    // ECDSA P-384 key-pair derivation from a CDI should succeed
    let cdi = dpe.derive_cdi(&measurement, b"info").unwrap();
    assert!(dpe.derive_key_pair(&cdi, b"label", b"info").is_ok());

    // Exported key-pair derivation is unsupported and should return an error
    let dummy_handle = [0u8; 32];
    assert!(dpe
        .derive_key_pair_exported(&dummy_handle, b"label", b"info")
        .is_err());

    // Signing without a configured alias key should return an error
    let sign_data = SignData::Digest(Digest::Sha384(Sha384([0u8; 48])));
    assert!(dpe.sign_with_alias(&sign_data).is_err());
}
