//! RNG tests. Non-deterministic by nature — we test statistical properties only.

use caliptra_dpe_crypto::Crypto;
use wolfcrypt_dpe::WolfCryptDpe;

#[test]
fn rng_produces_nonzero_bytes() {
    let mut dpe = WolfCryptDpe::new_p384();
    let mut buf = [0u8; 32];
    dpe.rand_bytes(&mut buf).unwrap();
    // Probability of 32 all-zero bytes from a working CSPRNG is 2^{-256}
    assert_ne!(buf, [0u8; 32]);
}

#[test]
fn rng_different_calls_different_output() {
    let mut dpe = WolfCryptDpe::new_p384();
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    dpe.rand_bytes(&mut buf1).unwrap();
    dpe.rand_bytes(&mut buf2).unwrap();
    assert_ne!(buf1, buf2);
}

#[test]
fn rng_fills_entire_buffer() {
    let mut dpe = WolfCryptDpe::new_p384();
    let mut buf = [0xFFu8; 64];
    dpe.rand_bytes(&mut buf).unwrap();
    // Very unlikely all bytes remain 0xFF
    assert_ne!(buf, [0xFFu8; 64]);
}
