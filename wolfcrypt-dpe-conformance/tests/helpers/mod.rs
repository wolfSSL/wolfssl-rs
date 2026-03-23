//! Common test helpers shared across all conformance test modules.

pub mod dpe_harness;
pub mod x509_parser;

use caliptra_dpe_crypto::{
    Crypto, CryptoSuite, Digest, PubKey, Sha256, Sha384, Signature,
    ecdsa::{EcdsaPubKey, EcdsaSignature},
};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/// Create a fresh WolfCryptDpe384 instance.
pub fn new_wolf_384() -> wolfcrypt_dpe::WolfCryptDpe384 {
    wolfcrypt_dpe::WolfCryptDpe384::new()
}

/// Create a fresh WolfCryptDpe256 instance.
pub fn new_wolf_256() -> wolfcrypt_dpe::WolfCryptDpe256 {
    wolfcrypt_dpe::WolfCryptDpe256::new()
}

/// Create a fresh reference RustCrypto P-384 instance.
pub fn new_ref_384() -> caliptra_dpe_crypto::Ecdsa384RustCrypto {
    caliptra_dpe_crypto::Ecdsa384RustCrypto::new()
}

/// Create a fresh reference RustCrypto P-256 instance.
pub fn new_ref_256() -> caliptra_dpe_crypto::Ecdsa256RustCrypto {
    caliptra_dpe_crypto::Ecdsa256RustCrypto::new()
}

// ---------------------------------------------------------------------------
// Random input generators
// ---------------------------------------------------------------------------

/// Generate a random Digest::Sha384 measurement.
pub fn random_measurement_384(rng: &mut impl RngCore) -> Digest {
    let mut bytes = [0u8; 48];
    rng.fill_bytes(&mut bytes);
    Digest::Sha384(Sha384(bytes))
}

/// Generate a random Digest::Sha256 measurement.
pub fn random_measurement_256(rng: &mut impl RngCore) -> Digest {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Digest::Sha256(Sha256(bytes))
}

/// Generate random bytes of given length.
pub fn random_info(rng: &mut impl RngCore, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

// ---------------------------------------------------------------------------
// Key/signature format conversion helpers
// ---------------------------------------------------------------------------

/// Convert a `PubKey::Ecdsa` to SEC1 uncompressed format: `04 || x || y`.
pub fn pubkey_to_uncompressed(pub_key: &PubKey) -> Vec<u8> {
    match pub_key {
        PubKey::Ecdsa(ecdsa_pub) => {
            let (x, y) = ecdsa_pub.as_slice();
            let mut bytes = Vec::with_capacity(1 + x.len() + y.len());
            bytes.push(0x04);
            bytes.extend_from_slice(x);
            bytes.extend_from_slice(y);
            bytes
        }
        #[allow(unreachable_patterns)]
        _ => panic!("Expected ECDSA public key"),
    }
}

/// Convert a `Signature::Ecdsa` to fixed-size `r || s` bytes.
pub fn sig_to_fixed(sig: &Signature) -> Vec<u8> {
    match sig {
        Signature::Ecdsa(ecdsa_sig) => {
            let (r, s) = ecdsa_sig.as_slice();
            let mut bytes = Vec::with_capacity(r.len() + s.len());
            bytes.extend_from_slice(r);
            bytes.extend_from_slice(s);
            bytes
        }
        #[allow(unreachable_patterns)]
        _ => panic!("Expected ECDSA signature"),
    }
}

/// Extract (x, y) coordinate byte slices from a PubKey.
pub fn pubkey_xy(pub_key: &PubKey) -> (&[u8], &[u8]) {
    match pub_key {
        PubKey::Ecdsa(ecdsa_pub) => ecdsa_pub.as_slice(),
        #[allow(unreachable_patterns)]
        _ => panic!("Expected ECDSA public key"),
    }
}

// ---------------------------------------------------------------------------
// Independent ECDSA verification (using p384/p256 crates directly)
// ---------------------------------------------------------------------------

/// Verify an ECDSA-P384-SHA384 signature independently.
pub fn verify_p384_signature(
    pubkey_uncompressed: &[u8],
    message_digest: &[u8],
    sig_r_s: &[u8],
) -> Result<(), String> {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(pubkey_uncompressed)
        .map_err(|e| format!("P384 VerifyingKey: {e}"))?;
    let sig = Signature::from_slice(sig_r_s)
        .map_err(|e| format!("P384 Signature: {e}"))?;
    vk.verify_prehash(message_digest, &sig)
        .map_err(|e| format!("P384 verify: {e}"))
}

/// Verify an ECDSA-P256-SHA256 signature independently.
pub fn verify_p256_signature(
    pubkey_uncompressed: &[u8],
    message_digest: &[u8],
    sig_r_s: &[u8],
) -> Result<(), String> {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(pubkey_uncompressed)
        .map_err(|e| format!("P256 VerifyingKey: {e}"))?;
    let sig = Signature::from_slice(sig_r_s)
        .map_err(|e| format!("P256 Signature: {e}"))?;
    vk.verify_prehash(message_digest, &sig)
        .map_err(|e| format!("P256 verify: {e}"))
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

/// Create a fixed Sha384 digest from a byte pattern.
pub fn fixed_measurement_384(pattern: u8) -> Digest {
    Digest::Sha384(Sha384([pattern; 48]))
}

/// Create a fixed Sha256 digest from a byte pattern.
pub fn fixed_measurement_256(pattern: u8) -> Digest {
    Digest::Sha256(Sha256([pattern; 32]))
}

/// Extract raw bytes from a Digest.
pub fn digest_bytes(d: &Digest) -> &[u8] {
    d.as_slice()
}
