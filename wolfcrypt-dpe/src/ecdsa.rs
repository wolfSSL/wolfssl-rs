//! ECDSA key derivation + signing via wolfcrypt.
//!
//! Key pair construction:
//! - For derive_key_pair: HKDF-derived raw scalar bytes → from_private_key_and_public_point()
//!   which imports the scalar and computes the public key.
//! - For sign_with_derived: import both private + public key bytes.
//!
//! Compared to the ring-based implementation, this is simpler: no RFC 5915 DER
//! wrapping is needed because wolfcrypt works with raw key bytes.

use crate::prelude::*;

use caliptra_dpe_crypto::{
    ecdsa::{self, EcdsaAlgorithm, EcdsaPub, EcdsaSig},
    CryptoError, PubKey, SignData, Signature, SignatureAlgorithm,
};
use signature_trait::Signer;

use wolfcrypt::{EcdsaSignature, EcdsaSigningKey, P256, P384};

use crate::error::{
    from_wolfcrypt, ERR_INVALID_PUBKEY, ERR_INVALID_SIGNATURE, ERR_UNSUPPORTED_CURVE,
};
use crate::hkdf::hkdf_get_priv_key;

/// A cached ECDSA signing key handle, avoiding per-call key reimport.
///
/// wolfCrypt's `from_private_key_and_public_point` performs EC point
/// multiplication on every call. For `sign_with_alias` (called repeatedly
/// with the same key), caching the imported handle avoids this overhead.
pub(crate) enum CachedSigningKey {
    P256(EcdsaSigningKey<P256>),
    P384(EcdsaSigningKey<P384>),
}

impl CachedSigningKey {
    /// Import a signing key from raw bytes and cache the handle.
    pub(crate) fn new(
        alg: SignatureAlgorithm,
        priv_key: &[u8],
        pub_key: &PubKey,
    ) -> Result<Self, CryptoError> {
        let pub_bytes = pubkey_to_uncompressed(pub_key)?;
        match alg {
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let sk = EcdsaSigningKey::<P256>::from_private_key_and_public_point(
                    priv_key, &pub_bytes,
                )
                .map_err(from_wolfcrypt)?;
                Ok(Self::P256(sk))
            }
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let sk = EcdsaSigningKey::<P384>::from_private_key_and_public_point(
                    priv_key, &pub_bytes,
                )
                .map_err(from_wolfcrypt)?;
                Ok(Self::P384(sk))
            }
            #[expect(unreachable_patterns)]
            _ => Err(CryptoError::NotImplemented),
        }
    }

    /// Sign data using the cached key handle.
    pub(crate) fn sign(&self, data: &SignData) -> Result<Signature, CryptoError> {
        match self {
            Self::P256(sk) => sign_p256(sk, data),
            Self::P384(sk) => sign_p384(sk, data),
        }
    }
}

/// Curve-specific field size.
fn curve_size(alg: SignatureAlgorithm) -> Result<usize, CryptoError> {
    match alg {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Ok(32),
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Ok(48),
        #[expect(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}

/// Extract (x, y) from an uncompressed public key point (04 || x || y).
fn parse_uncompressed_pubkey(pub_bytes: &[u8], size: usize) -> Result<PubKey, CryptoError> {
    let expected_len = 1 + 2 * size;
    if pub_bytes.len() != expected_len || pub_bytes[0] != 0x04 {
        return Err(CryptoError::CryptoLibError(ERR_INVALID_PUBKEY));
    }
    let x = &pub_bytes[1..1 + size];
    let y = &pub_bytes[1 + size..1 + 2 * size];

    match size {
        32 => {
            let mut x_arr = [0u8; 32];
            let mut y_arr = [0u8; 32];
            x_arr.copy_from_slice(x);
            y_arr.copy_from_slice(y);
            Ok(PubKey::Ecdsa(ecdsa::EcdsaPubKey::Ecdsa256(
                EcdsaPub::from_slice(&x_arr, &y_arr),
            )))
        }
        48 => {
            let mut x_arr = [0u8; 48];
            let mut y_arr = [0u8; 48];
            x_arr.copy_from_slice(x);
            y_arr.copy_from_slice(y);
            Ok(PubKey::Ecdsa(ecdsa::EcdsaPubKey::Ecdsa384(
                EcdsaPub::from_slice(&x_arr, &y_arr),
            )))
        }
        _ => Err(CryptoError::CryptoLibError(ERR_UNSUPPORTED_CURVE)),
    }
}

/// Build uncompressed public key bytes (04 || x || y) from a PubKey.
fn pubkey_to_uncompressed(pub_key: &PubKey) -> Result<Vec<u8>, CryptoError> {
    match pub_key {
        PubKey::Ecdsa(ecdsa_pub) => {
            let (x, y) = ecdsa_pub.as_slice();
            let mut bytes = Vec::with_capacity(1 + x.len() + y.len());
            bytes.push(0x04);
            bytes.extend_from_slice(x);
            bytes.extend_from_slice(y);
            Ok(bytes)
        }
        #[expect(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}

/// Parse a fixed-format ECDSA signature (r || s) into a caliptra Signature.
fn parse_fixed_signature(sig_bytes: &[u8], size: usize) -> Result<Signature, CryptoError> {
    if sig_bytes.len() != 2 * size {
        return Err(CryptoError::CryptoLibError(ERR_INVALID_SIGNATURE));
    }
    let r = &sig_bytes[..size];
    let s = &sig_bytes[size..];

    match size {
        32 => {
            let mut r_arr = [0u8; 32];
            let mut s_arr = [0u8; 32];
            r_arr.copy_from_slice(r);
            s_arr.copy_from_slice(s);
            Ok(Signature::Ecdsa(ecdsa::EcdsaSignature::Ecdsa256(
                EcdsaSig::from_slice(&r_arr, &s_arr),
            )))
        }
        48 => {
            let mut r_arr = [0u8; 48];
            let mut s_arr = [0u8; 48];
            r_arr.copy_from_slice(r);
            s_arr.copy_from_slice(s);
            Ok(Signature::Ecdsa(ecdsa::EcdsaSignature::Ecdsa384(
                EcdsaSig::from_slice(&r_arr, &s_arr),
            )))
        }
        _ => Err(CryptoError::CryptoLibError(ERR_UNSUPPORTED_CURVE)),
    }
}

/// Sign with a P-256 key, handling SignData variants.
fn sign_p256(sk: &EcdsaSigningKey<P256>, data: &SignData) -> Result<Signature, CryptoError> {
    match data {
        SignData::Digest(dig) => {
            let sig = sk.sign_prehash(dig.as_slice()).map_err(from_wolfcrypt)?;
            parse_fixed_signature(sig.as_bytes(), 32)
        }
        SignData::Raw(raw) => {
            let sig: EcdsaSignature<P256> = sk.sign(raw);
            parse_fixed_signature(sig.as_bytes(), 32)
        }
        SignData::Mu(_) => Err(CryptoError::MismatchedAlgorithm),
    }
}

/// Sign with a P-384 key, handling SignData variants.
fn sign_p384(sk: &EcdsaSigningKey<P384>, data: &SignData) -> Result<Signature, CryptoError> {
    match data {
        SignData::Digest(dig) => {
            let sig = sk.sign_prehash(dig.as_slice()).map_err(from_wolfcrypt)?;
            parse_fixed_signature(sig.as_bytes(), 48)
        }
        SignData::Raw(raw) => {
            let sig: EcdsaSignature<P384> = sk.sign(raw);
            parse_fixed_signature(sig.as_bytes(), 48)
        }
        SignData::Mu(_) => Err(CryptoError::MismatchedAlgorithm),
    }
}

/// Derive a key pair from CDI + label + info, returning (private_key_bytes, PubKey).
pub(crate) fn derive_key_pair(
    alg: SignatureAlgorithm,
    cdi: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, PubKey), CryptoError> {
    let size = curve_size(alg)?;

    // Step 1: Derive private key bytes via HKDF
    let priv_bytes = hkdf_get_priv_key(alg, cdi, label, info)?;

    // Step 2: Import private key and compute public key via EC point multiplication.
    // No DER wrapping needed — wolfcrypt computes pub = priv * G.
    match alg {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
            let sk = EcdsaSigningKey::<P256>::from_private_key_bytes(&priv_bytes)
                .map_err(from_wolfcrypt)?;
            let vk = sk.verifying_key().map_err(from_wolfcrypt)?;
            let pub_bytes = vk.as_bytes();
            let pub_key = parse_uncompressed_pubkey(pub_bytes, size)?;
            Ok((priv_bytes, pub_key))
        }
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
            let sk = EcdsaSigningKey::<P384>::from_private_key_bytes(&priv_bytes)
                .map_err(from_wolfcrypt)?;
            let vk = sk.verifying_key().map_err(from_wolfcrypt)?;
            let pub_bytes = vk.as_bytes();
            let pub_key = parse_uncompressed_pubkey(pub_bytes, size)?;
            Ok((priv_bytes, pub_key))
        }
        #[expect(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}

/// Sign data using a derived private key and public key.
pub(crate) fn sign_with_key(
    alg: SignatureAlgorithm,
    data: &SignData,
    priv_key: &[u8],
    pub_key: &PubKey,
) -> Result<Signature, CryptoError> {
    let pub_bytes = pubkey_to_uncompressed(pub_key)?;

    match alg {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
            let sk =
                EcdsaSigningKey::<P256>::from_private_key_and_public_point(priv_key, &pub_bytes)
                    .map_err(from_wolfcrypt)?;
            sign_p256(&sk, data)
        }
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
            let sk =
                EcdsaSigningKey::<P384>::from_private_key_and_public_point(priv_key, &pub_bytes)
                    .map_err(from_wolfcrypt)?;
            sign_p384(&sk, data)
        }
        #[expect(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}
