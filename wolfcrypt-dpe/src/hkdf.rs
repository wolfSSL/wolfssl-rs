//! CDI derivation via wolfcrypt HKDF.
//!
//! HKDF parameter ordering matches the caliptra-dpe reference implementation:
//! - derive_cdi:   Extract(salt=info, IKM=measurement), Expand(info=measurement, L=curve_size)
//! - get_priv_key: Extract(salt=info, IKM=cdi),         Expand(info=label,       L=curve_size)

use crate::prelude::*;

use caliptra_dpe_crypto::{
    ecdsa::EcdsaAlgorithm, CryptoError, Digest, SignatureAlgorithm,
};

use crate::error::from_wolfcrypt;

/// Helper: select output size from SignatureAlgorithm.
fn hkdf_output_size(algs: SignatureAlgorithm) -> Result<usize, CryptoError> {
    match algs {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Ok(32),
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Ok(48),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}

/// Perform HKDF extract + expand.
fn hkdf_extract_expand(
    algs: SignatureAlgorithm,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    match algs {
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
            let hkdf = wolfcrypt::WolfHkdfSha256::new(Some(salt), ikm);
            let mut out = vec![0u8; output_len];
            hkdf.expand(info, &mut out).map_err(from_wolfcrypt)?;
            Ok(out)
        }
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
            let hkdf = wolfcrypt::WolfHkdfSha384::new(Some(salt), ikm);
            let mut out = vec![0u8; output_len];
            hkdf.expand(info, &mut out).map_err(from_wolfcrypt)?;
            Ok(out)
        }
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::NotImplemented),
    }
}

/// Derive a CDI from measurement and info using HKDF.
///
/// Mirrors the caliptra-dpe reference implementation:
///   HKDF-Extract(salt=info, IKM=measurement.as_slice())
///   HKDF-Expand(PRK, info=measurement.as_slice(), L=curve_size)
pub(crate) fn hkdf_derive_cdi(
    algs: SignatureAlgorithm,
    measurement: &Digest,
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let output_len = hkdf_output_size(algs)?;
    // Extract: salt=info, IKM=measurement
    // Expand: info=measurement, L=output_len
    hkdf_extract_expand(algs, info, measurement.as_slice(), measurement.as_slice(), output_len)
}

/// Derive private key bytes from CDI, label, and info using HKDF.
///
/// Mirrors the caliptra-dpe reference implementation:
///   HKDF-Extract(salt=info, IKM=cdi)
///   HKDF-Expand(PRK, info=label, L=curve_size)
pub(crate) fn hkdf_get_priv_key(
    algs: SignatureAlgorithm,
    cdi: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let output_len = hkdf_output_size(algs)?;
    // Extract: salt=info, IKM=cdi
    // Expand: info=label, L=output_len
    hkdf_extract_expand(algs, info, cdi, label, output_len)
}
