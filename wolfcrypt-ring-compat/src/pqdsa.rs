//! ML-DSA (Dilithium) post-quantum digital signature support.
//!
//! This module implements ML-DSA-44, ML-DSA-65, and ML-DSA-87 using
//! wolfCrypt's native Dilithium API (not the OpenSSL compat layer).

pub(crate) mod key_pair;
pub(crate) mod signature;

use crate::error::Unspecified;
use crate::wolfcrypt_rs::{
    wc_dilithium_free, wc_dilithium_import_public, wc_dilithium_init, wc_dilithium_key,
    wc_dilithium_set_level, wc_dilithium_verify_ctx_msg, DILITHIUM_ML_DSA_44_KEY_SIZE,
    DILITHIUM_ML_DSA_44_PUB_KEY_SIZE, DILITHIUM_ML_DSA_44_SIG_SIZE, DILITHIUM_ML_DSA_65_KEY_SIZE,
    DILITHIUM_ML_DSA_65_PUB_KEY_SIZE, DILITHIUM_ML_DSA_65_SIG_SIZE, DILITHIUM_ML_DSA_87_KEY_SIZE,
    DILITHIUM_ML_DSA_87_PUB_KEY_SIZE, DILITHIUM_ML_DSA_87_SIG_SIZE, DILITHIUM_SEED_SIZE,
    WC_ML_DSA_44, WC_ML_DSA_65, WC_ML_DSA_87,
};

/// Identifies which ML-DSA parameter set is in use.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum AlgorithmID {
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
}

impl AlgorithmID {
    /// The wolfCrypt security level parameter for `wc_dilithium_set_level`.
    pub(crate) const fn level(&self) -> u8 {
        match self {
            Self::ML_DSA_44 => WC_ML_DSA_44,
            Self::ML_DSA_65 => WC_ML_DSA_65,
            Self::ML_DSA_87 => WC_ML_DSA_87,
        }
    }

    /// The private key size (expanded secret key without public key).
    pub(crate) const fn priv_key_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => DILITHIUM_ML_DSA_44_KEY_SIZE,
            Self::ML_DSA_65 => DILITHIUM_ML_DSA_65_KEY_SIZE,
            Self::ML_DSA_87 => DILITHIUM_ML_DSA_87_KEY_SIZE,
        }
    }

    /// Combined key size: private key + public key concatenated.
    /// This is the format used by `from_raw_private_key` and `as_raw_bytes`.
    #[expect(dead_code)]
    pub(crate) const fn combined_key_size_bytes(&self) -> usize {
        self.priv_key_size_bytes() + self.pub_key_size_bytes()
    }

    pub(crate) const fn pub_key_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => DILITHIUM_ML_DSA_44_PUB_KEY_SIZE,
            Self::ML_DSA_65 => DILITHIUM_ML_DSA_65_PUB_KEY_SIZE,
            Self::ML_DSA_87 => DILITHIUM_ML_DSA_87_PUB_KEY_SIZE,
        }
    }

    pub(crate) const fn seed_size_bytes(&self) -> usize {
        DILITHIUM_SEED_SIZE
    }

    pub(crate) const fn signature_size_bytes(&self) -> usize {
        match self {
            Self::ML_DSA_44 => DILITHIUM_ML_DSA_44_SIG_SIZE,
            Self::ML_DSA_65 => DILITHIUM_ML_DSA_65_SIG_SIZE,
            Self::ML_DSA_87 => DILITHIUM_ML_DSA_87_SIG_SIZE,
        }
    }
}

/// Verify a signature using the native wolfCrypt Dilithium API.
///
/// This is the core verification routine used by both `verify_sig` (raw bytes)
/// and `parsed_verify_sig` (from `ParsedPublicKey`).
pub(crate) fn verify_pqdsa_sig_native(
    public_key: &[u8],
    id: &'static AlgorithmID,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    // Validate sizes
    if public_key.len() != id.pub_key_size_bytes() {
        return Err(Unspecified);
    }
    if signature.len() != id.signature_size_bytes() {
        return Err(Unspecified);
    }

    // SAFETY: zeroed struct is valid initial state; wolfCrypt key freed after use.
    unsafe {
        let mut key = wc_dilithium_key::zeroed();
        let rc = wc_dilithium_init(&mut key);
        if rc != 0 {
            return Err(Unspecified);
        }

        let rc = wc_dilithium_set_level(&mut key, id.level());
        if rc != 0 {
            wc_dilithium_free(&mut key);
            return Err(Unspecified);
        }

        let rc = wc_dilithium_import_public(public_key.as_ptr(), public_key.len() as u32, &mut key);
        if rc != 0 {
            wc_dilithium_free(&mut key);
            return Err(Unspecified);
        }

        let mut res: core::ffi::c_int = 0;
        // Use FIPS 204 context-aware verification with empty context.
        // ML-DSA.Verify uses M' = 0x00 || 0x00 || msg (empty context).
        let rc = wc_dilithium_verify_ctx_msg(
            signature.as_ptr(),
            signature.len() as u32,
            core::ptr::null(), // empty context
            0,                 // context length = 0
            msg.as_ptr(),
            msg.len() as u32,
            &mut res,
            &mut key,
        );
        wc_dilithium_free(&mut key);

        if rc != 0 || res != 1 {
            return Err(Unspecified);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_id_sizes() {
        // Sanity check that sizes match the header constants
        assert_eq!(AlgorithmID::ML_DSA_44.pub_key_size_bytes(), 1312);
        assert_eq!(AlgorithmID::ML_DSA_44.priv_key_size_bytes(), 2560);
        assert_eq!(AlgorithmID::ML_DSA_44.signature_size_bytes(), 2420);

        assert_eq!(AlgorithmID::ML_DSA_65.pub_key_size_bytes(), 1952);
        assert_eq!(AlgorithmID::ML_DSA_65.priv_key_size_bytes(), 4032);
        assert_eq!(AlgorithmID::ML_DSA_65.signature_size_bytes(), 3309);

        assert_eq!(AlgorithmID::ML_DSA_87.pub_key_size_bytes(), 2592);
        assert_eq!(AlgorithmID::ML_DSA_87.priv_key_size_bytes(), 4896);
        assert_eq!(AlgorithmID::ML_DSA_87.signature_size_bytes(), 4627);
    }
}
