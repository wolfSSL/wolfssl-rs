//! wolfcrypt-dpe: caliptra_dpe::crypto::Crypto backed by wolfcrypt.
//!
//! This crate does NOT contain any FFI code. All cryptographic operations
//! are performed through the safe Rust API of the `wolfcrypt` crate.

#![no_std]

extern crate alloc;
pub(crate) mod prelude {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

use crate::prelude::*;

mod error;
mod hash;
mod hkdf;
mod ecdsa;
mod rng;

use core::marker::PhantomData;

use caliptra_dpe_crypto::{
    Crypto, CryptoError, CryptoSuite, Digest, DigestAlgorithm,
    DigestType, ExportedCdiHandle, PubKey, SignData, Signature, SignatureAlgorithm,
    SignatureType, MAX_EXPORTED_CDI_SIZE,
};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Re-export upstream marker types so users can name the generic parameters.
pub use caliptra_dpe_crypto::ecdsa::curve_256::Curve256;
pub use caliptra_dpe_crypto::ecdsa::curve_384::Curve384;
pub use caliptra_dpe_crypto::{Sha256, Sha384};

use crate::ecdsa::CachedSigningKey;
use crate::hash::WolfCryptHasher;

/// The private key type: raw scalar bytes, zeroized on drop.
#[derive(Debug)]
pub struct WolfCryptPrivKey(pub(crate) Vec<u8>);

impl Drop for WolfCryptPrivKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Maximum number of exported CDI handles stored simultaneously.
const MAX_CDI_HANDLES: usize = 1;

/// wolfSSL-backed implementation of the caliptra-dpe Crypto trait,
/// parameterized by signature curve and digest algorithm.
///
/// `S` determines the signature algorithm (e.g. `Curve384`, `Curve256`).
/// `D` determines the digest algorithm (e.g. `Sha384`, `Sha256`).
pub struct WolfCryptDpeImpl<S: SignatureType, D: DigestType> {
    /// Stored exported CDI slots: (cdi_bytes, handle).
    /// CDI bytes are wrapped in `Zeroizing` so they are wiped on drop.
    export_cdi_slots: Vec<(Zeroizing<Vec<u8>>, ExportedCdiHandle)>,
    /// Cached alias signing key handle, built once by `set_alias_key`.
    /// Avoids reimporting the key (EC point multiplication) on every
    /// `sign_with_alias` call.
    alias_signing_key: Option<CachedSigningKey>,
    /// Alias public key (set externally; used by sign_with_alias).
    alias_pub_key: Option<PubKey>,
    /// Cached wolfCrypt RNG, lazily initialized on first use.
    /// Avoids wc_InitRng (DRBG init + OS entropy reseed) on every call.
    rng: Option<wolfcrypt::WolfRng>,
    _marker: PhantomData<(S, D)>,
}

/// P-384 / SHA-384 variant (the default).
pub type WolfCryptDpe384 = WolfCryptDpeImpl<Curve384, Sha384>;

/// P-256 / SHA-256 variant.
pub type WolfCryptDpe256 = WolfCryptDpeImpl<Curve256, Sha256>;

/// Backward-compatible alias: defaults to P-384 / SHA-384.
pub type WolfCryptDpe = WolfCryptDpe384;

impl<S: SignatureType, D: DigestType> WolfCryptDpeImpl<S, D> {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            export_cdi_slots: Vec::new(),
            alias_signing_key: None,
            alias_pub_key: None,
            rng: None,
            _marker: PhantomData,
        }
    }

    /// Set the alias key pair used by `sign_with_alias`.
    ///
    /// Imports the key into wolfCrypt once and caches the handle so that
    /// subsequent `sign_with_alias` calls skip the EC point multiplication.
    pub fn set_alias_key(&mut self, priv_key: WolfCryptPrivKey, pub_key: PubKey) -> Result<(), CryptoError> {
        let cached = CachedSigningKey::new(S::SIGNATURE_ALGORITHM, &priv_key.0, &pub_key)?;
        self.alias_signing_key = Some(cached);
        self.alias_pub_key = Some(pub_key);
        Ok(())
    }
}

impl WolfCryptDpe384 {
    /// Create a new instance for ECDSA P-384 / SHA-384.
    pub fn new_p384() -> Self {
        Self::new()
    }
}

impl WolfCryptDpe256 {
    /// Create a new instance for ECDSA P-256 / SHA-256.
    pub fn new_p256() -> Self {
        Self::new()
    }
}

impl Default for WolfCryptDpe384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WolfCryptDpe256 {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: SignatureType, D: DigestType> SignatureType for WolfCryptDpeImpl<S, D> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm = S::SIGNATURE_ALGORITHM;
}

impl<S: SignatureType, D: DigestType> DigestType for WolfCryptDpeImpl<S, D> {
    const DIGEST_ALGORITHM: DigestAlgorithm = D::DIGEST_ALGORITHM;
}

impl<S: SignatureType, D: DigestType> CryptoSuite for WolfCryptDpeImpl<S, D> {}

/// Constant-time comparison of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

impl<S: SignatureType, D: DigestType> Crypto for WolfCryptDpeImpl<S, D> {
    type Cdi = Vec<u8>;
    type Hasher<'c> = WolfCryptHasher where Self: 'c;
    type PrivKey = WolfCryptPrivKey;

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        rng::rand_bytes(&mut self.rng, dst)
    }

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        WolfCryptHasher::new(D::DIGEST_ALGORITHM)
    }

    fn derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        hkdf::hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)
    }

    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf::hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)?;

        // Order matches caliptra-dpe reference: check duplicate before slot limit.
        for (stored_cdi, _) in self.export_cdi_slots.iter() {
            if ct_eq(stored_cdi.as_slice(), cdi.as_slice()) {
                return Err(CryptoError::ExportedCdiHandleDuplicateCdi);
            }
        }

        if self.export_cdi_slots.len() >= MAX_CDI_HANDLES {
            return Err(CryptoError::ExportedCdiHandleLimitExceeded);
        }

        let mut handle = [0u8; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut handle)?;
        self.export_cdi_slots.push((Zeroizing::new(cdi), handle));
        Ok(handle)
    }

    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
        let (priv_bytes, pub_key) =
            ecdsa::derive_key_pair(S::SIGNATURE_ALGORITHM, cdi, label, info)?;
        Ok((WolfCryptPrivKey(priv_bytes), pub_key))
    }

    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, PubKey), CryptoError> {
        let cdi = {
            let mut found = None;
            // Iterate all slots without short-circuiting to avoid timing side-channels.
            for (stored_cdi, stored_handle) in self.export_cdi_slots.iter() {
                if ct_eq(stored_handle.as_slice(), exported_handle.as_slice()) {
                    found = Some(stored_cdi.clone());
                }
            }
            found.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        let (priv_bytes, pub_key) =
            ecdsa::derive_key_pair(S::SIGNATURE_ALGORITHM, &cdi, label, info)?;
        Ok((WolfCryptPrivKey(priv_bytes), pub_key))
    }

    fn sign_with_alias(&mut self, data: &SignData) -> Result<Signature, CryptoError> {
        let cached = self
            .alias_signing_key
            .as_ref()
            .ok_or(CryptoError::CryptoLibError(error::ERR_ALIAS_NOT_SET))?;
        cached.sign(data)
    }

    fn sign_with_derived(
        &mut self,
        data: &SignData,
        priv_key: &Self::PrivKey,
        pub_key: &PubKey,
    ) -> Result<Signature, CryptoError> {
        ecdsa::sign_with_key(S::SIGNATURE_ALGORITHM, data, &priv_key.0, pub_key)
    }
}
