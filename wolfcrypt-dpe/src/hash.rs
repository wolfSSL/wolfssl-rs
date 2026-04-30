//! SHA-256 / SHA-384 hashing via wolfcrypt digest.

use caliptra_dpe_crypto::{CryptoError, Digest, DigestAlgorithm, Hasher, Sha256, Sha384};
use digest_trait::Digest as DigestTrait;

/// Streaming hasher backed by wolfcrypt.
pub struct WolfCryptHasher {
    inner: HasherInner,
}

enum HasherInner {
    Sha256(wolfcrypt::Sha256),
    Sha384(wolfcrypt::Sha384),
}

impl WolfCryptHasher {
    pub(crate) fn new(alg: DigestAlgorithm) -> Result<Self, CryptoError> {
        let inner = match alg {
            DigestAlgorithm::Sha256 => HasherInner::Sha256(wolfcrypt::Sha256::new()),
            DigestAlgorithm::Sha384 => HasherInner::Sha384(wolfcrypt::Sha384::new()),
        };
        Ok(Self { inner })
    }
}

impl Hasher for WolfCryptHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        match &mut self.inner {
            HasherInner::Sha256(h) => DigestTrait::update(h, bytes),
            HasherInner::Sha384(h) => DigestTrait::update(h, bytes),
        }
        Ok(())
    }

    fn finish(self) -> Result<Digest, CryptoError> {
        match self.inner {
            HasherInner::Sha256(h) => {
                let result = h.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                Ok(Digest::Sha256(Sha256(arr)))
            }
            HasherInner::Sha384(h) => {
                let result = h.finalize();
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&result);
                Ok(Digest::Sha384(Sha384(arr)))
            }
        }
    }
}
