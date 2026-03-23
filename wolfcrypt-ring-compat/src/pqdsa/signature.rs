//! ML-DSA verification and signing algorithm types.
//!
//! These are the "algorithm descriptor" types used to parameterize
//! `PqdsaKeyPair`, `UnparsedPublicKey`, and `ParsedPublicKey`.

use crate::error::Unspecified;
use crate::pqdsa::{verify_pqdsa_sig_native, AlgorithmID};
use crate::signature::VerificationAlgorithm;
use crate::{digest, sealed};
use core::fmt;
use core::fmt::{Debug, Formatter};
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// An ML-DSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct PqdsaVerificationAlgorithm {
    pub(crate) id: &'static AlgorithmID,
}

impl sealed::Sealed for PqdsaVerificationAlgorithm {}

/// An ML-DSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct PqdsaSigningAlgorithm(pub(crate) &'static PqdsaVerificationAlgorithm);

impl PqdsaSigningAlgorithm {
    /// Returns the size of the signature in bytes.
    #[must_use]
    pub fn signature_len(&self) -> usize {
        self.0.id.signature_size_bytes()
    }
}

/// A PQDSA public key (cached raw bytes).
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) octets: Box<[u8]>,
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl PublicKey {
    /// Create a `PublicKey` from raw public key bytes.
    pub(crate) fn new(octets: Box<[u8]>) -> Self {
        Self { octets }
    }
}

impl VerificationAlgorithm for PqdsaVerificationAlgorithm {
    #[cfg(feature = "ring-sig-verify")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        self.verify_sig(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }

    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        verify_pqdsa_sig_native(public_key, self.id, msg, signature)
    }

    /// ML-DSA does not support digest-then-sign; always returns `Unspecified`.
    fn verify_digest_sig(
        &self,
        _public_key: &[u8],
        _digest: &digest::Digest,
        _signature: &[u8],
    ) -> Result<(), Unspecified> {
        Err(Unspecified)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "PqdsaPublicKey(\"{}\")",
            crate::hex::encode(self.octets.as_ref())
        ))
    }
}
