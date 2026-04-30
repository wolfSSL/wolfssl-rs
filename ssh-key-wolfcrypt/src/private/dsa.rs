//! Digital Signature Algorithm (DSA) private keys.

use crate::{public::DsaPublicKey, Error, Mpint, Result};
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Digital Signature Algorithm (DSA) private key.
///
/// Uniformly random integer `x`, such that `0 < x < q`, i.e. `x` is in the
/// range `[1, q–1]`.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[derive(Clone)]
pub struct DsaPrivateKey {
    /// Integer representing a DSA private key.
    inner: Mpint,
}

impl DsaPrivateKey {
    /// Create a new DSA private key given the value `x`.
    pub fn new(x: Mpint) -> Result<Self> {
        if x.is_positive() {
            Ok(Self { inner: x })
        } else {
            Err(Error::FormatEncoding)
        }
    }

    /// Get the serialized private key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the inner [`Mpint`].
    pub fn as_mpint(&self) -> &Mpint {
        &self.inner
    }
}

impl AsRef<[u8]> for DsaPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ConstantTimeEq for DsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl Eq for DsaPrivateKey {}

impl PartialEq for DsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl TryFrom<Mpint> for DsaPrivateKey {
    type Error = Error;

    fn try_from(x: Mpint) -> Result<Self> {
        Self::new(x)
    }
}

impl Decode for DsaPrivateKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        Self::new(Mpint::decode(reader)?)
    }
}

impl Encode for DsaPrivateKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        self.inner.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.inner.encode(writer)
    }
}

impl fmt::Debug for DsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaPrivateKey").finish_non_exhaustive()
    }
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Digital Signature Algorithm (DSA) private/public keypair.
#[derive(Clone)]
pub struct DsaKeypair {
    /// Public key.
    public: DsaPublicKey,

    /// Private key.
    private: DsaPrivateKey,
}

impl DsaKeypair {
    /// Create a new [`DsaKeypair`] with the given `public` and `private` components.
    pub fn new(public: DsaPublicKey, private: DsaPrivateKey) -> Result<Self> {
        // TODO(tarcieri): validate the `public` and `private` components match
        Ok(Self { public, private })
    }

    /// Get the public component of this key.
    pub fn public(&self) -> &DsaPublicKey {
        &self.public
    }

    /// Get the private component of this key.
    pub fn private(&self) -> &DsaPrivateKey {
        &self.private
    }
}

impl ConstantTimeEq for DsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

impl PartialEq for DsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for DsaKeypair {}

impl Decode for DsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let public = DsaPublicKey::decode(reader)?;
        let private = DsaPrivateKey::decode(reader)?;
        DsaKeypair::new(public, private)
    }
}

impl Encode for DsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [self.public.encoded_len()?, self.private.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.encode(writer)?;
        self.private.encode(writer)
    }
}

impl From<DsaKeypair> for DsaPublicKey {
    fn from(keypair: DsaKeypair) -> DsaPublicKey {
        keypair.public
    }
}

impl From<&DsaKeypair> for DsaPublicKey {
    fn from(keypair: &DsaKeypair) -> DsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for DsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
