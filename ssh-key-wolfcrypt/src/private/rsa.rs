//! Rivest–Shamir–Adleman (RSA) private keys.

use crate::{Error, Mpint, Result, public::RsaPublicKey};
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(feature = "rsa")]
use rand_core::CryptoRng;

/// RSA private key.
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// RSA private exponent.
    d: Mpint,

    /// CRT coefficient: `(inverse of q) mod p`.
    iqmp: Mpint,

    /// First prime factor of `n`.
    p: Mpint,

    /// Second prime factor of `n`.
    q: Mpint,
}

impl RsaPrivateKey {
    /// Create a new RSA private key with the following components:
    ///
    /// - `d`: RSA private exponent.
    /// - `iqmp`: CRT coefficient: `(inverse of q) mod p`.
    /// - `p`: First prime factor of `n`.
    /// - `q`: Second prime factor of `n`.
    pub fn new(d: Mpint, iqmp: Mpint, p: Mpint, q: Mpint) -> Result<Self> {
        if d.is_positive() && iqmp.is_positive() && p.is_positive() && q.is_positive() {
            Ok(Self { d, iqmp, p, q })
        } else {
            Err(Error::FormatEncoding)
        }
    }

    /// RSA private exponent.
    pub fn d(&self) -> &Mpint {
        &self.d
    }

    /// CRT coefficient: `(inverse of q) mod p`.
    pub fn iqmp(&self) -> &Mpint {
        &self.iqmp
    }

    /// First prime factor of `n`.
    pub fn p(&self) -> &Mpint {
        &self.p
    }

    /// Second prime factor of `n`.
    pub fn q(&self) -> &Mpint {
        &self.q
    }
}

impl ConstantTimeEq for RsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.d.ct_eq(&other.d)
            & self.iqmp.ct_eq(&other.iqmp)
            & self.p.ct_eq(&other.p)
            & self.q.ct_eq(&other.q)
    }
}

impl Eq for RsaPrivateKey {}

impl PartialEq for RsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for RsaPrivateKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let d = Mpint::decode(reader)?;
        let iqmp = Mpint::decode(reader)?;
        let p = Mpint::decode(reader)?;
        let q = Mpint::decode(reader)?;
        Self::new(d, iqmp, p, q)
    }
}

impl Encode for RsaPrivateKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.d.encoded_len()?,
            self.iqmp.encoded_len()?,
            self.p.encoded_len()?,
            self.q.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.d.encode(writer)?;
        self.iqmp.encode(writer)?;
        self.p.encode(writer)?;
        self.q.encode(writer)?;
        Ok(())
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.iqmp.zeroize();
        self.p.zeroize();
        self.q.zeroize();
    }
}

/// RSA private/public keypair.
#[derive(Clone)]
pub struct RsaKeypair {
    /// Public key.
    public: RsaPublicKey,

    /// Private key.
    private: RsaPrivateKey,
}

impl RsaKeypair {
    /// Generate a random RSA keypair of the given bit size.
    ///
    /// The caller-provided `rng` is ignored — wolfCrypt uses its own
    /// internal DRBG via [`wolfcrypt::rand::WolfRng`]. The parameter is
    /// retained for API compatibility with the upstream `ssh-key` crate.
    #[cfg(feature = "rsa")]
    pub fn random<R: CryptoRng + ?Sized>(_rng: &mut R, bit_size: usize) -> Result<Self> {
        let mut wc_rng = wolfcrypt::rand::WolfRng::new().map_err(Error::from)?;
        let bit_size = u32::try_from(bit_size).map_err(|_| Error::Crypto)?;
        let mut wc_key = wolfcrypt::rsa::NativeRsaKey::generate_native(
            bit_size, &mut wc_rng,
        ).map_err(Error::from)?;

        // Export raw (e, n, d, p, q, iqmp) — wolfCrypt handles all DER
        // parsing internally via wc_RsaExportKey + wc_RsaKeyToDer.
        let c = wc_key.export_raw_components().map_err(Error::from)?;

        let e = Mpint::from_positive_bytes(&c.e).map_err(|_| Error::Crypto)?;
        let n = Mpint::from_positive_bytes(&c.n).map_err(|_| Error::Crypto)?;
        let d = Mpint::from_positive_bytes(&c.d).map_err(|_| Error::Crypto)?;
        let p = Mpint::from_positive_bytes(&c.p).map_err(|_| Error::Crypto)?;
        let q = Mpint::from_positive_bytes(&c.q).map_err(|_| Error::Crypto)?;
        let iqmp = Mpint::from_positive_bytes(&c.iqmp).map_err(|_| Error::Crypto)?;

        let public = RsaPublicKey::new(e, n)?;
        let private = RsaPrivateKey::new(d, iqmp, p, q)?;
        RsaKeypair::new(public, private)
    }

    /// Create a new keypair from the given `public` and `private` key components.
    ///
    /// # Precondition
    ///
    /// The caller must ensure the components are mathematically consistent
    /// (i.e. `p * q == n` and `d` is the correct private exponent for `e`).
    /// This constructor does **not** validate that the private key matches
    /// the public key — passing mismatched components will produce a keypair
    /// that silently fails at signing or decryption time.
    pub fn new(public: RsaPublicKey, private: RsaPrivateKey) -> Result<Self> {
        Ok(Self { public, private })
    }

    /// Get the size of the RSA modulus in bits.
    pub fn key_size(&self) -> u32 {
        self.public.key_size()
    }

    /// Get the public component of the keypair.
    pub fn public(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Get the private component of the keypair.
    pub fn private(&self) -> &RsaPrivateKey {
        &self.private
    }

}

/// Import an RSA public key into wolfCrypt from raw (n, e) byte arrays.
///
/// Delegates to [`wolfcrypt::rsa::NativeRsaKey::from_raw_public`], which
/// builds a minimal PKCS#1 DER internally and calls `wc_RsaPublicKeyDecode`.
#[cfg(feature = "rsa")]
pub(crate) fn import_rsa_public_key(n: &[u8], e: &[u8]) -> Result<wolfcrypt::rsa::NativeRsaKey> {
    wolfcrypt::rsa::NativeRsaKey::from_raw_public(n, e).map_err(Error::from)
}

impl ConstantTimeEq for RsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

impl Eq for RsaKeypair {}

impl PartialEq for RsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for RsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let n = Mpint::decode(reader)?;
        let e = Mpint::decode(reader)?;
        let public = RsaPublicKey::new(e, n)?;
        let private = RsaPrivateKey::decode(reader)?;
        Self::new(public, private)
    }
}

impl Encode for RsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.public.n().encoded_len()?,
            self.public.e().encoded_len()?,
            self.private.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.n().encode(writer)?;
        self.public.e().encode(writer)?;
        self.private.encode(writer)
    }
}

impl From<RsaKeypair> for RsaPublicKey {
    fn from(keypair: RsaKeypair) -> RsaPublicKey {
        keypair.public
    }
}

impl From<&RsaKeypair> for RsaPublicKey {
    fn from(keypair: &RsaKeypair) -> RsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for RsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

