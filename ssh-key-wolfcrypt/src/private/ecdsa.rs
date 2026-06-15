//! Elliptic Curve Digital Signature Algorithm (ECDSA) private keys.

use crate::{public::EcdsaPublicKey, Algorithm, EcdsaCurve, Error, Result};
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use sec1::consts::{U32, U48, U66};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;

#[cfg(all(
    feature = "rand_core",
    any(feature = "p256", feature = "p384", feature = "p521")
))]
use wolfcrypt::ecc::{EccCurveId, EccKey};

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private key.
#[derive(Clone)]
pub struct EcdsaPrivateKey<const SIZE: usize> {
    /// Byte array containing serialized big endian private scalar.
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> EcdsaPrivateKey<SIZE> {
    /// Borrow the inner byte array as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Convert to the inner byte array.
    pub fn into_bytes(self) -> [u8; SIZE] {
        self.bytes
    }

    /// Does this private key need to be prefixed with a leading zero?
    fn needs_leading_zero(&self) -> bool {
        self.bytes[0] >= 0x80
    }
}

impl<const SIZE: usize> Decode for EcdsaPrivateKey<SIZE> {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let mut len = reader.remaining_len();

            // Strip leading zero if necessary:
            // `mpint` is signed and may need a leading zero for unsigned integers
            if len == SIZE.checked_add(1).ok_or(encoding::Error::Length)? {
                // TODO(tarcieri): make sure leading zero was necessary
                if u8::decode(reader)? != 0 {
                    return Err(Error::FormatEncoding);
                }

                len = SIZE;
            }

            // Minimum allowed key size: may be smaller than modulus size
            const MIN_SIZE: usize = 32;
            if len < MIN_SIZE || len > SIZE {
                return Err(encoding::Error::Length.into());
            }

            // Add leading zeros if the encoded key is smaller than `SIZE`.
            // The resulting value is big endian and needs leading zero padding.
            let leading_zeros = SIZE.checked_sub(len).ok_or(encoding::Error::Length)?;

            let mut bytes = [0u8; SIZE];
            reader.read(&mut bytes[leading_zeros..])?;
            Ok(Self { bytes })
        })
    }
}

impl<const SIZE: usize> Encode for EcdsaPrivateKey<SIZE> {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [4, self.needs_leading_zero().into(), SIZE].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        [self.needs_leading_zero().into(), SIZE]
            .checked_sum()?
            .encode(writer)?;

        if self.needs_leading_zero() {
            writer.write(&[0])?;
        }

        writer.write(&self.bytes)?;
        Ok(())
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for EcdsaPrivateKey<SIZE> {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self { bytes }
    }
}

impl<const SIZE: usize> AsRef<[u8; SIZE]> for EcdsaPrivateKey<SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        &self.bytes
    }
}

impl<const SIZE: usize> ConstantTimeEq for EcdsaPrivateKey<SIZE> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

impl<const SIZE: usize> PartialEq for EcdsaPrivateKey<SIZE> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const SIZE: usize> Eq for EcdsaPrivateKey<SIZE> {}

impl<const SIZE: usize> fmt::Debug for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaPrivateKey").finish_non_exhaustive()
    }
}

impl<const SIZE: usize> fmt::LowerHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> fmt::UpperHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> Drop for EcdsaPrivateKey<SIZE> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// p256/p384/p521 crate `From<SecretKey>` impls removed — wolfcrypt is
// now the sole cryptographic backend.

/// Zero-pad a big-endian private key scalar into a fixed-size array.
#[cfg(all(
    feature = "rand_core",
    any(feature = "p256", feature = "p384", feature = "p521")
))]
fn pad_private<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    if bytes.len() > N {
        return Err(Error::Crypto);
    }
    let mut arr = [0u8; N];
    arr[N - bytes.len()..].copy_from_slice(bytes);
    Ok(arr)
}

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private/public keypair.
#[derive(Clone)]
pub enum EcdsaKeypair {
    /// NIST P-256 ECDSA keypair.
    NistP256 {
        /// Public key.
        public: sec1::EncodedPoint<U32>,

        /// Private key.
        private: EcdsaPrivateKey<32>,
    },

    /// NIST P-384 ECDSA keypair.
    NistP384 {
        /// Public key.
        public: sec1::EncodedPoint<U48>,

        /// Private key.
        private: EcdsaPrivateKey<48>,
    },

    /// NIST P-521 ECDSA keypair.
    NistP521 {
        /// Public key.
        public: sec1::EncodedPoint<U66>,

        /// Private key.
        private: EcdsaPrivateKey<66>,
    },
}

impl core::fmt::Debug for EcdsaKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcdsaKeypair").finish_non_exhaustive()
    }
}

impl EcdsaKeypair {
    /// Generate a random ECDSA private key using wolfcrypt.
    ///
    /// The caller-provided `rng` is ignored — wolfCrypt uses its own
    /// internal DRBG via [`wolfcrypt::rand::WolfRng`]. The parameter is
    /// retained for API compatibility with the upstream `ssh-key` crate.
    #[cfg(all(
        feature = "rand_core",
        any(feature = "p256", feature = "p384", feature = "p521")
    ))]
    #[expect(unused_variables)]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, curve: EcdsaCurve) -> Result<Self> {
        use wolfcrypt::rand::WolfRng;

        let curve_id = match curve {
            #[cfg(feature = "p256")]
            EcdsaCurve::NistP256 => EccCurveId::SecP256R1,
            #[cfg(feature = "p384")]
            EcdsaCurve::NistP384 => EccCurveId::SecP384R1,
            #[cfg(feature = "p521")]
            EcdsaCurve::NistP521 => EccCurveId::SecP521R1,
            #[cfg(not(all(feature = "p256", feature = "p384", feature = "p521")))]
            _ => return Err(Error::AlgorithmUnknown),
        };

        let mut wc_rng = WolfRng::new().map_err(|_| Error::Crypto)?;
        let key = EccKey::generate(curve_id, &mut wc_rng).map_err(|_| Error::Crypto)?;

        let priv_bytes = key.export_private().map_err(|_| Error::Crypto)?;
        let pub_bytes = key.export_public_x963().map_err(|_| Error::Crypto)?;

        match curve {
            #[cfg(feature = "p256")]
            EcdsaCurve::NistP256 => {
                let public =
                    sec1::EncodedPoint::<U32>::from_bytes(&pub_bytes).map_err(|_| Error::Crypto)?;
                Ok(EcdsaKeypair::NistP256 {
                    private: EcdsaPrivateKey::from(pad_private(&priv_bytes)?),
                    public,
                })
            }
            #[cfg(feature = "p384")]
            EcdsaCurve::NistP384 => {
                let public =
                    sec1::EncodedPoint::<U48>::from_bytes(&pub_bytes).map_err(|_| Error::Crypto)?;
                Ok(EcdsaKeypair::NistP384 {
                    private: EcdsaPrivateKey::from(pad_private(&priv_bytes)?),
                    public,
                })
            }
            #[cfg(feature = "p521")]
            EcdsaCurve::NistP521 => {
                let public =
                    sec1::EncodedPoint::<U66>::from_bytes(&pub_bytes).map_err(|_| Error::Crypto)?;
                Ok(EcdsaKeypair::NistP521 {
                    private: EcdsaPrivateKey::from(pad_private(&priv_bytes)?),
                    public,
                })
            }
            #[cfg(not(all(feature = "p256", feature = "p384", feature = "p521")))]
            _ => Err(Error::AlgorithmUnknown),
        }
    }

    /// Get the [`Algorithm`] for this public key type.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Ecdsa {
            curve: self.curve(),
        }
    }

    /// Get the [`EcdsaCurve`] for this key.
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            Self::NistP256 { .. } => EcdsaCurve::NistP256,
            Self::NistP384 { .. } => EcdsaCurve::NistP384,
            Self::NistP521 { .. } => EcdsaCurve::NistP521,
        }
    }

    /// Get the bytes representing the public key.
    pub fn public_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { public, .. } => public.as_ref(),
            Self::NistP384 { public, .. } => public.as_ref(),
            Self::NistP521 { public, .. } => public.as_ref(),
        }
    }

    /// Get the bytes representing the private key.
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { private, .. } => private.as_ref(),
            Self::NistP384 { private, .. } => private.as_ref(),
            Self::NistP521 { private, .. } => private.as_ref(),
        }
    }
}

impl ConstantTimeEq for EcdsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        let public_eq =
            Choice::from((EcdsaPublicKey::from(self) == EcdsaPublicKey::from(other)) as u8);

        let private_key_a = match self {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        let private_key_b = match other {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        public_eq & private_key_a.ct_eq(private_key_b)
    }
}

impl Eq for EcdsaKeypair {}

impl PartialEq for EcdsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for EcdsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        match EcdsaPublicKey::decode(reader)? {
            EcdsaPublicKey::NistP256(public) => {
                let private = EcdsaPrivateKey::<32>::decode(reader)?;
                Ok(Self::NistP256 { public, private })
            }
            EcdsaPublicKey::NistP384(public) => {
                let private = EcdsaPrivateKey::<48>::decode(reader)?;
                Ok(Self::NistP384 { public, private })
            }
            EcdsaPublicKey::NistP521(public) => {
                let private = EcdsaPrivateKey::<66>::decode(reader)?;
                Ok(Self::NistP521 { public, private })
            }
        }
    }
}

impl Encode for EcdsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        let public_len = EcdsaPublicKey::from(self).encoded_len()?;

        let private_len = match self {
            Self::NistP256 { private, .. } => private.encoded_len()?,
            Self::NistP384 { private, .. } => private.encoded_len()?,
            Self::NistP521 { private, .. } => private.encoded_len()?,
        };

        [public_len, private_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        EcdsaPublicKey::from(self).encode(writer)?;

        match self {
            Self::NistP256 { private, .. } => private.encode(writer)?,
            Self::NistP384 { private, .. } => private.encode(writer)?,
            Self::NistP521 { private, .. } => private.encode(writer)?,
        }

        Ok(())
    }
}

impl From<EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: EcdsaKeypair) -> EcdsaPublicKey {
        EcdsaPublicKey::from(&keypair)
    }
}

impl From<&EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: &EcdsaKeypair) -> EcdsaPublicKey {
        match keypair {
            EcdsaKeypair::NistP256 { public, .. } => EcdsaPublicKey::NistP256(*public),
            EcdsaKeypair::NistP384 { public, .. } => EcdsaPublicKey::NistP384(*public),
            EcdsaKeypair::NistP521 { public, .. } => EcdsaPublicKey::NistP521(*public),
        }
    }
}
