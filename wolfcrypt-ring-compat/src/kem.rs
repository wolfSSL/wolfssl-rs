//! Key-Encapsulation Mechanisms (KEMs), including ML-KEM (FIPS 203).
//!
//! # Example
//!
//! ```rust
//! use ring::{
//!     kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
//!     kem::ML_KEM_512,
//! };
//!
//! // Alice generates their (private) decapsulation key.
//! let decapsulation_key = DecapsulationKey::generate(&ML_KEM_512)?;
//!
//! // Alice computes the (public) encapsulation key.
//! let encapsulation_key = decapsulation_key.encapsulation_key()?;
//!
//! let encapsulation_key_bytes = encapsulation_key.key_bytes()?;
//!
//! // Alice sends the encapsulation key bytes to Bob through some
//! // protocol message.
//! let encapsulation_key_bytes = encapsulation_key_bytes.as_ref();
//!
//! // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
//! let retrieved_encapsulation_key = EncapsulationKey::new(&ML_KEM_512, encapsulation_key_bytes)?;
//!
//! // Bob executes the encapsulation algorithm to produce their copy of the secret, and associated ciphertext.
//! let (ciphertext, bob_secret) = retrieved_encapsulation_key.encapsulate()?;
//!
//! // Alice receives ciphertext bytes from Bob
//! let ciphertext_bytes = ciphertext.as_ref();
//!
//! // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
//! // copy of the secret.
//! let alice_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;
//!
//! // Alice and Bob have now arrived at the same secret
//! assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```

use crate::buffer::Buffer;
use crate::error::{KeyRejected, Unspecified};
use alloc::borrow::Cow;
use core::cmp::Ordering;
use core::fmt::{Debug, Formatter};
use wolfcrypt_rs::{
    MlKemKey, WC_RNG,
    wc_MlKemKey_New, wc_MlKemKey_Delete, wc_MlKemKey_MakeKey,
    wc_MlKemKey_Encapsulate, wc_MlKemKey_Decapsulate,
    wc_MlKemKey_EncodePublicKey, wc_MlKemKey_EncodePrivateKey,
    wc_MlKemKey_DecodePublicKey, wc_MlKemKey_DecodePrivateKey,
    wc_InitRng, wc_FreeRng,
    WC_ML_KEM_512, WC_ML_KEM_768, WC_ML_KEM_1024,
    WC_ML_KEM_SS_SZ,
    WC_ML_KEM_512_PUBLIC_KEY_SIZE, WC_ML_KEM_512_PRIVATE_KEY_SIZE, WC_ML_KEM_512_CIPHER_TEXT_SIZE,
    WC_ML_KEM_768_PUBLIC_KEY_SIZE, WC_ML_KEM_768_PRIVATE_KEY_SIZE, WC_ML_KEM_768_CIPHER_TEXT_SIZE,
    WC_ML_KEM_1024_PUBLIC_KEY_SIZE, WC_ML_KEM_1024_PRIVATE_KEY_SIZE, WC_ML_KEM_1024_CIPHER_TEXT_SIZE,
};
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// INVALID_DEVID matches wolfSSL's INVALID_DEVID (-2).
const INVALID_DEVID: core::ffi::c_int = -2;

const ML_KEM_512_SHARED_SECRET_LENGTH: usize = WC_ML_KEM_SS_SZ;
const ML_KEM_512_PUBLIC_KEY_LENGTH: usize = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
const ML_KEM_512_SECRET_KEY_LENGTH: usize = WC_ML_KEM_512_PRIVATE_KEY_SIZE;
const ML_KEM_512_CIPHERTEXT_LENGTH: usize = WC_ML_KEM_512_CIPHER_TEXT_SIZE;

const ML_KEM_768_SHARED_SECRET_LENGTH: usize = WC_ML_KEM_SS_SZ;
const ML_KEM_768_PUBLIC_KEY_LENGTH: usize = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
const ML_KEM_768_SECRET_KEY_LENGTH: usize = WC_ML_KEM_768_PRIVATE_KEY_SIZE;
const ML_KEM_768_CIPHERTEXT_LENGTH: usize = WC_ML_KEM_768_CIPHER_TEXT_SIZE;

const ML_KEM_1024_SHARED_SECRET_LENGTH: usize = WC_ML_KEM_SS_SZ;
const ML_KEM_1024_PUBLIC_KEY_LENGTH: usize = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
const ML_KEM_1024_SECRET_KEY_LENGTH: usize = WC_ML_KEM_1024_PRIVATE_KEY_SIZE;
const ML_KEM_1024_CIPHERTEXT_LENGTH: usize = WC_ML_KEM_1024_CIPHER_TEXT_SIZE;

/// NIST FIPS 203 ML-KEM-512 algorithm.
pub const ML_KEM_512: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem512,
    decapsulate_key_size: ML_KEM_512_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_512_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_512_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_512_SHARED_SECRET_LENGTH,
};

/// NIST FIPS 203 ML-KEM-768 algorithm.
pub const ML_KEM_768: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem768,
    decapsulate_key_size: ML_KEM_768_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_768_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_768_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_768_SHARED_SECRET_LENGTH,
};

/// NIST FIPS 203 ML-KEM-1024 algorithm.
pub const ML_KEM_1024: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem1024,
    decapsulate_key_size: ML_KEM_1024_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_1024_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_1024_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_1024_SHARED_SECRET_LENGTH,
};

/// An identifier for a KEM algorithm.
pub trait AlgorithmIdentifier:
    Copy + Clone + Debug + PartialEq + crate::sealed::Sealed + 'static
{
    /// Returns the wolfCrypt ML-KEM type constant.
    fn wc_type(self) -> core::ffi::c_int;
}

/// A KEM algorithm
#[derive(PartialEq)]
pub struct Algorithm<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    pub(crate) id: Id,
    pub(crate) decapsulate_key_size: usize,
    pub(crate) encapsulate_key_size: usize,
    pub(crate) ciphertext_size: usize,
    pub(crate) shared_secret_size: usize,
}

impl<Id> Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Returns the identifier for this algorithm.
    #[must_use]
    pub fn id(&self) -> Id {
        self.id
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn decapsulate_key_size(&self) -> usize {
        self.decapsulate_key_size
    }

    #[inline]
    pub(crate) fn encapsulate_key_size(&self) -> usize {
        self.encapsulate_key_size
    }

    #[inline]
    pub(crate) fn ciphertext_size(&self) -> usize {
        self.ciphertext_size
    }

    #[inline]
    pub(crate) fn shared_secret_size(&self) -> usize {
        self.shared_secret_size
    }
}

impl<Id> Debug for Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// Identifier for a KEM algorithm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {
    /// NIST FIPS 203 ML-KEM-512 algorithm.
    MlKem512,

    /// NIST FIPS 203 ML-KEM-768 algorithm.
    MlKem768,

    /// NIST FIPS 203 ML-KEM-1024 algorithm.
    MlKem1024,
}

impl AlgorithmIdentifier for AlgorithmId {
    fn wc_type(self) -> core::ffi::c_int {
        match self {
            AlgorithmId::MlKem512 => WC_ML_KEM_512,
            AlgorithmId::MlKem768 => WC_ML_KEM_768,
            AlgorithmId::MlKem1024 => WC_ML_KEM_1024,
        }
    }
}

impl crate::sealed::Sealed for AlgorithmId {}

// ================================================================
// RAII wrapper for MlKemKey
// ================================================================

/// Wrapper around a heap-allocated `MlKemKey` that frees on drop.
struct OwnedMlKemKey {
    ptr: *mut MlKemKey,
}

impl OwnedMlKemKey {
    /// Allocate a new ML-KEM key for the given type.
    fn new(wc_type: core::ffi::c_int) -> Result<Self, Unspecified> {
        // SAFETY: wc_MlKemKey_New allocates a new key; null_mut() and INVALID_DEVID are valid args.
        let ptr = unsafe {
            wc_MlKemKey_New(wc_type, core::ptr::null_mut(), INVALID_DEVID)
        };
        if ptr.is_null() {
            return Err(Unspecified);
        }
        Ok(Self { ptr })
    }

    fn as_mut_ptr(&self) -> *mut MlKemKey {
        self.ptr
    }
}

impl Drop for OwnedMlKemKey {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr is non-null and was allocated by wc_MlKemKey_New.
            unsafe {
                wc_MlKemKey_Delete(self.ptr, core::ptr::null_mut());
            }
            self.ptr = core::ptr::null_mut();
        }
    }
}

// Safety: MlKemKey contains no thread-local state; all access is through &self
// or &mut self on the containing types (which use interior mutability only through
// the wolfCrypt C API which is thread-safe for distinct key objects).
unsafe impl Send for OwnedMlKemKey {}
unsafe impl Sync for OwnedMlKemKey {}

// ================================================================
// RAII wrapper for WC_RNG
// ================================================================

/// Scoped RNG that initializes on creation and frees on drop.
struct ScopedRng {
    rng: WC_RNG,
}

impl ScopedRng {
    fn new() -> Result<Self, Unspecified> {
        let mut rng = WC_RNG::zeroed();
        // SAFETY: rng is a zeroed WC_RNG; wc_InitRng initializes it in place.
        if unsafe { wc_InitRng(&mut rng) } != 0 {
            return Err(Unspecified);
        }
        Ok(Self { rng })
    }

    fn as_mut_ptr(&mut self) -> *mut WC_RNG {
        &mut self.rng
    }
}

impl Drop for ScopedRng {
    fn drop(&mut self) {
        // SAFETY: rng was successfully initialized by wc_InitRng in the constructor.
        unsafe {
            wc_FreeRng(&mut self.rng);
        }
    }
}

// ================================================================
// DecapsulationKey
// ================================================================

/// A serializable decapsulation key usable with KEMs. This can be randomly generated with `DecapsulationKey::generate`.
pub struct DecapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    key: OwnedMlKemKey,
    /// Whether this key was generated (and thus has both private + public components).
    /// Keys imported from raw bytes only have the private component.
    has_public: bool,
}

mod buffer_type {
    pub struct EncapsulationKeyBytesType {
        _priv: (),
    }
    pub struct DecapsulationKeyBytesType {
        _priv: (),
    }
}

/// Serialized encapsulation key bytes.
pub struct EncapsulationKeyBytes<'a>(Buffer<'a, buffer_type::EncapsulationKeyBytesType>);

impl<'a> core::ops::Deref for EncapsulationKeyBytes<'a> {
    type Target = Buffer<'a, buffer_type::EncapsulationKeyBytesType>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EncapsulationKeyBytes<'static> {
    pub(crate) fn new(owned: Vec<u8>) -> Self {
        Self(Buffer::new(owned))
    }
}

impl core::fmt::Debug for EncapsulationKeyBytes<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulationKeyBytes").finish()
    }
}

/// Serialized decapsulation key bytes.
pub struct DecapsulationKeyBytes<'a>(Buffer<'a, buffer_type::DecapsulationKeyBytesType>);

impl<'a> core::ops::Deref for DecapsulationKeyBytes<'a> {
    type Target = Buffer<'a, buffer_type::DecapsulationKeyBytesType>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DecapsulationKeyBytes<'static> {
    pub(crate) fn new(owned: Vec<u8>) -> Self {
        Self(Buffer::new(owned))
    }
}

impl core::fmt::Debug for DecapsulationKeyBytes<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKeyBytes").finish()
    }
}

impl<Id> DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Creates a new KEM decapsulation key from raw bytes. This method MUST NOT be used to generate
    /// a new decapsulation key, rather it MUST be used to construct `DecapsulationKey` previously serialized
    /// to raw bytes.
    ///
    /// `alg` is the [`Algorithm`] to be associated with the generated `DecapsulationKey`.
    ///
    /// `bytes` is a slice of raw bytes representing a `DecapsulationKey`.
    ///
    /// # Security Considerations
    ///
    /// This function performs size validation but does not fully validate key material integrity.
    /// Invalid key bytes (e.g., corrupted or tampered data) may be accepted by this function but
    /// will cause [`Self::decapsulate`] to fail or produce incorrect results. Only use bytes that
    /// were previously obtained from [`Self::key_bytes`] on a validly generated key.
    ///
    /// # Limitations
    ///
    /// The `DecapsulationKey` returned by this function will NOT provide the associated
    /// `EncapsulationKey` via [`Self::encapsulation_key`]. The `EncapsulationKey` must be
    /// serialized and restored separately using [`EncapsulationKey::key_bytes`] and
    /// [`EncapsulationKey::new`].
    ///
    /// # Errors
    ///
    /// Returns `KeyRejected::too_small()` if `bytes.len() < alg.decapsulate_key_size()`.
    ///
    /// Returns `KeyRejected::too_large()` if `bytes.len() > alg.decapsulate_key_size()`.
    ///
    /// Returns `KeyRejected::unexpected_error()` if the underlying cryptographic operation fails.
    pub fn new(alg: &'static Algorithm<Id>, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.decapsulate_key_size()) {
            Ordering::Less => return Err(KeyRejected::too_small()),
            Ordering::Greater => return Err(KeyRejected::too_large()),
            Ordering::Equal => {}
        }
        let key = OwnedMlKemKey::new(alg.id.wc_type())
            .map_err(|_| KeyRejected::unexpected_error())?;
        // SAFETY: key is valid from OwnedMlKemKey::new; pointer and length derived from a valid Rust slice.
        let rc = unsafe {
            wc_MlKemKey_DecodePrivateKey(
                key.as_mut_ptr(),
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if rc != 0 {
            return Err(KeyRejected::unexpected_error());
        }
        Ok(DecapsulationKey {
            algorithm: alg,
            key,
            has_public: false,
        })
    }

    /// Generate a new KEM decapsulation key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm<Id>) -> Result<Self, Unspecified> {
        let key = OwnedMlKemKey::new(alg.id.wc_type())?;
        let mut rng = ScopedRng::new()?;
        // SAFETY: key and rng are valid; initialized by their respective constructors above.
        let rc = unsafe {
            wc_MlKemKey_MakeKey(key.as_mut_ptr(), rng.as_mut_ptr())
        };
        if rc != 0 {
            return Err(Unspecified);
        }
        Ok(DecapsulationKey {
            algorithm: alg,
            key,
            has_public: true,
        })
    }

    /// Return the algorithm associated with the given KEM decapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Returns the raw bytes of the `DecapsulationKey`.
    ///
    /// The returned bytes can be used with [`Self::new`] to reconstruct the `DecapsulationKey`.
    ///
    /// # Errors
    ///
    /// Returns [`Unspecified`] if the key bytes cannot be retrieved from the underlying
    /// cryptographic implementation.
    pub fn key_bytes(&self) -> Result<DecapsulationKeyBytes<'static>, Unspecified> {
        let size = self.algorithm.decapsulate_key_size();
        let mut buf = vec![0u8; size];
        // SAFETY: self.key is valid; buf is a freshly allocated buffer of the correct size.
        let rc = unsafe {
            wc_MlKemKey_EncodePrivateKey(
                self.key.as_mut_ptr(),
                buf.as_mut_ptr(),
                size as u32,
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }
        Ok(DecapsulationKeyBytes::new(buf))
    }

    /// Returns the `EncapsulationKey` associated with this `DecapsulationKey`.
    ///
    /// # Errors
    ///
    /// Returns [`Unspecified`] in the following cases:
    /// * The `DecapsulationKey` was constructed from raw bytes using [`Self::new`],
    ///   as the underlying key representation does not include the public key component.
    ///   In this case, the `EncapsulationKey` must be serialized and restored separately.
    /// * An internal error occurs while extracting the public key.
    pub fn encapsulation_key(&self) -> Result<EncapsulationKey<Id>, Unspecified> {
        if !self.has_public {
            return Err(Unspecified);
        }

        // Export the public key bytes and create a new EncapsulationKey from them.
        let size = self.algorithm.encapsulate_key_size();
        let mut pub_bytes = vec![0u8; size];
        // SAFETY: self.key is valid with public component; buf is correctly sized.
        let rc = unsafe {
            wc_MlKemKey_EncodePublicKey(
                self.key.as_mut_ptr(),
                pub_bytes.as_mut_ptr(),
                size as u32,
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }

        // Create a new key object and import the public key
        let pub_key = OwnedMlKemKey::new(self.algorithm.id.wc_type())?;
        // SAFETY: pub_key is valid; pub_bytes was just encoded from the private key above.
        let rc = unsafe {
            wc_MlKemKey_DecodePublicKey(
                pub_key.as_mut_ptr(),
                pub_bytes.as_ptr(),
                pub_bytes.len() as u32,
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }

        Ok(EncapsulationKey {
            algorithm: self.algorithm,
            key: pub_key,
        })
    }

    /// Performs the decapsulate operation using this `DecapsulationKey` on the given ciphertext.
    ///
    /// `ciphertext` is the ciphertext generated by the encapsulate operation using the `EncapsulationKey`
    /// associated with this `DecapsulationKey`.
    ///
    /// # Errors
    ///
    /// Returns [`Unspecified`] if decapsulation fails due to an internal error.
    /// Note that per the ML-KEM specification (FIPS 203), decapsulation with an
    /// incorrect ciphertext uses implicit rejection: it produces a pseudorandom
    /// shared secret rather than returning an error. This prevents chosen-ciphertext
    /// attacks but means tampered ciphertexts will silently produce wrong secrets.
    #[allow(clippy::needless_pass_by_value)]
    pub fn decapsulate(&self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Unspecified> {
        let ss_size = self.algorithm.shared_secret_size();
        let mut shared_secret = vec![0u8; ss_size];
        let ct = ciphertext.as_ref();

        // SAFETY: self.key is valid; output and ciphertext buffers are correctly sized.
        let rc = unsafe {
            wc_MlKemKey_Decapsulate(
                self.key.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                ct.as_ptr(),
                ct.len() as u32,
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }

        Ok(SharedSecret(shared_secret.into_boxed_slice()))
    }
}

unsafe impl<Id> Send for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// ================================================================
// EncapsulationKey
// ================================================================

/// A serializable encapsulation key usable with KEM algorithms. Constructed
/// from either a `DecapsulationKey` or raw bytes.
pub struct EncapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    key: OwnedMlKemKey,
}

impl<Id> EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Return the algorithm associated with the given KEM encapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Performs the encapsulate operation using this KEM encapsulation key, generating a ciphertext
    /// and associated shared secret.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn encapsulate(&self) -> Result<(Ciphertext<'static>, SharedSecret), Unspecified> {
        let ct_size = self.algorithm.ciphertext_size();
        let ss_size = self.algorithm.shared_secret_size();
        let mut ciphertext = vec![0u8; ct_size];
        let mut shared_secret = vec![0u8; ss_size];

        let mut rng = ScopedRng::new()?;

        // SAFETY: self.key and rng are valid; output buffers are correctly sized for the algorithm.
        let rc = unsafe {
            wc_MlKemKey_Encapsulate(
                self.key.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                rng.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }

        Ok((
            Ciphertext::new(ciphertext),
            SharedSecret::new(shared_secret.into_boxed_slice()),
        ))
    }

    /// Returns the `EncapsulationKey` bytes.
    ///
    /// # Errors
    /// * `Unspecified`: Any failure to retrieve the `EncapsulationKey` bytes.
    pub fn key_bytes(&self) -> Result<EncapsulationKeyBytes<'static>, Unspecified> {
        let size = self.algorithm.encapsulate_key_size();
        let mut buf = vec![0u8; size];
        // SAFETY: self.key is valid; buf is a freshly allocated buffer of the correct size.
        let rc = unsafe {
            wc_MlKemKey_EncodePublicKey(
                self.key.as_mut_ptr(),
                buf.as_mut_ptr(),
                size as u32,
            )
        };
        if rc != 0 {
            return Err(Unspecified);
        }
        Ok(EncapsulationKeyBytes::new(buf))
    }

    /// Creates a new KEM encapsulation key from raw bytes. This method MUST NOT be used to generate
    /// a new encapsulation key, rather it MUST be used to construct `EncapsulationKey` previously serialized
    /// to raw bytes.
    ///
    /// `alg` is the [`Algorithm`] to be associated with the generated `EncapsulationKey`.
    ///
    /// `bytes` is a slice of raw bytes representing a `EncapsulationKey`.
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    pub fn new(alg: &'static Algorithm<Id>, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.encapsulate_key_size()) {
            Ordering::Less => return Err(KeyRejected::too_small()),
            Ordering::Greater => return Err(KeyRejected::too_large()),
            Ordering::Equal => {}
        }
        let key = OwnedMlKemKey::new(alg.id.wc_type())
            .map_err(|_| KeyRejected::unexpected_error())?;
        // SAFETY: key is valid from OwnedMlKemKey::new; pointer and length derived from a valid Rust slice.
        let rc = unsafe {
            wc_MlKemKey_DecodePublicKey(
                key.as_mut_ptr(),
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if rc != 0 {
            return Err(KeyRejected::unexpected_error());
        }
        Ok(EncapsulationKey {
            algorithm: alg,
            key,
        })
    }
}

unsafe impl<Id> Send for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// ================================================================
// Ciphertext / SharedSecret
// ================================================================

/// A set of encrypted bytes produced by [`EncapsulationKey::encapsulate`],
/// and used as an input to [`DecapsulationKey::decapsulate`].
pub struct Ciphertext<'a>(Cow<'a, [u8]>);

impl<'a> Ciphertext<'a> {
    fn new(value: Vec<u8>) -> Ciphertext<'a> {
        Self(Cow::Owned(value))
    }
}

impl Drop for Ciphertext<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}

impl AsRef<[u8]> for Ciphertext<'_> {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            Cow::Borrowed(v) => v,
            Cow::Owned(ref v) => v.as_ref(),
        }
    }
}

impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(Cow::Borrowed(value))
    }
}

/// The cryptographic shared secret output from the KEM encapsulate / decapsulate process.
pub struct SharedSecret(Box<[u8]>);

impl SharedSecret {
    fn new(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
    use crate::error::KeyRejected;

    use crate::kem::{ML_KEM_1024, ML_KEM_512, ML_KEM_768};

    #[test]
    fn ciphertext() {
        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::from(ciphertext_bytes.as_ref());
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
        drop(ciphertext);

        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::<'static>::new(ciphertext_bytes);
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
    }

    #[test]
    fn shared_secret() {
        let secret_bytes = vec![42u8; 4];
        let shared_secret = SharedSecret::new(secret_bytes.into_boxed_slice());
        assert_eq!(shared_secret.as_ref(), &[42, 42, 42, 42]);
    }

    #[test]
    fn test_kem_serialize() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            // Test DecapsulationKey serialization
            let priv_key_raw_bytes = priv_key.key_bytes().unwrap();
            assert_eq!(
                priv_key_raw_bytes.as_ref().len(),
                algorithm.decapsulate_key_size()
            );
            let priv_key_from_bytes =
                DecapsulationKey::new(algorithm, priv_key_raw_bytes.as_ref()).unwrap();

            assert_eq!(
                priv_key.key_bytes().unwrap().as_ref(),
                priv_key_from_bytes.key_bytes().unwrap().as_ref()
            );
            assert_eq!(priv_key.algorithm(), priv_key_from_bytes.algorithm());

            // Test EncapsulationKey serialization
            let pub_key = priv_key.encapsulation_key().unwrap();
            let pubkey_raw_bytes = pub_key.key_bytes().unwrap();
            let pub_key_from_bytes =
                EncapsulationKey::new(algorithm, pubkey_raw_bytes.as_ref()).unwrap();

            assert_eq!(
                pub_key.key_bytes().unwrap().as_ref(),
                pub_key_from_bytes.key_bytes().unwrap().as_ref()
            );
            assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());
        }
    }

    #[test]
    fn test_kem_wrong_sizes() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            // Test EncapsulationKey size validation
            let too_long_bytes = vec![0u8; algorithm.encapsulate_key_size() + 1];
            let long_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_pub_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.encapsulate_key_size() - 1];
            let short_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_pub_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );

            // Test DecapsulationKey size validation
            let too_long_bytes = vec![0u8; algorithm.decapsulate_key_size() + 1];
            let long_priv_key_from_bytes = DecapsulationKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_priv_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.decapsulate_key_size() - 1];
            let short_priv_key_from_bytes = DecapsulationKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_priv_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );
        }
    }

    #[test]
    fn test_kem_e2e() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            // Serialize and reconstruct the decapsulation key
            let priv_key_bytes = priv_key.key_bytes().unwrap();
            let priv_key_from_bytes =
                DecapsulationKey::new(algorithm, priv_key_bytes.as_ref()).unwrap();

            // Keys reconstructed from bytes cannot provide encapsulation_key()
            assert!(priv_key_from_bytes.encapsulation_key().is_err());

            let pub_key = priv_key.encapsulation_key().unwrap();

            let (alice_ciphertext, alice_secret) =
                pub_key.encapsulate().expect("encapsulate successful");

            // Decapsulate using the reconstructed key
            let bob_secret = priv_key_from_bytes
                .decapsulate(alice_ciphertext)
                .expect("decapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    /// Round-trip: generate, export pub key, import into new EncapsulationKey,
    /// encapsulate, decapsulate with original private key. Shared secrets must
    /// match byte-for-byte.
    #[test]
    fn test_serialized_kem_e2e() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();

            // Generate public key bytes to send to bob
            let pub_key_bytes = pub_key.key_bytes().unwrap();

            // Generate private key bytes for alice to store securely
            let priv_key_bytes = priv_key.key_bytes().unwrap();

            // Drop originals to prove we can work from serialized form
            drop(pub_key);
            drop(priv_key);

            let retrieved_pub_key =
                EncapsulationKey::new(algorithm, pub_key_bytes.as_ref()).unwrap();
            let (ciphertext, bob_secret) = retrieved_pub_key
                .encapsulate()
                .expect("encapsulate successful");

            // Alice reconstructs her private key from stored bytes
            let retrieved_priv_key =
                DecapsulationKey::new(algorithm, priv_key_bytes.as_ref()).unwrap();
            let alice_secret = retrieved_priv_key
                .decapsulate(ciphertext)
                .expect("decapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    #[test]
    fn test_decapsulation_key_serialization_roundtrip() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            // Generate original key
            let original_key = DecapsulationKey::generate(algorithm).unwrap();

            // Test key_bytes() returns correct size
            let key_bytes = original_key.key_bytes().unwrap();
            assert_eq!(key_bytes.as_ref().len(), algorithm.decapsulate_key_size());

            // Test round-trip serialization/deserialization
            let reconstructed_key = DecapsulationKey::new(algorithm, key_bytes.as_ref()).unwrap();

            // Verify algorithm consistency
            assert_eq!(original_key.algorithm(), reconstructed_key.algorithm());
            assert_eq!(original_key.algorithm(), algorithm);

            // Test serialization produces identical bytes (stability check)
            let key_bytes_2 = reconstructed_key.key_bytes().unwrap();
            assert_eq!(key_bytes.as_ref(), key_bytes_2.as_ref());

            // Test functional equivalence: both keys decrypt the same ciphertext identically
            let pub_key = original_key.encapsulation_key().unwrap();
            let (ciphertext, expected_secret) =
                pub_key.encapsulate().expect("encapsulate successful");

            let secret_from_original = original_key
                .decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .expect("decapsulate with original key");
            let secret_from_reconstructed = reconstructed_key
                .decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .expect("decapsulate with reconstructed key");

            // Verify both keys produce identical secrets
            assert_eq!(expected_secret.as_ref(), secret_from_original.as_ref());
            assert_eq!(expected_secret.as_ref(), secret_from_reconstructed.as_ref());

            // Verify secret length matches algorithm specification
            assert_eq!(expected_secret.as_ref().len(), algorithm.shared_secret_size);
        }
    }

    /// Negative test: tamper with ciphertext and verify that decapsulation
    /// produces a *different* shared secret (ML-KEM implicit rejection).
    /// Per FIPS 203, decapsulation with a tampered ciphertext must not produce
    /// the same shared secret as the legitimate one.
    #[test]
    fn test_tampered_ciphertext_produces_different_secret() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            let pub_key = priv_key.encapsulation_key().unwrap();

            let (ciphertext, original_secret) = pub_key.encapsulate().unwrap();

            // Tamper with the ciphertext by flipping a byte
            let mut tampered_ct = ciphertext.as_ref().to_vec();
            tampered_ct[0] ^= 0xFF;

            // Decapsulate with tampered ciphertext.
            // ML-KEM uses implicit rejection: this should succeed but produce
            // a different (pseudorandom) shared secret.
            let tampered_result = priv_key.decapsulate(Ciphertext::from(tampered_ct.as_slice()));
            match tampered_result {
                Ok(tampered_secret) => {
                    // Implicit rejection: secret must differ from the real one
                    assert_ne!(
                        original_secret.as_ref(),
                        tampered_secret.as_ref(),
                        "Tampered ciphertext must not produce the same shared secret for {:?}",
                        algorithm.id()
                    );
                }
                Err(_) => {
                    // Some implementations may return an error instead of implicit rejection.
                    // Both behaviors are acceptable for a negative test.
                }
            }
        }
    }

    /// Negative test: wrong-length ciphertext is rejected.
    #[test]
    fn test_wrong_ciphertext_length_rejected() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();

            // Too short
            let short_ct = vec![0u8; algorithm.ciphertext_size() - 1];
            let result = priv_key.decapsulate(Ciphertext::from(short_ct.as_slice()));
            assert!(
                result.is_err(),
                "Too-short ciphertext should be rejected for {:?}",
                algorithm.id()
            );

            // Too long
            let long_ct = vec![0u8; algorithm.ciphertext_size() + 1];
            let result = priv_key.decapsulate(Ciphertext::from(long_ct.as_slice()));
            assert!(
                result.is_err(),
                "Too-long ciphertext should be rejected for {:?}",
                algorithm.id()
            );
        }
    }

    #[test]
    fn test_cross_algorithm_key_rejection() {
        let algorithms = [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024];

        for source_alg in &algorithms {
            let key = DecapsulationKey::generate(source_alg).unwrap();
            let key_bytes = key.key_bytes().unwrap();

            for target_alg in &algorithms {
                if source_alg.id() == target_alg.id() {
                    let result = DecapsulationKey::new(target_alg, key_bytes.as_ref());
                    assert!(
                        result.is_ok(),
                        "Same algorithm should accept its own key bytes"
                    );
                } else {
                    let result = DecapsulationKey::new(target_alg, key_bytes.as_ref());
                    assert!(
                        result.is_err(),
                        "Algorithm {:?} should reject key bytes from {:?}",
                        target_alg.id(),
                        source_alg.id()
                    );

                    let err = result.err().unwrap();
                    let source_size = source_alg.decapsulate_key_size();
                    let target_size = target_alg.decapsulate_key_size();
                    if source_size < target_size {
                        assert_eq!(
                            err,
                            KeyRejected::too_small(),
                            "Smaller key should be rejected as too_small"
                        );
                    } else {
                        assert_eq!(
                            err,
                            KeyRejected::too_large(),
                            "Larger key should be rejected as too_large"
                        );
                    }
                }
            }
        }

        // Also test EncapsulationKey cross-algorithm rejection
        for source_alg in &algorithms {
            let decap_key = DecapsulationKey::generate(source_alg).unwrap();
            let encap_key = decap_key.encapsulation_key().unwrap();
            let key_bytes = encap_key.key_bytes().unwrap();

            for target_alg in &algorithms {
                if source_alg.id() == target_alg.id() {
                    let result = EncapsulationKey::new(target_alg, key_bytes.as_ref());
                    assert!(
                        result.is_ok(),
                        "Same algorithm should accept its own encapsulation key bytes"
                    );
                } else {
                    let result = EncapsulationKey::new(target_alg, key_bytes.as_ref());
                    assert!(
                        result.is_err(),
                        "Algorithm {:?} should reject encapsulation key bytes from {:?}",
                        target_alg.id(),
                        source_alg.id()
                    );
                }
            }
        }
    }

    #[test]
    fn test_debug_fmt() {
        let private = DecapsulationKey::generate(&ML_KEM_512).expect("successful generation");
        assert_eq!(
            format!("{private:?}"),
            "DecapsulationKey { algorithm: MlKem512, .. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                private.encapsulation_key().expect("public key retrievable")
            ),
            "EncapsulationKey { algorithm: MlKem512, .. }"
        );
    }
}
