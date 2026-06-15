//! ML-DSA (FIPS 204 / Dilithium) signing and verification backed by wolfCrypt.
//!
//! Provides generic [`MlDsaSigningKey<L>`] and [`MlDsaVerifyingKey<L>`] types
//! parameterised by security level ([`MlDsa44`], [`MlDsa65`], [`MlDsa87`]),
//! implementing the RustCrypto [`signature::Signer`] and [`signature::Verifier`]
//! traits with the [`MlDsaSignature`] type.
//!
//! # Example
//!
//! ```ignore
//! use wolfcrypt::mldsa::{MlDsa65SigningKey, MlDsaSignature};
//! use wolfcrypt::WolfRng;
//! use signature_trait::{Signer, Verifier};
//!
//! let mut rng = WolfRng::new().unwrap();
//! let sk = MlDsa65SigningKey::generate(&mut rng).unwrap();
//! let vk = sk.verifying_key();
//! let sig: MlDsaSignature = sk.sign(b"hello");
//! vk.verify(b"hello", &sig).unwrap();
//! ```

use core::cell::UnsafeCell;
use core::marker::PhantomData;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{check, len_as_u32, WolfCryptError};
use wolfcrypt_rs::{
    wc_FreeRng, wc_InitRng, wc_dilithium_export_private, wc_dilithium_export_public,
    wc_dilithium_free, wc_dilithium_import_key, wc_dilithium_import_public, wc_dilithium_init,
    wc_dilithium_key, wc_dilithium_make_key, wc_dilithium_set_level, wc_dilithium_sign_msg,
    wc_dilithium_verify_msg, DILITHIUM_ML_DSA_44_KEY_SIZE, DILITHIUM_ML_DSA_44_PUB_KEY_SIZE,
    DILITHIUM_ML_DSA_44_SIG_SIZE, DILITHIUM_ML_DSA_65_KEY_SIZE, DILITHIUM_ML_DSA_65_PUB_KEY_SIZE,
    DILITHIUM_ML_DSA_65_SIG_SIZE, DILITHIUM_ML_DSA_87_KEY_SIZE, DILITHIUM_ML_DSA_87_PUB_KEY_SIZE,
    DILITHIUM_ML_DSA_87_SIG_SIZE, WC_ML_DSA_44, WC_ML_DSA_65, WC_ML_DSA_87, WC_RNG,
};

// ---------------------------------------------------------------------------
// MlDsaSignature<L> — level-parameterised signature container
// ---------------------------------------------------------------------------

/// An ML-DSA signature parameterised by security level.
///
/// The byte length is fixed per level: 2420 (ML-DSA-44), 3309 (ML-DSA-65),
/// or 4627 (ML-DSA-87) bytes per NIST FIPS 204, Table 2.
///
/// Parameterising by `L` ensures the type system prevents accidentally
/// verifying a signature produced at one level with a key at another.
#[derive(Debug)]
pub struct MlDsaSignature<L: MlDsaLevel> {
    bytes: Vec<u8>,
    _level: PhantomData<L>,
}

impl<L: MlDsaLevel> Clone for MlDsaSignature<L> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _level: PhantomData,
        }
    }
}

impl<L: MlDsaLevel> AsRef<[u8]> for MlDsaSignature<L> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<L: MlDsaLevel> signature_trait::SignatureEncoding for MlDsaSignature<L> {
    type Repr = Box<[u8]>;
}

impl<L: MlDsaLevel> TryFrom<&[u8]> for MlDsaSignature<L> {
    type Error = signature_trait::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == L::SIG_SIZE {
            Ok(Self {
                bytes: bytes.to_vec(),
                _level: PhantomData,
            })
        } else {
            Err(signature_trait::Error::new())
        }
    }
}

impl<L: MlDsaLevel> From<MlDsaSignature<L>> for Box<[u8]> {
    fn from(sig: MlDsaSignature<L>) -> Box<[u8]> {
        sig.bytes.into_boxed_slice()
    }
}

// ---------------------------------------------------------------------------
// MlDsaLevel trait — compile-time security level selection
// ---------------------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// Trait binding an ML-DSA security level to its wolfCrypt constants.
///
/// Sealed so that only [`MlDsa44`], [`MlDsa65`], and [`MlDsa87`]
/// can implement it.
pub trait MlDsaLevel: sealed::Sealed {
    /// wolfCrypt level parameter (WC_ML_DSA_44 = 2, WC_ML_DSA_65 = 3, WC_ML_DSA_87 = 5).
    const LEVEL: u8;
    /// Signature size in bytes (FIPS 204, Table 2).
    const SIG_SIZE: usize;
    /// Public key size in bytes (FIPS 204, Table 2).
    const PUB_KEY_SIZE: usize;
    /// Private key size in bytes (FIPS 204, Table 2).
    const PRIV_KEY_SIZE: usize;
}

/// ML-DSA-44 (NIST security level 2).
pub struct MlDsa44;

impl sealed::Sealed for MlDsa44 {}
impl sealed::Sealed for MlDsa65 {}
impl sealed::Sealed for MlDsa87 {}

impl MlDsaLevel for MlDsa44 {
    const LEVEL: u8 = WC_ML_DSA_44;
    const SIG_SIZE: usize = DILITHIUM_ML_DSA_44_SIG_SIZE;
    const PUB_KEY_SIZE: usize = DILITHIUM_ML_DSA_44_PUB_KEY_SIZE;
    const PRIV_KEY_SIZE: usize = DILITHIUM_ML_DSA_44_KEY_SIZE;
}

/// ML-DSA-65 (NIST security level 3).
pub struct MlDsa65;

impl MlDsaLevel for MlDsa65 {
    const LEVEL: u8 = WC_ML_DSA_65;
    const SIG_SIZE: usize = DILITHIUM_ML_DSA_65_SIG_SIZE;
    const PUB_KEY_SIZE: usize = DILITHIUM_ML_DSA_65_PUB_KEY_SIZE;
    const PRIV_KEY_SIZE: usize = DILITHIUM_ML_DSA_65_KEY_SIZE;
}

/// ML-DSA-87 (NIST security level 5).
pub struct MlDsa87;

impl MlDsaLevel for MlDsa87 {
    const LEVEL: u8 = WC_ML_DSA_87;
    const SIG_SIZE: usize = DILITHIUM_ML_DSA_87_SIG_SIZE;
    const PUB_KEY_SIZE: usize = DILITHIUM_ML_DSA_87_PUB_KEY_SIZE;
    const PRIV_KEY_SIZE: usize = DILITHIUM_ML_DSA_87_KEY_SIZE;
}

// ---------------------------------------------------------------------------
// MlDsaSigningKey<L>
// ---------------------------------------------------------------------------

/// An ML-DSA signing key (private key) backed by wolfCrypt.
///
/// The type parameter `L` selects the security level at compile time.
pub struct MlDsaSigningKey<L: MlDsaLevel> {
    /// Interior mutability: wolfCrypt requires `*mut` for sign even though
    /// the `Signer` trait provides only `&self`.
    key: UnsafeCell<wc_dilithium_key>,
    /// wolfCrypt RNG needed by `wc_dilithium_sign_msg`.
    rng: UnsafeCell<WC_RNG>,
    _level: PhantomData<L>,
}

// SAFETY: `wc_dilithium_key` and `WC_RNG` own independent state with no
// shared mutable globals, so the struct can safely be moved between threads.
unsafe impl<L: MlDsaLevel> Send for MlDsaSigningKey<L> {}

impl<L: MlDsaLevel> MlDsaSigningKey<L> {
    /// Generate a new ML-DSA keypair using the provided RNG.
    pub fn generate(rng: &mut crate::rand::WolfRng) -> Result<Self, WolfCryptError> {
        let mut key = wc_dilithium_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_dilithium_init` will fully initialise it.
        let rc = unsafe { wc_dilithium_init(&mut key) };
        check(rc, "wc_dilithium_init")?;

        // SAFETY: `key` is initialised. Set the security level before key generation.
        let rc = unsafe { wc_dilithium_set_level(&mut key, L::LEVEL) };
        check(rc, "wc_dilithium_set_level")?;

        // SAFETY: `key` has level set, `rng` is a valid WC_RNG.
        let rc = unsafe { wc_dilithium_make_key(&mut key, &mut rng.rng) };
        check(rc, "wc_dilithium_make_key")?;

        // Initialise an internal RNG owned by this signing key for future sign calls.
        let mut own_rng = WC_RNG::zeroed();
        // SAFETY: `own_rng` is zeroed and will be fully initialised.
        let rc = unsafe { wc_InitRng(&mut own_rng) };
        check(rc, "wc_InitRng")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            rng: UnsafeCell::new(own_rng),
            _level: PhantomData,
        })
    }

    /// Return the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> MlDsaVerifyingKey<L> {
        let mut pub_buf = vec![0u8; L::PUB_KEY_SIZE];
        let mut pub_len: u32 = L::PUB_KEY_SIZE as u32;

        // SAFETY: the key is fully initialised with both private and public
        // components after `wc_dilithium_make_key`.
        let rc = unsafe {
            wc_dilithium_export_public(self.key.get(), pub_buf.as_mut_ptr(), &mut pub_len)
        };
        assert_eq!(
            rc, 0,
            "wc_dilithium_export_public failed (key not initialized)"
        );
        assert_eq!(pub_len as usize, L::PUB_KEY_SIZE);

        MlDsaVerifyingKey::from_bytes(&pub_buf).expect("exported public key must be valid")
    }

    /// Load an ML-DSA signing key from raw private and public key bytes.
    ///
    /// Both `priv_bytes` and `pub_bytes` must be exactly `L::PRIV_KEY_SIZE` and
    /// `L::PUB_KEY_SIZE` bytes, respectively.  The bytes are typically obtained
    /// from a prior call to [`to_private_bytes`] and [`verifying_key().as_bytes()`].
    pub fn from_key_bytes(priv_bytes: &[u8], pub_bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if priv_bytes.len() != L::PRIV_KEY_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        if pub_bytes.len() != L::PUB_KEY_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        let mut key = wc_dilithium_key::zeroed();

        // SAFETY: `key` is zeroed; `wc_dilithium_init` fully initialises it.
        let rc = unsafe { wc_dilithium_init(&mut key) };
        check(rc, "wc_dilithium_init")?;

        // SAFETY: key is initialised; set level before import.
        let rc = unsafe { wc_dilithium_set_level(&mut key, L::LEVEL) };
        check(rc, "wc_dilithium_set_level")?;

        // SAFETY: `key` has level set; import private + public bytes.
        let rc = unsafe {
            wc_dilithium_import_key(
                priv_bytes.as_ptr(),
                len_as_u32(priv_bytes.len()),
                pub_bytes.as_ptr(),
                len_as_u32(pub_bytes.len()),
                &mut key,
            )
        };
        check(rc, "wc_dilithium_import_key")?;

        let mut own_rng = WC_RNG::zeroed();
        // SAFETY: `own_rng` is zeroed; `wc_InitRng` will fully initialise it.
        let rc = unsafe { wc_InitRng(&mut own_rng) };
        if rc != 0 {
            // SAFETY: key was successfully initialised; free before returning.
            unsafe { wc_dilithium_free(&mut key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_InitRng",
            });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            rng: UnsafeCell::new(own_rng),
            _level: PhantomData,
        })
    }

    /// Export the raw private key bytes.
    ///
    /// The returned `Zeroizing<Vec<u8>>` automatically zeroizes the key
    /// material when dropped.
    pub fn to_private_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut priv_buf = vec![0u8; L::PRIV_KEY_SIZE];
        let mut priv_len: u32 = L::PRIV_KEY_SIZE as u32;

        // SAFETY: the key is fully initialised.
        let rc = unsafe {
            wc_dilithium_export_private(self.key.get(), priv_buf.as_mut_ptr(), &mut priv_len)
        };
        assert_eq!(
            rc, 0,
            "wc_dilithium_export_private failed (key not initialized)"
        );
        priv_buf.truncate(priv_len as usize);
        zeroize::Zeroizing::new(priv_buf)
    }
}

impl<L: MlDsaLevel> Drop for MlDsaSigningKey<L> {
    fn drop(&mut self) {
        // SAFETY: the key and RNG were successfully initialised during
        // construction. We free each exactly once.
        unsafe {
            wc_dilithium_free(self.key.get_mut());
            wc_FreeRng(self.rng.get_mut());
        }
    }
}

impl<L: MlDsaLevel> signature_trait::Signer<MlDsaSignature<L>> for MlDsaSigningKey<L> {
    fn try_sign(&self, msg: &[u8]) -> Result<MlDsaSignature<L>, signature_trait::Error> {
        let mut sig_buf = vec![0u8; L::SIG_SIZE];
        let mut sig_len: u32 = L::SIG_SIZE as u32;

        // SAFETY: `self.key` and `self.rng` are initialised. The key has both
        // private and public components. `sig_buf` is large enough for the
        // signature. We use `UnsafeCell::get()` to obtain `*mut` pointers
        // because wolfCrypt's C API requires mutable pointers even though the
        // logical key material is not modified.
        let rc = unsafe {
            wc_dilithium_sign_msg(
                msg.as_ptr(),
                len_as_u32(msg.len()),
                sig_buf.as_mut_ptr(),
                &mut sig_len,
                self.key.get(),
                self.rng.get(),
            )
        };

        if rc != 0 {
            return Err(signature_trait::Error::new());
        }

        if sig_len as usize != L::SIG_SIZE {
            return Err(signature_trait::Error::new());
        }

        Ok(MlDsaSignature {
            bytes: sig_buf,
            _level: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// MlDsaVerifyingKey<L>
// ---------------------------------------------------------------------------

/// An ML-DSA verifying key (public key) backed by wolfCrypt.
///
/// The type parameter `L` selects the security level at compile time.
pub struct MlDsaVerifyingKey<L: MlDsaLevel> {
    /// Interior mutability: `wc_dilithium_verify_msg` requires `*mut`.
    key: UnsafeCell<wc_dilithium_key>,
    /// Cached copy of the public key bytes.
    pub_bytes: Vec<u8>,
    _level: PhantomData<L>,
}

// SAFETY: `wc_dilithium_key` owns independent state with no shared mutable
// globals, so the struct can safely be moved between threads.
unsafe impl<L: MlDsaLevel> Send for MlDsaVerifyingKey<L> {}

impl<L: MlDsaLevel> MlDsaVerifyingKey<L> {
    /// Construct a verifying key from raw public key bytes.
    ///
    /// The byte length must match the level's `PUB_KEY_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != L::PUB_KEY_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        let mut key = wc_dilithium_key::zeroed();

        // SAFETY: `key` is zeroed and `wc_dilithium_init` will fully initialise it.
        let rc = unsafe { wc_dilithium_init(&mut key) };
        check(rc, "wc_dilithium_init")?;

        // SAFETY: `key` is initialised. Set the security level before import.
        let rc = unsafe { wc_dilithium_set_level(&mut key, L::LEVEL) };
        check(rc, "wc_dilithium_set_level")?;

        // SAFETY: `key` has level set. We import exactly PUB_KEY_SIZE bytes.
        let rc = unsafe {
            wc_dilithium_import_public(bytes.as_ptr(), len_as_u32(bytes.len()), &mut key)
        };
        check(rc, "wc_dilithium_import_public")?;

        Ok(Self {
            key: UnsafeCell::new(key),
            pub_bytes: bytes.to_vec(),
            _level: PhantomData,
        })
    }

    /// Return a reference to the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }
}

impl<L: MlDsaLevel> Drop for MlDsaVerifyingKey<L> {
    fn drop(&mut self) {
        // SAFETY: `self.key` was successfully initialised during construction.
        // We free it exactly once.
        unsafe {
            wc_dilithium_free(self.key.get_mut());
        }
    }
}

impl<L: MlDsaLevel> signature_trait::Verifier<MlDsaSignature<L>> for MlDsaVerifyingKey<L> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &MlDsaSignature<L>,
    ) -> Result<(), signature_trait::Error> {
        let sig_bytes = signature.as_ref();
        let mut result: i32 = 0;

        // SAFETY: `self.key` is initialised with a valid public key.
        // `sig_bytes` contains the signature. `result` receives 1 if the
        // signature is valid, 0 otherwise. We use `UnsafeCell::get()` for
        // the mutable pointer required by wolfCrypt's C API; the public key
        // material is not logically modified.
        let rc = unsafe {
            wc_dilithium_verify_msg(
                sig_bytes.as_ptr(),
                len_as_u32(sig_bytes.len()),
                msg.as_ptr(),
                len_as_u32(msg.len()),
                &mut result,
                self.key.get(),
            )
        };

        if rc != 0 || result != 1 {
            return Err(signature_trait::Error::new());
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Type aliases for convenience
// ---------------------------------------------------------------------------

/// ML-DSA-44 signing key (NIST security level 2).
pub type MlDsa44SigningKey = MlDsaSigningKey<MlDsa44>;
/// ML-DSA-44 verifying key (NIST security level 2).
pub type MlDsa44VerifyingKey = MlDsaVerifyingKey<MlDsa44>;
/// ML-DSA-44 signature (2420 bytes).
pub type MlDsa44Signature = MlDsaSignature<MlDsa44>;

/// ML-DSA-65 signing key (NIST security level 3).
pub type MlDsa65SigningKey = MlDsaSigningKey<MlDsa65>;
/// ML-DSA-65 verifying key (NIST security level 3).
pub type MlDsa65VerifyingKey = MlDsaVerifyingKey<MlDsa65>;
/// ML-DSA-65 signature (3309 bytes).
pub type MlDsa65Signature = MlDsaSignature<MlDsa65>;

/// ML-DSA-87 signing key (NIST security level 5).
pub type MlDsa87SigningKey = MlDsaSigningKey<MlDsa87>;
/// ML-DSA-87 verifying key (NIST security level 5).
pub type MlDsa87VerifyingKey = MlDsaVerifyingKey<MlDsa87>;
/// ML-DSA-87 signature (4627 bytes).
pub type MlDsa87Signature = MlDsaSignature<MlDsa87>;
