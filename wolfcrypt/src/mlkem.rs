//! ML-KEM (Module-Lattice Key Encapsulation Mechanism) backed by wolfCrypt.
//!
//! Implements NIST FIPS 203 ML-KEM at three security levels:
//!
//! | Level | Type | Security | Ciphertext | Public key |
//! |-------|------|----------|------------|------------|
//! | [`MlKem512`] | `WC_ML_KEM_512` | ~AES-128 equivalent | 768 B | 800 B |
//! | [`MlKem768`] | `WC_ML_KEM_768` | ~AES-192 equivalent | 1088 B | 1184 B |
//! | [`MlKem1024`] | `WC_ML_KEM_1024` | ~AES-256 equivalent | 1568 B | 1568 B |
//!
//! Use ML-KEM-768 for most applications (NIST's recommended level).
//! Use ML-KEM-1024 when policy requires AES-256-equivalent post-quantum
//! security.  ML-KEM-512 is the fastest but offers the lowest security
//! margin and may not be accepted by all compliance frameworks.
//!
//! Provides [`MlKemDecapsulationKey`] for key generation and decapsulation, and
//! [`MlKemEncapsulationKey`] for encapsulation using a public key.

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::marker::PhantomData;
use core::ptr;

use zeroize::ZeroizeOnDrop;

use crate::error::{check, len_as_u32, WolfCryptError};
use wolfcrypt_rs::{
    wc_FreeRng, wc_InitRng, wc_MlKemKey_Decapsulate, wc_MlKemKey_DecodePrivateKey,
    wc_MlKemKey_DecodePublicKey, wc_MlKemKey_Delete, wc_MlKemKey_Encapsulate,
    wc_MlKemKey_EncodePrivateKey, wc_MlKemKey_EncodePublicKey, wc_MlKemKey_MakeKey,
    wc_MlKemKey_New, MlKemKey, INVALID_DEVID, WC_ML_KEM_1024, WC_ML_KEM_1024_CIPHER_TEXT_SIZE,
    WC_ML_KEM_1024_PRIVATE_KEY_SIZE, WC_ML_KEM_1024_PUBLIC_KEY_SIZE, WC_ML_KEM_512,
    WC_ML_KEM_512_CIPHER_TEXT_SIZE, WC_ML_KEM_512_PRIVATE_KEY_SIZE, WC_ML_KEM_512_PUBLIC_KEY_SIZE,
    WC_ML_KEM_768, WC_ML_KEM_768_CIPHER_TEXT_SIZE, WC_ML_KEM_768_PRIVATE_KEY_SIZE,
    WC_ML_KEM_768_PUBLIC_KEY_SIZE, WC_ML_KEM_SS_SZ, WC_RNG,
};

// ---------------------------------------------------------------------------
// Level trait and implementations
// ---------------------------------------------------------------------------

/// Trait that associates an ML-KEM security level with its type constant and
/// sizes as defined in NIST FIPS 203.
pub trait MlKemLevel: Send + 'static {
    /// wolfCrypt type constant (`WC_ML_KEM_512`, etc.).
    const TYPE: c_int;
    /// Public (encapsulation) key size in bytes.
    const PK_SIZE: usize;
    /// Private (decapsulation) key size in bytes.
    const SK_SIZE: usize;
    /// Ciphertext size in bytes.
    const CT_SIZE: usize;
    /// Shared secret size in bytes (always 32 for ML-KEM).
    const SS_SIZE: usize;
}

/// ML-KEM-512 (NIST security level 1).
pub struct MlKem512;

/// ML-KEM-768 (NIST security level 3).
pub struct MlKem768;

/// ML-KEM-1024 (NIST security level 5).
pub struct MlKem1024;

impl MlKemLevel for MlKem512 {
    const TYPE: c_int = WC_ML_KEM_512;
    const PK_SIZE: usize = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
    const SK_SIZE: usize = WC_ML_KEM_512_PRIVATE_KEY_SIZE;
    const CT_SIZE: usize = WC_ML_KEM_512_CIPHER_TEXT_SIZE;
    const SS_SIZE: usize = WC_ML_KEM_SS_SZ;
}

impl MlKemLevel for MlKem768 {
    const TYPE: c_int = WC_ML_KEM_768;
    const PK_SIZE: usize = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
    const SK_SIZE: usize = WC_ML_KEM_768_PRIVATE_KEY_SIZE;
    const CT_SIZE: usize = WC_ML_KEM_768_CIPHER_TEXT_SIZE;
    const SS_SIZE: usize = WC_ML_KEM_SS_SZ;
}

impl MlKemLevel for MlKem1024 {
    const TYPE: c_int = WC_ML_KEM_1024;
    const PK_SIZE: usize = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
    const SK_SIZE: usize = WC_ML_KEM_1024_PRIVATE_KEY_SIZE;
    const CT_SIZE: usize = WC_ML_KEM_1024_CIPHER_TEXT_SIZE;
    const SS_SIZE: usize = WC_ML_KEM_SS_SZ;
}

// ---------------------------------------------------------------------------
// SharedSecret
// ---------------------------------------------------------------------------

/// The shared secret produced by ML-KEM encapsulation/decapsulation (32 bytes).
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret(#[zeroize(drop)] [u8; WC_ML_KEM_SS_SZ]);

impl SharedSecret {
    /// Return the raw shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison would be ideal, but for test ergonomics
        // a plain comparison suffices here (the secret is already exposed
        // via `as_bytes`).
        self.0 == other.0
    }
}
impl Eq for SharedSecret {}

// ---------------------------------------------------------------------------
// MlKemDecapsulationKey
// ---------------------------------------------------------------------------

/// An ML-KEM decapsulation (private) key backed by wolfCrypt.
///
/// Created via [`generate`](Self::generate), this key can produce its
/// corresponding [`MlKemEncapsulationKey`] and decapsulate ciphertexts.
pub struct MlKemDecapsulationKey<L: MlKemLevel> {
    key: *mut MlKemKey,
    rng: WC_RNG,
    _level: PhantomData<L>,
}

// SAFETY: `MlKemKey` and `WC_RNG` own independent state with no shared
// mutable globals; safe to move between threads.
unsafe impl<L: MlKemLevel> Send for MlKemDecapsulationKey<L> {}

impl<L: MlKemLevel> MlKemDecapsulationKey<L> {
    /// Generate a fresh ML-KEM keypair.
    pub fn generate() -> Result<Self, WolfCryptError> {
        // Allocate key on the heap via wolfCrypt.
        // SAFETY: `wc_MlKemKey_New` returns a heap-allocated key or null.
        let key = unsafe { wc_MlKemKey_New(L::TYPE, ptr::null_mut(), INVALID_DEVID) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // Initialise RNG for key generation.
        let mut rng = WC_RNG::zeroed();
        // SAFETY: `rng` is zeroed; `wc_InitRng` will fully initialise it.
        let rc = unsafe { wc_InitRng(&mut rng) };
        if rc != 0 {
            // Clean up the key on failure.
            unsafe {
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_InitRng",
            });
        }

        // Generate the keypair.
        // SAFETY: `key` is a valid heap-allocated MlKemKey, `rng` is
        // initialised.
        let rc = unsafe { wc_MlKemKey_MakeKey(key, &mut rng) };
        if rc != 0 {
            unsafe {
                wc_FreeRng(&mut rng);
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_MlKemKey_MakeKey",
            });
        }

        Ok(Self {
            key,
            rng,
            _level: PhantomData,
        })
    }

    /// Return the corresponding encapsulation (public) key.
    ///
    /// The public key bytes are exported from the private key and then
    /// imported into a new public-only key object.
    pub fn encapsulation_key(&self) -> Result<MlKemEncapsulationKey<L>, WolfCryptError> {
        let mut pk_buf = vec![0u8; L::PK_SIZE];

        // SAFETY: `self.key` is a fully-generated ML-KEM key. `pk_buf` is
        // `L::PK_SIZE` bytes.
        let rc = unsafe {
            wc_MlKemKey_EncodePublicKey(self.key, pk_buf.as_mut_ptr(), L::PK_SIZE as u32)
        };
        check(rc, "wc_MlKemKey_EncodePublicKey")?;

        MlKemEncapsulationKey::from_bytes(&pk_buf)
    }

    /// Export the raw public key bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, WolfCryptError> {
        let mut pk_buf = vec![0u8; L::PK_SIZE];
        let rc = unsafe {
            wc_MlKemKey_EncodePublicKey(self.key, pk_buf.as_mut_ptr(), L::PK_SIZE as u32)
        };
        check(rc, "wc_MlKemKey_EncodePublicKey")?;
        Ok(pk_buf)
    }

    /// Export the raw private key bytes.
    ///
    /// The returned `Zeroizing<Vec<u8>>` automatically zeroizes the key
    /// material when dropped.
    pub fn private_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, WolfCryptError> {
        let mut sk_buf = vec![0u8; L::SK_SIZE];
        let rc = unsafe {
            wc_MlKemKey_EncodePrivateKey(self.key, sk_buf.as_mut_ptr(), L::SK_SIZE as u32)
        };
        check(rc, "wc_MlKemKey_EncodePrivateKey")?;
        Ok(zeroize::Zeroizing::new(sk_buf))
    }

    /// Load an ML-KEM decapsulation key from stored private key bytes.
    ///
    /// `bytes` must be exactly `L::SK_SIZE` bytes as produced by
    /// [`private_key_bytes`](Self::private_key_bytes).
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != L::SK_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        let key = unsafe { wc_MlKemKey_New(L::TYPE, ptr::null_mut(), INVALID_DEVID) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: `key` is a valid heap-allocated MlKemKey; `bytes` is SK_SIZE bytes.
        let rc =
            unsafe { wc_MlKemKey_DecodePrivateKey(key, bytes.as_ptr(), len_as_u32(bytes.len())) };
        if rc != 0 {
            unsafe {
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_MlKemKey_DecodePrivateKey",
            });
        }

        let mut rng = WC_RNG::zeroed();
        let rc = unsafe { wc_InitRng(&mut rng) };
        if rc != 0 {
            unsafe {
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_InitRng",
            });
        }

        Ok(Self {
            key,
            rng,
            _level: PhantomData,
        })
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    ///
    /// `ct` must be exactly `L::CT_SIZE` bytes.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret, WolfCryptError> {
        if ct.len() != L::CT_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        let mut ss = [0u8; WC_ML_KEM_SS_SZ];

        // SAFETY: `self.key` holds a full keypair (private + public).
        // `ct` is exactly `L::CT_SIZE` bytes. `ss` is 32 bytes.
        let rc = unsafe {
            wc_MlKemKey_Decapsulate(self.key, ss.as_mut_ptr(), ct.as_ptr(), len_as_u32(ct.len()))
        };
        check(rc, "wc_MlKemKey_Decapsulate")?;

        Ok(SharedSecret(ss))
    }
}

impl<L: MlKemLevel> Drop for MlKemDecapsulationKey<L> {
    fn drop(&mut self) {
        // SAFETY: `self.key` was successfully allocated by `wc_MlKemKey_New`
        // and `self.rng` was initialised by `wc_InitRng`. Freed exactly once.
        unsafe {
            wc_MlKemKey_Delete(self.key, ptr::null_mut());
            wc_FreeRng(&mut self.rng);
        }
    }
}

// ---------------------------------------------------------------------------
// MlKemEncapsulationKey
// ---------------------------------------------------------------------------

/// An ML-KEM encapsulation (public) key backed by wolfCrypt.
///
/// Created from raw public key bytes via [`from_bytes`](Self::from_bytes) or
/// from a [`MlKemDecapsulationKey`] via its
/// [`encapsulation_key`](MlKemDecapsulationKey::encapsulation_key) method.
pub struct MlKemEncapsulationKey<L: MlKemLevel> {
    key: *mut MlKemKey,
    rng: WC_RNG,
    _level: PhantomData<L>,
}

// SAFETY: Same rationale as `MlKemDecapsulationKey`.
unsafe impl<L: MlKemLevel> Send for MlKemEncapsulationKey<L> {}

impl<L: MlKemLevel> MlKemEncapsulationKey<L> {
    /// Import an encapsulation key from raw public key bytes.
    ///
    /// `bytes` must be exactly `L::PK_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != L::PK_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        // Allocate a fresh key object.
        let key = unsafe { wc_MlKemKey_New(L::TYPE, ptr::null_mut(), INVALID_DEVID) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // Import the public key bytes.
        // SAFETY: `key` is a valid heap-allocated MlKemKey, `bytes` is
        // `L::PK_SIZE` bytes.
        let rc =
            unsafe { wc_MlKemKey_DecodePublicKey(key, bytes.as_ptr(), len_as_u32(bytes.len())) };
        if rc != 0 {
            unsafe {
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_MlKemKey_DecodePublicKey",
            });
        }

        // Initialise RNG for encapsulation.
        let mut rng = WC_RNG::zeroed();
        let rc = unsafe { wc_InitRng(&mut rng) };
        if rc != 0 {
            unsafe {
                wc_MlKemKey_Delete(key, ptr::null_mut());
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_InitRng",
            });
        }

        Ok(Self {
            key,
            rng,
            _level: PhantomData,
        })
    }

    /// Export the raw public key bytes.
    pub fn as_bytes(&self) -> Result<Vec<u8>, WolfCryptError> {
        let mut pk_buf = vec![0u8; L::PK_SIZE];
        let rc = unsafe {
            wc_MlKemKey_EncodePublicKey(self.key, pk_buf.as_mut_ptr(), L::PK_SIZE as u32)
        };
        check(rc, "wc_MlKemKey_EncodePublicKey")?;
        Ok(pk_buf)
    }

    /// Encapsulate: produce a ciphertext and shared secret.
    ///
    /// Returns `(ciphertext, shared_secret)` where the ciphertext should be
    /// sent to the holder of the decapsulation key.
    ///
    /// Takes `&mut self` because encapsulation mutates the internal RNG.
    /// Unlike the `Signer`/`Verifier` types (which use `UnsafeCell` to
    /// satisfy the trait-mandated `&self`), this method has no trait
    /// constraint, so `&mut self` is the honest signature.
    pub fn encapsulate(&mut self) -> Result<(Vec<u8>, SharedSecret), WolfCryptError> {
        let mut ct = vec![0u8; L::CT_SIZE];
        let mut ss = [0u8; WC_ML_KEM_SS_SZ];

        // SAFETY: `self.key` has a decoded public key. `ct` is `L::CT_SIZE`
        // bytes, `ss` is 32 bytes, `self.rng` is initialised.
        let rc = unsafe {
            wc_MlKemKey_Encapsulate(self.key, ct.as_mut_ptr(), ss.as_mut_ptr(), &mut self.rng)
        };
        check(rc, "wc_MlKemKey_Encapsulate")?;

        Ok((ct, SharedSecret(ss)))
    }
}

impl<L: MlKemLevel> Drop for MlKemEncapsulationKey<L> {
    fn drop(&mut self) {
        // SAFETY: `self.key` was allocated by `wc_MlKemKey_New` and
        // `self.rng` by `wc_InitRng`. Freed exactly once.
        unsafe {
            wc_MlKemKey_Delete(self.key, ptr::null_mut());
            wc_FreeRng(&mut self.rng);
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience type aliases
// ---------------------------------------------------------------------------

/// ML-KEM-512 decapsulation key.
pub type MlKem512DecapsulationKey = MlKemDecapsulationKey<MlKem512>;
/// ML-KEM-768 decapsulation key.
pub type MlKem768DecapsulationKey = MlKemDecapsulationKey<MlKem768>;
/// ML-KEM-1024 decapsulation key.
pub type MlKem1024DecapsulationKey = MlKemDecapsulationKey<MlKem1024>;

/// ML-KEM-512 encapsulation key.
pub type MlKem512EncapsulationKey = MlKemEncapsulationKey<MlKem512>;
/// ML-KEM-768 encapsulation key.
pub type MlKem768EncapsulationKey = MlKemEncapsulationKey<MlKem768>;
/// ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey = MlKemEncapsulationKey<MlKem1024>;
