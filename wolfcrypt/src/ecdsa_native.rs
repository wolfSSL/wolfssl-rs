//! ECDSA signing and verification (P-256, P-384) backed by native wolfCrypt
//! `wc_ecc_*` functions.
//!
//! This module is active when `OPENSSL_EXTRA` is absent (e.g. the
//! `cryptocb-only` firmware build).  It provides the same public API as
//! the `ecdsa` module (EVP-based) so that callers are unaffected by the
//! choice of implementation.
//!
//! Signing uses `wc_ecc_sign_hash` which dispatches to the registered
//! CryptoCb device in `WOLF_CRYPTO_CB_ONLY_ECC` builds.  Hashing uses the
//! native `wc_Sha256Hash` / `wc_Sha384Hash` one-shot functions.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::marker::PhantomData;

use generic_array::GenericArray;

use crate::error::WolfCryptError;

use wolfcrypt_rs::{
    WC_RNG, wc_InitRng, wc_FreeRng,
    wc_ecc_key,
    wc_ecc_key_new, wc_ecc_key_free,
    wc_ecc_make_key_ex, wc_ecc_set_rng,
    wc_ecc_import_private_key_ex, wc_ecc_import_x963, wc_ecc_export_x963,
    wc_ecc_sign_hash, wc_ecc_verify_hash,
    wc_ecc_sig_to_rs, wc_ecc_rs_raw_to_sig,
    ECC_SECP256R1,
};

#[cfg(wolfssl_ecc_p384)]
use wolfcrypt_rs::ECC_SECP384R1;

#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
use wolfcrypt_rs::ECC_SECP521R1;

// ============================================================
// Sealed trait pattern
// ============================================================

mod sealed {
    pub trait Sealed {}
}

/// Trait describing an ECDSA curve's parameters.
///
/// Sealed so that only [`P256`] and [`P384`] can implement it.
pub trait EcdsaCurve: sealed::Sealed + 'static {
    /// wolfCrypt curve ID (e.g. `ECC_SECP256R1`).
    const CURVE_ID: c_int;
    /// Size of one field element in bytes (32 for P-256, 48 for P-384).
    const FIELD_SIZE: usize;
    /// Size of the fixed-size signature (2 * FIELD_SIZE).
    const SIG_SIZE: usize;
    /// Size of the uncompressed public point (1 + 2 * FIELD_SIZE).
    const UNCOMPRESSED_POINT_SIZE: usize;
    /// Hash output length in bytes for this curve's canonical digest.
    ///
    /// This is *not* always equal to `FIELD_SIZE`.  For example, P-521 uses
    /// SHA-512 (64 bytes) while its field size is 66 bytes.
    const HASH_LEN: usize;
    /// Typenum encoding of [`SIG_SIZE`](Self::SIG_SIZE).
    type SigSize: generic_array::ArrayLength<u8>;

    /// Hash `msg` using the curve's canonical digest.
    fn hash_message(msg: &[u8]) -> Result<Vec<u8>, WolfCryptError>;
}

/// NIST P-256 (secp256r1 / prime256v1) curve marker.
pub struct P256;

impl sealed::Sealed for P256 {}

impl EcdsaCurve for P256 {
    const CURVE_ID: c_int = ECC_SECP256R1;
    const FIELD_SIZE: usize = 32;
    const SIG_SIZE: usize = 64;
    const UNCOMPRESSED_POINT_SIZE: usize = 65;
    const HASH_LEN: usize = 32;
    type SigSize = typenum::U64;

    fn hash_message(msg: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        let mut hash = vec![0u8; 32];
        let rc = unsafe {
            wolfcrypt_rs::wc_Sha256Hash(msg.as_ptr(), msg.len() as u32, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_Sha256Hash" });
        }
        Ok(hash)
    }
}

/// NIST P-384 (secp384r1) curve marker.
#[cfg(wolfssl_ecc_p384)]
pub struct P384;

#[cfg(wolfssl_ecc_p384)]
impl sealed::Sealed for P384 {}

#[cfg(wolfssl_ecc_p384)]
impl EcdsaCurve for P384 {
    const CURVE_ID: c_int = ECC_SECP384R1;
    const FIELD_SIZE: usize = 48;
    const SIG_SIZE: usize = 96;
    const UNCOMPRESSED_POINT_SIZE: usize = 97;
    const HASH_LEN: usize = 48;
    type SigSize = typenum::U96;

    fn hash_message(msg: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        let mut hash = vec![0u8; 48];
        let rc = unsafe {
            wolfcrypt_rs::wc_Sha384Hash(msg.as_ptr(), msg.len() as u32, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_Sha384Hash" });
        }
        Ok(hash)
    }
}

/// NIST P-521 (secp521r1) curve marker.
#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
pub struct P521;

#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
impl sealed::Sealed for P521 {}

#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
impl EcdsaCurve for P521 {
    const CURVE_ID: c_int = ECC_SECP521R1;
    /// P-521 field element: ceil(521/8) = 66 bytes.
    const FIELD_SIZE: usize = 66;
    /// Fixed-size r || s signature: 2 * 66 = 132 bytes.
    const SIG_SIZE: usize = 132;
    /// Uncompressed public point: 1 + 2 * 66 = 133 bytes.
    const UNCOMPRESSED_POINT_SIZE: usize = 133;
    const HASH_LEN: usize = 64;
    type SigSize = typenum::U132;

    fn hash_message(msg: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
        let mut hash = vec![0u8; 64];
        let rc = unsafe {
            wolfcrypt_rs::wc_Sha512Hash(msg.as_ptr(), msg.len() as u32, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_Sha512Hash" });
        }
        Ok(hash)
    }
}

// ============================================================
// EcdsaSignature<C>
// ============================================================

/// A fixed-size, stack-allocated ECDSA signature in `r || s` format.
pub struct EcdsaSignature<C: EcdsaCurve> {
    bytes: GenericArray<u8, C::SigSize>,
    _curve: PhantomData<C>,
}

impl<C: EcdsaCurve> EcdsaSignature<C> {
    /// Create a signature from raw `r || s` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != C::SIG_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        Ok(Self {
            bytes: GenericArray::clone_from_slice(bytes),
            _curve: PhantomData,
        })
    }

    /// Return the raw `r || s` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return `r` component (big-endian, zero-padded to FIELD_SIZE bytes).
    pub fn r_bytes(&self) -> &[u8] {
        &self.bytes[..C::FIELD_SIZE]
    }

    /// Return `s` component (big-endian, zero-padded to FIELD_SIZE bytes).
    pub fn s_bytes(&self) -> &[u8] {
        &self.bytes[C::FIELD_SIZE..]
    }
}

impl<C: EcdsaCurve> Clone for EcdsaSignature<C> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes.clone(), _curve: PhantomData }
    }
}

impl<C: EcdsaCurve> PartialEq for EcdsaSignature<C> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl<C: EcdsaCurve> Eq for EcdsaSignature<C> {}

impl<C: EcdsaCurve> core::fmt::Debug for EcdsaSignature<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcdsaSignature")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl<C: EcdsaCurve> signature_trait::SignatureEncoding for EcdsaSignature<C> {
    type Repr = Vec<u8>;
}

impl<C: EcdsaCurve> TryFrom<&[u8]> for EcdsaSignature<C> {
    type Error = signature_trait::Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes).map_err(|_| signature_trait::Error::new())
    }
}

impl<C: EcdsaCurve> From<EcdsaSignature<C>> for Vec<u8> {
    fn from(sig: EcdsaSignature<C>) -> Vec<u8> {
        sig.bytes.to_vec()
    }
}

impl<C: EcdsaCurve> AsRef<[u8]> for EcdsaSignature<C> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================
// Helper: convert DER signature to fixed r||s
// ============================================================

fn der_to_fixed_rs<C: EcdsaCurve>(
    der: &[u8],
    der_len: u32,
) -> Result<GenericArray<u8, C::SigSize>, WolfCryptError> {
    let mut r = vec![0u8; C::FIELD_SIZE];
    let mut s = vec![0u8; C::FIELD_SIZE];
    let mut r_len = C::FIELD_SIZE as u32;
    let mut s_len = C::FIELD_SIZE as u32;

    let rc = unsafe {
        wc_ecc_sig_to_rs(
            der.as_ptr(), der_len,
            r.as_mut_ptr(), &mut r_len,
            s.as_mut_ptr(), &mut s_len,
        )
    };
    if rc != 0 {
        return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_sig_to_rs" });
    }

    // wc_ecc_sig_to_rs returns r and s stripped of leading zeros.
    // Zero-pad them to FIELD_SIZE on the left.
    //
    // Defensive: we passed FIELD_SIZE as the buffer capacity; wolfCrypt must
    // never report a length exceeding it.  If it does (C bug, memory
    // corruption) the subtraction below would wrap in release builds causing
    // UB.  Return an error instead.
    if r_len as usize > C::FIELD_SIZE || s_len as usize > C::FIELD_SIZE {
        return Err(WolfCryptError::INVALID_INPUT);
    }
    let mut combined = GenericArray::<u8, C::SigSize>::default();
    let r_pad = C::FIELD_SIZE - r_len as usize;
    combined[r_pad..C::FIELD_SIZE].copy_from_slice(&r[..r_len as usize]);
    let s_pad = C::FIELD_SIZE - s_len as usize;
    combined[C::FIELD_SIZE + s_pad..].copy_from_slice(&s[..s_len as usize]);

    Ok(combined)
}

// ============================================================
// EcdsaSigningKey<C>
// ============================================================

/// An ECDSA signing key (private key) backed by native wolfCrypt `wc_ecc_*`.
pub struct EcdsaSigningKey<C: EcdsaCurve> {
    /// Heap-allocated wc_ecc_key (via wc_ecc_key_new).
    ///
    /// `UnsafeCell` makes this type `!Sync`, which is the correct contract:
    /// wolfCrypt contexts are not thread-safe.
    key: UnsafeCell<*mut wc_ecc_key>,
    _curve: PhantomData<C>,
}

// SAFETY: wc_ecc_key owns independent heap state; safe to move between threads.
unsafe impl<C: EcdsaCurve> Send for EcdsaSigningKey<C> {}

impl<C: EcdsaCurve> Drop for EcdsaSigningKey<C> {
    fn drop(&mut self) {
        let key = *self.key.get_mut();
        if !key.is_null() {
            unsafe { wc_ecc_key_free(key) };
        }
    }
}

impl<C: EcdsaCurve> EcdsaSigningKey<C> {
    /// Generate a fresh random ECDSA signing key on curve `C`.
    pub fn generate() -> Result<Self, WolfCryptError> {
        let key = unsafe { wc_ecc_key_new(core::ptr::null_mut()) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        let mut rng = WC_RNG::zeroed();
        // SAFETY: rng is zero-initialised; wc_InitRng completes setup.
        let rc = unsafe { wc_InitRng(&mut rng) };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_InitRng" });
        }

        // SAFETY: key and rng are both initialised; FIELD_SIZE matches CURVE_ID.
        let rc = unsafe {
            wc_ecc_make_key_ex(&mut rng, C::FIELD_SIZE as c_int, key, C::CURVE_ID)
        };
        // Always free the RNG, success or failure.
        unsafe { wc_FreeRng(&mut rng) };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_make_key_ex" });
        }

        Ok(Self { key: UnsafeCell::new(key), _curve: PhantomData })
    }

    /// Construct a signing key from raw private-key scalar bytes and an
    /// uncompressed public point (0x04 || x || y).
    pub fn from_private_key_and_public_point(
        priv_bytes: &[u8],
        pub_bytes: &[u8],
    ) -> Result<Self, WolfCryptError> {
        if pub_bytes.len() != C::UNCOMPRESSED_POINT_SIZE || pub_bytes[0] != 0x04 {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        let key = unsafe { wc_ecc_key_new(core::ptr::null_mut()) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }
        let rc = unsafe {
            wc_ecc_import_private_key_ex(
                priv_bytes.as_ptr(), priv_bytes.len() as u32,
                pub_bytes.as_ptr(), pub_bytes.len() as u32,
                key, C::CURVE_ID,
            )
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_import_private_key_ex" });
        }
        Ok(Self { key: UnsafeCell::new(key), _curve: PhantomData })
    }

    /// Construct a signing key from raw private-key scalar bytes only.
    ///
    /// The public key is computed via EC point multiplication (pub = priv * G).
    /// In a `WOLF_CRYPTO_CB_ONLY_ECC` build this computation is dispatched to
    /// the registered CryptoCb device.
    pub fn from_private_key_bytes(priv_bytes: &[u8]) -> Result<Self, WolfCryptError> {
        let key = unsafe { wc_ecc_key_new(core::ptr::null_mut()) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }
        let rc = unsafe {
            wc_ecc_import_private_key_ex(
                priv_bytes.as_ptr(), priv_bytes.len() as u32,
                core::ptr::null(), 0,
                key, C::CURVE_ID,
            )
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_import_private_key_ex" });
        }
        Ok(Self { key: UnsafeCell::new(key), _curve: PhantomData })
    }

    /// Return the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> Result<EcdsaVerifyingKey<C>, WolfCryptError> {
        let key = unsafe { *self.key.get() };
        let mut buf = vec![0u8; C::UNCOMPRESSED_POINT_SIZE];
        let mut sz = buf.len() as u32;
        let rc = unsafe { wc_ecc_export_x963(key, buf.as_mut_ptr(), &mut sz) };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_export_x963" });
        }
        buf.truncate(sz as usize);
        EcdsaVerifyingKey::from_uncompressed_point(&buf)
    }

    /// Sign pre-hashed data directly (no internal hashing).
    ///
    /// `hash` must be exactly `C::HASH_LEN` bytes.
    pub fn sign_prehash(&self, hash: &[u8]) -> Result<EcdsaSignature<C>, WolfCryptError> {
        if hash.len() != C::HASH_LEN {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        let key = unsafe { *self.key.get() };

        // Max DER ECDSA signature: SEQUENCE + 2 * (INTEGER + optional-zero + field).
        let mut der = vec![0u8; C::FIELD_SIZE * 2 + 16];
        let mut der_len = der.len() as u32;

        // Initialise a per-call RNG for ECC_TIMING_RESISTANT scalar-multiplication
        // blinding.  Required on software builds; harmless on CryptoCb builds where
        // the dispatch ignores it.
        let mut rng = WC_RNG::zeroed();
        let rc = unsafe { wc_InitRng(&mut rng) };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_InitRng (sign)" });
        }

        // Attach the RNG to the key so internal timing-resistant code can use it.
        let rc = unsafe { wc_ecc_set_rng(key, &mut rng) };
        if rc != 0 {
            unsafe { wc_FreeRng(&mut rng) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_set_rng" });
        }

        // SAFETY: hash is HASH_LEN bytes; key holds the private key; rng is live.
        //
        // Note: the same `rng` is passed both as the key-attached RNG (via
        // `wc_ecc_set_rng` above, used for scalar-multiplication blinding) and
        // as the explicit RNG argument here (used for nonce generation).
        // wolfCrypt accepts the same object for both roles; this is intentional.
        let rc = unsafe {
            wc_ecc_sign_hash(
                hash.as_ptr(), hash.len() as u32,
                der.as_mut_ptr(), &mut der_len,
                &mut rng,
                key,
            )
        };
        // Always free the RNG regardless of outcome.
        unsafe { wc_FreeRng(&mut rng) };
        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_sign_hash" });
        }

        let combined = der_to_fixed_rs::<C>(&der, der_len)?;
        Ok(EcdsaSignature { bytes: combined, _curve: PhantomData })
    }
}

impl<C: EcdsaCurve> signature_trait::Signer<EcdsaSignature<C>> for EcdsaSigningKey<C> {
    fn try_sign(&self, msg: &[u8]) -> Result<EcdsaSignature<C>, signature_trait::Error> {
        let hash = C::hash_message(msg).map_err(|_| signature_trait::Error::new())?;
        self.sign_prehash(&hash).map_err(|_| signature_trait::Error::new())
    }
}

// ============================================================
// EcdsaVerifyingKey<C>
// ============================================================

/// An ECDSA verifying key (public key) backed by native wolfCrypt `wc_ecc_*`.
pub struct EcdsaVerifyingKey<C: EcdsaCurve> {
    key: UnsafeCell<*mut wc_ecc_key>,
    /// Cached uncompressed point bytes (0x04 || x || y).
    pub_bytes: Vec<u8>,
    _curve: PhantomData<C>,
}

unsafe impl<C: EcdsaCurve> Send for EcdsaVerifyingKey<C> {}

impl<C: EcdsaCurve> Drop for EcdsaVerifyingKey<C> {
    fn drop(&mut self) {
        let key = *self.key.get_mut();
        if !key.is_null() {
            unsafe { wc_ecc_key_free(key) };
        }
    }
}

impl<C: EcdsaCurve> EcdsaVerifyingKey<C> {
    /// Construct a verifying key from an uncompressed public point (0x04 || x || y).
    pub fn from_uncompressed_point(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != C::UNCOMPRESSED_POINT_SIZE || bytes[0] != 0x04 {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        let key = unsafe { wc_ecc_key_new(core::ptr::null_mut()) };
        if key.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }
        let rc = unsafe {
            wc_ecc_import_x963(bytes.as_ptr(), bytes.len() as u32, key)
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wc_ecc_import_x963" });
        }
        Ok(Self {
            key: UnsafeCell::new(key),
            pub_bytes: bytes.to_vec(),
            _curve: PhantomData,
        })
    }

    /// Return the uncompressed public point bytes (0x04 || x || y).
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }
}

impl<C: EcdsaCurve> signature_trait::Verifier<EcdsaSignature<C>> for EcdsaVerifyingKey<C> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &EcdsaSignature<C>,
    ) -> Result<(), signature_trait::Error> {
        let hash = C::hash_message(msg).map_err(|_| signature_trait::Error::new())?;
        let key = unsafe { *self.key.get() };

        // Convert fixed r||s to DER.
        let r = signature.r_bytes();
        let s = signature.s_bytes();
        let mut der = vec![0u8; C::FIELD_SIZE * 2 + 16];
        let mut der_len = der.len() as u32;

        let rc = unsafe {
            wc_ecc_rs_raw_to_sig(
                r.as_ptr(), r.len() as u32,
                s.as_ptr(), s.len() as u32,
                der.as_mut_ptr(), &mut der_len,
            )
        };
        if rc != 0 {
            return Err(signature_trait::Error::new());
        }

        let mut res: c_int = 0;
        let rc = unsafe {
            wc_ecc_verify_hash(
                der.as_ptr(), der_len,
                hash.as_ptr(), hash.len() as u32,
                &mut res, key,
            )
        };
        if rc != 0 || res != 1 {
            return Err(signature_trait::Error::new());
        }
        Ok(())
    }
}

// ============================================================
// Type aliases
// ============================================================

/// P-256 ECDSA signing key.
pub type P256SigningKey = EcdsaSigningKey<P256>;
/// P-256 ECDSA verifying key.
pub type P256VerifyingKey = EcdsaVerifyingKey<P256>;
/// P-256 ECDSA signature.
pub type P256Signature = EcdsaSignature<P256>;

/// P-384 ECDSA signing key.
#[cfg(wolfssl_ecc_p384)]
pub type P384SigningKey = EcdsaSigningKey<P384>;
/// P-384 ECDSA verifying key.
#[cfg(wolfssl_ecc_p384)]
pub type P384VerifyingKey = EcdsaVerifyingKey<P384>;
/// P-384 ECDSA signature.
#[cfg(wolfssl_ecc_p384)]
pub type P384Signature = EcdsaSignature<P384>;

/// P-521 ECDSA signing key.
#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
pub type P521SigningKey = EcdsaSigningKey<P521>;
/// P-521 ECDSA verifying key.
#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
pub type P521VerifyingKey = EcdsaVerifyingKey<P521>;
/// P-521 ECDSA signature.
#[cfg(all(wolfssl_ecc_p521, wolfssl_sha512))]
pub type P521Signature = EcdsaSignature<P521>;
