//! ECDSA signing and verification (P-256, P-384, P-521) backed by wolfCrypt.
//!
//! Provides [`EcdsaSigningKey`] and [`EcdsaVerifyingKey`] parameterized by
//! curve ([`P256`] or [`P384`]), implementing the RustCrypto
//! [`signature::Signer`] and [`signature::Verifier`] traits.
//!
//! Signatures use the fixed-size `r || s` encoding (each component
//! zero-padded to the curve's field size), not DER.

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::marker::PhantomData;

use alloc::vec;
use alloc::vec::Vec;

use generic_array::GenericArray;

use crate::error::{len_as_c_int, WolfCryptError};

use wolfcrypt_rs::{
    BN_bn2bin, BN_bin2bn, BN_free, BN_num_bytes,
    EC_GROUP_free, EC_GROUP_new_by_curve_name,
    EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_public_key, EC_KEY_new,
    EC_KEY_set_group, EC_KEY_set_private_key, EC_KEY_set_public_key,
    EC_POINT_free, EC_POINT_mul, EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct,
    ECDSA_SIG_free, ECDSA_SIG_get0, ECDSA_SIG_new, ECDSA_SIG_set0,
    ECDSA_do_sign, ECDSA_do_verify,
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate,
    EVP_MD, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_sha256,
    NID_X9_62_prime256v1,
    BIGNUM, EC_GROUP, EC_KEY,
    point_conversion_form_t,
};

#[cfg(wolfssl_ecc_p384)]
use wolfcrypt_rs::{EVP_sha384, NID_secp384r1};

#[cfg(wolfssl_ecc_p521)]
use wolfcrypt_rs::{EVP_sha512, NID_secp521r1};

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
    /// The OpenSSL NID for this curve.
    const NID: c_int;
    /// Size of one field element in bytes (32 for P-256, 48 for P-384).
    const FIELD_SIZE: usize;
    /// Size of the fixed-size signature (2 * FIELD_SIZE).
    const SIG_SIZE: usize;
    /// Typenum encoding of [`SIG_SIZE`](Self::SIG_SIZE) for stack-allocated
    /// signature storage via `GenericArray`.
    type SigSize: generic_array::ArrayLength<u8>;
    /// Size of the uncompressed public point (1 + 2 * FIELD_SIZE).
    const UNCOMPRESSED_POINT_SIZE: usize;
    /// Hash length produced by the associated digest (same as FIELD_SIZE).
    const HASH_LEN: usize;
    /// Return a pointer to the EVP_MD for this curve's canonical hash.
    fn evp_md() -> *const EVP_MD;
}

/// NIST P-256 (secp256r1 / prime256v1) curve marker.
pub struct P256;

impl sealed::Sealed for P256 {}

impl EcdsaCurve for P256 {
    const NID: c_int = NID_X9_62_prime256v1;
    const FIELD_SIZE: usize = 32;
    const SIG_SIZE: usize = 64;
    type SigSize = typenum::U64;
    const UNCOMPRESSED_POINT_SIZE: usize = 65;
    const HASH_LEN: usize = 32;
    fn evp_md() -> *const EVP_MD {
        // SAFETY: EVP_sha256 returns a static pointer; always valid.
        unsafe { EVP_sha256() }
    }
}

/// NIST P-384 (secp384r1) curve marker.
#[cfg(wolfssl_ecc_p384)]
pub struct P384;

#[cfg(wolfssl_ecc_p384)]
impl sealed::Sealed for P384 {}

#[cfg(wolfssl_ecc_p384)]
impl EcdsaCurve for P384 {
    const NID: c_int = NID_secp384r1;
    const FIELD_SIZE: usize = 48;
    const SIG_SIZE: usize = 96;
    type SigSize = typenum::U96;
    const UNCOMPRESSED_POINT_SIZE: usize = 97;
    const HASH_LEN: usize = 48;
    fn evp_md() -> *const EVP_MD {
        // SAFETY: EVP_sha384 returns a static pointer; always valid.
        unsafe { EVP_sha384() }
    }
}

/// NIST P-521 (secp521r1) curve marker.
#[cfg(wolfssl_ecc_p521)]
pub struct P521;

#[cfg(wolfssl_ecc_p521)]
impl sealed::Sealed for P521 {}

#[cfg(wolfssl_ecc_p521)]
impl EcdsaCurve for P521 {
    const NID: c_int = NID_secp521r1;
    const FIELD_SIZE: usize = 66;  // ceil(521/8) = 66 bytes
    const SIG_SIZE: usize = 132;   // 2 * 66
    type SigSize = typenum::U132;
    const UNCOMPRESSED_POINT_SIZE: usize = 133; // 1 + 2*66
    const HASH_LEN: usize = 64;    // SHA-512 produces 64 bytes
    fn evp_md() -> *const EVP_MD {
        // SAFETY: EVP_sha512 returns a static pointer; always valid.
        unsafe { EVP_sha512() }
    }
}

// ============================================================
// EcdsaSignature<C>
// ============================================================

/// A fixed-size, stack-allocated ECDSA signature in `r || s` format.
///
/// Each component is zero-padded on the left to [`EcdsaCurve::FIELD_SIZE`]
/// bytes, giving a total length of `2 * FIELD_SIZE`.  The bytes are stored
/// inline in a `GenericArray` (no heap allocation).
pub struct EcdsaSignature<C: EcdsaCurve> {
    /// r || s, each FIELD_SIZE bytes.
    bytes: GenericArray<u8, C::SigSize>,
    _curve: PhantomData<C>,
}

impl<C: EcdsaCurve> EcdsaSignature<C> {
    /// Create a signature from raw `r || s` bytes.
    ///
    /// Returns `Err` if the slice length is not `C::SIG_SIZE`.
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

    /// Return `r` component (big-endian, FIELD_SIZE bytes).
    pub fn r_bytes(&self) -> &[u8] {
        &self.bytes[..C::FIELD_SIZE]
    }

    /// Return `s` component (big-endian, FIELD_SIZE bytes).
    pub fn s_bytes(&self) -> &[u8] {
        &self.bytes[C::FIELD_SIZE..]
    }
}

impl<C: EcdsaCurve> Clone for EcdsaSignature<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _curve: PhantomData,
        }
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
    // Vec<u8> rather than GenericArray<u8, C::SigSize>: using the GenericArray
    // would require `impl TryFrom<EcdsaSignature<C>> for GenericArray<...>`,
    // which is an orphan impl on a foreign type with a generic parameter —
    // technically allowed today but fragile across crate boundaries.  The
    // allocation (64–132 bytes, once per sign/verify) is negligible next to
    // the EC scalar multiplication.
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
// Helpers: hashing and BIGNUM conversion
// ============================================================

/// Hash `msg` with the curve's canonical digest, returning the hash bytes.
///
/// Allocates a fresh `EVP_MD_CTX` per call.  This is intentional: caching
/// the context in the key struct would add interior-mutability complexity
/// for no measurable gain — the EC scalar multiplication in sign/verify
/// dwarfs a single `XMALLOC`/`XFREE` pair.
fn hash_message<C: EcdsaCurve>(msg: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
    // SAFETY: EVP_MD_CTX_new returns a heap-allocated context or null.
    let ctx = unsafe { EVP_MD_CTX_new() };
    if ctx.is_null() {
        return Err(WolfCryptError::ALLOC_FAILED);
    }

    // SAFETY: ctx is valid, evp_md() returns a static pointer, engine is null.
    let rc = unsafe {
        EVP_DigestInit_ex(ctx, C::evp_md(), core::ptr::null_mut())
    };
    if rc != 1 {
        unsafe { EVP_MD_CTX_free(ctx) };
        return Err(WolfCryptError::Ffi { code: rc, func: "EVP_DigestInit_ex" });
    }

    // SAFETY: ctx is initialized, msg pointer and length are valid.
    let rc = unsafe {
        EVP_DigestUpdate(ctx, msg.as_ptr() as *const c_void, msg.len())
    };
    if rc != 1 {
        unsafe { EVP_MD_CTX_free(ctx) };
        return Err(WolfCryptError::Ffi { code: rc, func: "EVP_DigestUpdate" });
    }

    let mut hash = vec![0u8; C::HASH_LEN];
    let mut hash_len: c_uint = 0;

    // SAFETY: ctx is initialized, hash buffer is HASH_LEN bytes.
    let rc = unsafe { EVP_DigestFinal(ctx, hash.as_mut_ptr(), &mut hash_len) };
    unsafe { EVP_MD_CTX_free(ctx) };
    if rc != 1 {
        return Err(WolfCryptError::Ffi { code: rc, func: "EVP_DigestFinal" });
    }

    Ok(hash)
}

/// Convert a BIGNUM to a fixed-size big-endian byte array of `field_size`
/// bytes, zero-padded on the left.
///
/// SAFETY: `bn` must be a valid, non-null BIGNUM pointer.
unsafe fn bn_to_fixed_bytes(bn: *const BIGNUM, field_size: usize) -> Vec<u8> {
    // SAFETY: caller guarantees `bn` is a valid, non-null BIGNUM pointer.
    let num_bytes = unsafe { BN_num_bytes(bn) } as usize;
    let mut buf = vec![0u8; field_size];
    if num_bytes > 0 {
        // Write to the end of the buffer so leading zeros pad the front.
        let offset = field_size.saturating_sub(num_bytes);
        // SAFETY: `bn` is valid and `buf[offset..]` has at least `num_bytes` bytes.
        unsafe { BN_bn2bin(bn, buf[offset..].as_mut_ptr()) };
    }
    buf
}

// ============================================================
// EcdsaSigningKey<C>
// ============================================================

/// An ECDSA signing key (private key) backed by wolfCrypt's OpenSSL compat
/// layer.
///
/// Parameterized by curve: use [`P256`] or [`P384`].
pub struct EcdsaSigningKey<C: EcdsaCurve> {
    /// Heap-allocated EC_KEY.
    ///
    /// Strictly speaking `UnsafeCell` around the raw pointer is not
    /// required for soundness — `&self`'s aliasing scope covers the
    /// struct's own memory (the pointer value) but not the heap data
    /// behind it, so passing `*mut EC_KEY` to FFI is already legal.
    /// We keep `UnsafeCell` because it makes the type `!Sync`, which
    /// is the correct contract (wolfCrypt contexts are not thread-safe).
    key: UnsafeCell<*mut EC_KEY>,
    /// Heap-allocated EC_GROUP (owned; freed on drop).
    group: *mut EC_GROUP,
    _curve: PhantomData<C>,
}

// SAFETY: EC_KEY and EC_GROUP own independent heap state with no shared
// mutable globals; safe to move between threads.
unsafe impl<C: EcdsaCurve> Send for EcdsaSigningKey<C> {}

impl<C: EcdsaCurve> EcdsaSigningKey<C> {
    /// Generate a random ECDSA keypair on curve `C`.
    pub fn generate() -> Result<Self, WolfCryptError> {
        // SAFETY: EC_GROUP_new_by_curve_name returns null on failure.
        let group = unsafe { EC_GROUP_new_by_curve_name(C::NID) };
        if group.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: EC_KEY_new returns null on failure.
        let key = unsafe { EC_KEY_new() };
        if key.is_null() {
            unsafe { EC_GROUP_free(group) };
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: key and group are valid non-null pointers.
        let rc = unsafe { EC_KEY_set_group(key, group) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_group" });
        }

        // SAFETY: key is fully configured with a group; generate fills in
        // both private scalar and public point.
        let rc = unsafe { EC_KEY_generate_key(key) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_generate_key" });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            group,
            _curve: PhantomData,
        })
    }

    /// Return the corresponding verifying (public) key.
    ///
    /// Exports the public point in uncompressed form and constructs an
    /// [`EcdsaVerifyingKey`].
    pub fn verifying_key(&self) -> Result<EcdsaVerifyingKey<C>, WolfCryptError> {
        let key = unsafe { *self.key.get() };

        // SAFETY: key is valid; get0_public_key returns an internal pointer.
        let point = unsafe { EC_KEY_get0_public_key(key) };
        if point.is_null() {
            return Err(WolfCryptError::Ffi { code: 0, func: "EC_KEY_get0_public_key" });
        }

        let mut buf = vec![0u8; C::UNCOMPRESSED_POINT_SIZE];

        // SAFETY: group and point are valid. The buffer is sized for
        // uncompressed output. ctx is null (no BN_CTX needed).
        let written = unsafe {
            EC_POINT_point2oct(
                self.group as *const _,
                point,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                buf.as_mut_ptr(),
                buf.len(),
                core::ptr::null_mut(),
            )
        };
        if written != C::UNCOMPRESSED_POINT_SIZE {
            return Err(WolfCryptError::Ffi { code: written as i32, func: "EC_POINT_point2oct" });
        }

        EcdsaVerifyingKey::from_uncompressed_point(&buf)
    }

    /// Construct a signing key from raw private-key scalar bytes and an
    /// uncompressed public point (0x04 || x || y).
    ///
    /// `priv_bytes` is the big-endian encoding of the private scalar.
    /// `pub_bytes` must be exactly `C::UNCOMPRESSED_POINT_SIZE` bytes and
    /// start with `0x04`.
    pub fn from_private_key_and_public_point(
        priv_bytes: &[u8],
        pub_bytes: &[u8],
    ) -> Result<Self, WolfCryptError> {
        if pub_bytes.len() != C::UNCOMPRESSED_POINT_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        if pub_bytes[0] != 0x04 {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        // SAFETY: EC_GROUP_new_by_curve_name returns null on failure.
        let group = unsafe { EC_GROUP_new_by_curve_name(C::NID) };
        if group.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: EC_KEY_new returns null on failure.
        let key = unsafe { EC_KEY_new() };
        if key.is_null() {
            unsafe { EC_GROUP_free(group) };
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: key and group are valid non-null pointers.
        let rc = unsafe { EC_KEY_set_group(key, group) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_group" });
        }

        // --- Import the private key scalar ---

        // SAFETY: BN_bin2bn creates a new BIGNUM from big-endian bytes.
        // Passing null as ret allocates a fresh BIGNUM.
        let priv_bn = unsafe {
            BN_bin2bn(
                priv_bytes.as_ptr(),
                len_as_c_int(priv_bytes.len()),
                core::ptr::null_mut(),
            )
        };
        if priv_bn.is_null() {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: key is valid, priv_bn is a valid BIGNUM.
        // EC_KEY_set_private_key copies the BIGNUM, so we free it after.
        let rc = unsafe { EC_KEY_set_private_key(key, priv_bn) };
        unsafe { BN_free(priv_bn) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_private_key" });
        }

        // --- Import the public point ---

        // SAFETY: group is valid; EC_POINT_new returns null on failure.
        let point = unsafe { EC_POINT_new(group) };
        if point.is_null() {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: group and point are valid. pub_bytes is the correct length.
        let rc = unsafe {
            EC_POINT_oct2point(
                group,
                point,
                pub_bytes.as_ptr(),
                pub_bytes.len(),
                core::ptr::null_mut(),
            )
        };
        if rc != 1 {
            unsafe {
                EC_POINT_free(point);
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_POINT_oct2point" });
        }

        // SAFETY: key is valid, point is a valid decoded public point.
        // EC_KEY_set_public_key copies the point, so we can free it after.
        let rc = unsafe { EC_KEY_set_public_key(key, point) };
        unsafe { EC_POINT_free(point) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_public_key" });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            group,
            _curve: PhantomData,
        })
    }

    /// Construct a signing key from raw private-key scalar bytes only.
    ///
    /// The public key is computed via EC point multiplication (pub = priv * G).
    /// `priv_bytes` is the big-endian encoding of the private scalar.
    pub fn from_private_key_bytes(priv_bytes: &[u8]) -> Result<Self, WolfCryptError> {
        // SAFETY: EC_GROUP_new_by_curve_name returns null on failure.
        let group = unsafe { EC_GROUP_new_by_curve_name(C::NID) };
        if group.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: EC_KEY_new returns null on failure.
        let key = unsafe { EC_KEY_new() };
        if key.is_null() {
            unsafe { EC_GROUP_free(group) };
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: key and group are valid non-null pointers.
        let rc = unsafe { EC_KEY_set_group(key, group) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_group" });
        }

        // --- Import the private key scalar ---
        let priv_bn = unsafe {
            BN_bin2bn(
                priv_bytes.as_ptr(),
                len_as_c_int(priv_bytes.len()),
                core::ptr::null_mut(),
            )
        };
        if priv_bn.is_null() {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        let rc = unsafe { EC_KEY_set_private_key(key, priv_bn) };
        if rc != 1 {
            unsafe {
                BN_free(priv_bn);
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_private_key" });
        }

        // --- Compute public key: pub = priv * G ---
        let point = unsafe { EC_POINT_new(group) };
        if point.is_null() {
            unsafe {
                BN_free(priv_bn);
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: EC_POINT_mul(group, result, n, NULL, NULL, NULL) computes result = n * G.
        let rc = unsafe {
            EC_POINT_mul(
                group,
                point,
                priv_bn,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };
        unsafe { BN_free(priv_bn) };
        if rc != 1 {
            unsafe {
                EC_POINT_free(point);
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_POINT_mul" });
        }

        // SAFETY: key is valid, point is the computed public point.
        let rc = unsafe { EC_KEY_set_public_key(key, point) };
        unsafe { EC_POINT_free(point) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_public_key" });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            group,
            _curve: PhantomData,
        })
    }

    /// Sign pre-hashed data directly, skipping the internal hashing step.
    ///
    /// `hash` must be exactly `C::HASH_LEN` bytes (the output of the
    /// curve's canonical digest). Returns `WolfCryptError::InvalidInput`
    /// if the length is wrong.
    pub fn sign_prehash(
        &self,
        hash: &[u8],
    ) -> Result<EcdsaSignature<C>, WolfCryptError> {
        if hash.len() != C::HASH_LEN {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        let key = unsafe { *self.key.get() };

        // SAFETY: hash is HASH_LEN bytes, key is a valid EC_KEY with
        // private + public components. ECDSA_do_sign returns null on failure.
        let sig = unsafe {
            ECDSA_do_sign(hash.as_ptr(), len_as_c_int(hash.len()), key)
        };
        if sig.is_null() {
            return Err(WolfCryptError::Ffi { code: 0, func: "ECDSA_do_sign" });
        }

        // Extract r and s as BIGNUMs (internal pointers — do NOT free).
        let mut r_ptr: *const BIGNUM = core::ptr::null();
        let mut s_ptr: *const BIGNUM = core::ptr::null();

        // SAFETY: sig is a valid ECDSA_SIG. get0 writes internal pointers
        // to r_ptr and s_ptr. These are borrowed and must not be freed.
        unsafe { ECDSA_SIG_get0(sig, &mut r_ptr, &mut s_ptr) };

        // Convert to fixed-size bytes.
        let r_bytes = unsafe { bn_to_fixed_bytes(r_ptr, C::FIELD_SIZE) };
        let s_bytes = unsafe { bn_to_fixed_bytes(s_ptr, C::FIELD_SIZE) };

        // SAFETY: sig was allocated by ECDSA_do_sign; free it now.
        unsafe { ECDSA_SIG_free(sig) };

        let mut combined = GenericArray::<u8, C::SigSize>::default();
        combined[..C::FIELD_SIZE].copy_from_slice(&r_bytes);
        combined[C::FIELD_SIZE..].copy_from_slice(&s_bytes);

        Ok(EcdsaSignature {
            bytes: combined,
            _curve: PhantomData,
        })
    }
}

impl<C: EcdsaCurve> Drop for EcdsaSigningKey<C> {
    fn drop(&mut self) {
        // SAFETY: key and group were successfully allocated during
        // construction. Free key first (it references the group internally),
        // then group. Each is freed exactly once.
        unsafe {
            EC_KEY_free(*self.key.get_mut());
            EC_GROUP_free(self.group);
        }
    }
}

impl<C: EcdsaCurve> signature_trait::Signer<EcdsaSignature<C>> for EcdsaSigningKey<C> {
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<EcdsaSignature<C>, signature_trait::Error> {
        let hash = hash_message::<C>(msg).map_err(|_| signature_trait::Error::new())?;
        let key = unsafe { *self.key.get() };

        // SAFETY: hash is HASH_LEN bytes, key is a valid EC_KEY with
        // private + public components. ECDSA_do_sign returns null on failure.
        let sig = unsafe {
            ECDSA_do_sign(hash.as_ptr(), len_as_c_int(hash.len()), key)
        };
        if sig.is_null() {
            return Err(signature_trait::Error::new());
        }

        // Extract r and s as BIGNUMs (internal pointers — do NOT free).
        let mut r_ptr: *const BIGNUM = core::ptr::null();
        let mut s_ptr: *const BIGNUM = core::ptr::null();

        // SAFETY: sig is a valid ECDSA_SIG. get0 writes internal pointers
        // to r_ptr and s_ptr. These are borrowed and must not be freed.
        unsafe { ECDSA_SIG_get0(sig, &mut r_ptr, &mut s_ptr) };

        // Convert to fixed-size bytes.
        let r_bytes = unsafe { bn_to_fixed_bytes(r_ptr, C::FIELD_SIZE) };
        let s_bytes = unsafe { bn_to_fixed_bytes(s_ptr, C::FIELD_SIZE) };

        // SAFETY: sig was allocated by ECDSA_do_sign; free it now.
        unsafe { ECDSA_SIG_free(sig) };

        let mut combined = GenericArray::<u8, C::SigSize>::default();
        combined[..C::FIELD_SIZE].copy_from_slice(&r_bytes);
        combined[C::FIELD_SIZE..].copy_from_slice(&s_bytes);

        Ok(EcdsaSignature {
            bytes: combined,
            _curve: PhantomData,
        })
    }
}

// ============================================================
// EcdsaVerifyingKey<C>
// ============================================================

/// An ECDSA verifying key (public key) backed by wolfCrypt's OpenSSL compat
/// layer.
///
/// Parameterized by curve: use [`P256`] or [`P384`].
pub struct EcdsaVerifyingKey<C: EcdsaCurve> {
    /// Heap-allocated EC_KEY (public-only).
    ///
    /// `UnsafeCell` around the pointer: same rationale as
    /// [`EcdsaSigningKey::key`] — provides `!Sync`.
    key: UnsafeCell<*mut EC_KEY>,
    /// Heap-allocated EC_GROUP (owned; freed on drop).
    group: *mut EC_GROUP,
    /// Cached uncompressed public point bytes for cheap access.
    pub_bytes: Vec<u8>,
    _curve: PhantomData<C>,
}

// SAFETY: EC_KEY and EC_GROUP own independent heap state; safe to send.
unsafe impl<C: EcdsaCurve> Send for EcdsaVerifyingKey<C> {}

impl<C: EcdsaCurve> EcdsaVerifyingKey<C> {
    /// Construct a verifying key from an uncompressed public point
    /// (0x04 || x || y).
    ///
    /// The `bytes` slice must be exactly `C::UNCOMPRESSED_POINT_SIZE` bytes.
    pub fn from_uncompressed_point(bytes: &[u8]) -> Result<Self, WolfCryptError> {
        if bytes.len() != C::UNCOMPRESSED_POINT_SIZE {
            return Err(WolfCryptError::INVALID_INPUT);
        }
        if bytes[0] != 0x04 {
            return Err(WolfCryptError::INVALID_INPUT);
        }

        // SAFETY: EC_GROUP_new_by_curve_name returns null on failure.
        let group = unsafe { EC_GROUP_new_by_curve_name(C::NID) };
        if group.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: EC_KEY_new returns null on failure.
        let key = unsafe { EC_KEY_new() };
        if key.is_null() {
            unsafe { EC_GROUP_free(group) };
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: key and group are valid.
        let rc = unsafe { EC_KEY_set_group(key, group) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_group" });
        }

        // Create a temporary EC_POINT and decode the uncompressed bytes.
        // SAFETY: group is valid; EC_POINT_new returns null on failure.
        let point = unsafe { EC_POINT_new(group) };
        if point.is_null() {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: group and point are valid. bytes is the correct length.
        let rc = unsafe {
            EC_POINT_oct2point(
                group,
                point,
                bytes.as_ptr(),
                bytes.len(),
                core::ptr::null_mut(),
            )
        };
        if rc != 1 {
            unsafe {
                EC_POINT_free(point);
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_POINT_oct2point" });
        }

        // SAFETY: key is valid, point is a valid decoded public point.
        // EC_KEY_set_public_key copies the point, so we can free it after.
        let rc = unsafe { EC_KEY_set_public_key(key, point) };
        unsafe { EC_POINT_free(point) };
        if rc != 1 {
            unsafe {
                EC_KEY_free(key);
                EC_GROUP_free(group);
            }
            return Err(WolfCryptError::Ffi { code: rc, func: "EC_KEY_set_public_key" });
        }

        Ok(Self {
            key: UnsafeCell::new(key),
            group,
            pub_bytes: bytes.to_vec(),
            _curve: PhantomData,
        })
    }

    /// Return the uncompressed public point bytes (0x04 || x || y).
    pub fn as_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }
}

impl<C: EcdsaCurve> Drop for EcdsaVerifyingKey<C> {
    fn drop(&mut self) {
        // SAFETY: key and group were successfully allocated during
        // construction. Freed exactly once, key before group.
        unsafe {
            EC_KEY_free(*self.key.get_mut());
            EC_GROUP_free(self.group);
        }
    }
}

impl<C: EcdsaCurve> signature_trait::Verifier<EcdsaSignature<C>> for EcdsaVerifyingKey<C> {
    fn verify(
        &self,
        msg: &[u8],
        signature: &EcdsaSignature<C>,
    ) -> Result<(), signature_trait::Error> {
        let hash = hash_message::<C>(msg).map_err(|_| signature_trait::Error::new())?;
        let key = unsafe { *self.key.get() };

        // Parse r and s from the fixed-size signature.
        let r_bytes = signature.r_bytes();
        let s_bytes = signature.s_bytes();

        // SAFETY: BN_bin2bn creates a new BIGNUM from big-endian bytes.
        // Passing null as ret allocates a fresh BIGNUM.
        let r_bn = unsafe {
            BN_bin2bn(r_bytes.as_ptr(), len_as_c_int(r_bytes.len()), core::ptr::null_mut())
        };
        if r_bn.is_null() {
            return Err(signature_trait::Error::new());
        }

        let s_bn = unsafe {
            BN_bin2bn(s_bytes.as_ptr(), len_as_c_int(s_bytes.len()), core::ptr::null_mut())
        };
        if s_bn.is_null() {
            unsafe { BN_free(r_bn) };
            return Err(signature_trait::Error::new());
        }

        // SAFETY: ECDSA_SIG_new allocates a new ECDSA_SIG.
        let sig = unsafe { ECDSA_SIG_new() };
        if sig.is_null() {
            unsafe {
                BN_free(r_bn);
                BN_free(s_bn);
            }
            return Err(signature_trait::Error::new());
        }

        // SAFETY: ECDSA_SIG_set0 takes ownership of r_bn and s_bn.
        // After this call, do NOT free r_bn or s_bn — they belong to sig.
        let rc = unsafe { ECDSA_SIG_set0(sig, r_bn, s_bn) };
        if rc != 1 {
            // set0 failed; sig did NOT take ownership, so free everything.
            unsafe {
                BN_free(r_bn);
                BN_free(s_bn);
                ECDSA_SIG_free(sig);
            }
            return Err(signature_trait::Error::new());
        }

        // SAFETY: hash is HASH_LEN bytes, sig is valid, key is valid.
        // ECDSA_do_verify returns 1 on success, 0 or negative on failure.
        let result = unsafe {
            ECDSA_do_verify(hash.as_ptr(), len_as_c_int(hash.len()), sig, key)
        };

        // SAFETY: sig was allocated by ECDSA_SIG_new and owns r_bn/s_bn.
        unsafe { ECDSA_SIG_free(sig) };

        if result == 1 {
            Ok(())
        } else {
            Err(signature_trait::Error::new())
        }
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
#[cfg(wolfssl_ecc_p521)]
pub type P521SigningKey = EcdsaSigningKey<P521>;
/// P-521 ECDSA verifying key.
#[cfg(wolfssl_ecc_p521)]
pub type P521VerifyingKey = EcdsaVerifyingKey<P521>;
/// P-521 ECDSA signature.
#[cfg(wolfssl_ecc_p521)]
pub type P521Signature = EcdsaSignature<P521>;
