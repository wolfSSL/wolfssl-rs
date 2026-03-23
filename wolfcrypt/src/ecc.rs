//! Generic ECC operations with runtime curve selection, backed by wolfCrypt.
//!
//! This module wraps wolfCrypt's native `ecc_key` API, providing runtime curve
//! selection via [`EccCurveId`].  It is intentionally separate from the
//! [`crate::ecdsa`] and [`crate::ecdh`] modules, which use the OpenSSL
//! compatibility layer and are statically typed by curve.
//!
//! # Example
//!
//! ```no_run
//! use wolfcrypt::ecc::{EccCurveId, EccKey};
//! use wolfcrypt::rand::WolfRng;
//!
//! let mut rng = WolfRng::new().unwrap();
//! let mut alice = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();
//! let mut bob   = EccKey::generate(EccCurveId::SecP256R1, &mut rng).unwrap();
//!
//! let shared_a = alice.ecdh_shared_secret(&mut bob).unwrap();
//! let shared_b = bob.ecdh_shared_secret(&mut alice).unwrap();
//! assert_eq!(shared_a, shared_b);
//! ```

#![cfg(wolfssl_ecc)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;

use crate::error::{check, len_as_u32, WolfCryptError};
use crate::rand::WolfRng;
use wolfcrypt_rs::{
    wc_ecc_check_key, wc_ecc_export_private_only, wc_ecc_export_x963,
    wc_ecc_get_curve_size_from_id, wc_ecc_import_private_key,
    wc_ecc_import_private_key_ex, wc_ecc_import_x963,
    wc_ecc_init_ex, wc_ecc_key_free, wc_ecc_key_new, wc_ecc_make_key_ex,
    wc_ecc_shared_secret, wc_ecc_sign_hash, wc_ecc_verify_hash,
    ECC_SECP256K1, ECC_SECP256R1, ECC_SECP384R1, ECC_SECP521R1,
    wc_ecc_key,
};

/// Supported ECC curve IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EccCurveId {
    /// NIST P-256 (secp256r1).
    SecP256R1 = ECC_SECP256R1,
    /// NIST P-384 (secp384r1).
    SecP384R1 = ECC_SECP384R1,
    /// NIST P-521 (secp521r1).
    SecP521R1 = ECC_SECP521R1,
    /// secp256k1 (Bitcoin curve).
    SecP256K1 = ECC_SECP256K1,
}

/// Maximum size of an uncompressed X9.63 public key (1 + 2*66 for P-521).
const MAX_X963_PUB_SIZE: usize = 133;

/// Maximum size of a DER-encoded ECDSA signature.
///
/// For P-521 the worst case is: 2 (SEQUENCE header) + 2*(2 + 66 + 1) = 140.
/// We round up generously.
const MAX_DER_SIG_SIZE: usize = 256;

/// Maximum private key size in bytes (P-521 = 66 bytes).
const MAX_PRIV_KEY_SIZE: usize = 66;

/// Maximum shared-secret size in bytes (P-521 = 66 bytes).
const MAX_SHARED_SECRET_SIZE: usize = 66;

/// An ECC key (public, private, or both) backed by wolfCrypt's native
/// `ecc_key` struct.
///
/// The key is heap-allocated by `wc_ecc_key_new` and freed by
/// `wc_ecc_key_free` on drop.
pub struct EccKey {
    key: *mut wc_ecc_key,
}

// SAFETY: `wc_ecc_key` owns independent state with no shared mutable globals
// or thread-local storage, so the struct can safely be moved between threads.
unsafe impl Send for EccKey {}

impl EccKey {
    /// Allocate and initialise a new `wc_ecc_key`.
    ///
    /// Returns a valid, initialised key pointer or an error.
    fn alloc_and_init() -> Result<*mut wc_ecc_key, WolfCryptError> {
        // SAFETY: NULL heap → use default allocator.
        let key = unsafe { wc_ecc_key_new(ptr::null_mut()) };
        if key.is_null() {
            return Err(WolfCryptError::AllocFailed);
        }

        // SAFETY: `key` is non-null and freshly allocated.  NULL heap, -1
        // devId (INVALID_DEVID) → software-only.
        let rc = unsafe { wc_ecc_init_ex(key, ptr::null_mut(), -1) };
        if rc != 0 {
            // Init failed — free the allocation before returning.
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_ecc_init_ex",
            });
        }

        Ok(key)
    }

    /// Generate a new ECC keypair on the given `curve`.
    pub fn generate(curve: EccCurveId, rng: &mut WolfRng) -> Result<Self, WolfCryptError> {
        let key = Self::alloc_and_init()?;

        // Determine the key size in bytes from the curve ID.
        let key_size = unsafe { wc_ecc_get_curve_size_from_id(curve as i32) };
        if key_size <= 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: `key` is initialised.  `rng.rng` is a valid WC_RNG.
        let rc = unsafe {
            wc_ecc_make_key_ex(&mut rng.rng, key_size, key, curve as i32)
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_ecc_make_key_ex",
            });
        }

        Ok(Self { key })
    }

    /// Import a key from raw private and X9.63-encoded public components.
    ///
    /// `pub_key` must be in uncompressed X9.63 format (0x04 || x || y).
    /// `priv_key` is the raw big-endian private scalar.
    pub fn from_private_and_public(
        _curve: EccCurveId,
        priv_key: &[u8],
        pub_key: &[u8],
    ) -> Result<Self, WolfCryptError> {
        let key = Self::alloc_and_init()?;

        // SAFETY: `key` is initialised.  `priv_key` and `pub_key` are valid
        // slices.  wolfCrypt deduces the curve from the public key encoding.
        let rc = unsafe {
            wc_ecc_import_private_key(
                priv_key.as_ptr(),
                len_as_u32(priv_key.len()),
                pub_key.as_ptr(),
                len_as_u32(pub_key.len()),
                key,
            )
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_ecc_import_private_key",
            });
        }

        Ok(Self { key })
    }

    /// Import a private-only key from raw big-endian scalar bytes.
    ///
    /// wolfCrypt derives the public point internally (pub = priv * G),
    /// so only the private scalar and curve ID are needed.
    pub fn from_private(
        curve: EccCurveId,
        priv_key: &[u8],
    ) -> Result<Self, WolfCryptError> {
        let key = Self::alloc_and_init()?;

        // Pass NULL/0 for the public key — wolfCrypt will compute it
        // from the private scalar using the curve's generator point.
        let rc = unsafe {
            wc_ecc_import_private_key_ex(
                priv_key.as_ptr(),
                len_as_u32(priv_key.len()),
                ptr::null(),
                0,
                key,
                curve as i32,
            )
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_ecc_import_private_key_ex",
            });
        }

        Ok(Self { key })
    }

    /// Import a public-only key from X9.63 uncompressed format.
    pub fn from_public_x963(pub_key: &[u8]) -> Result<Self, WolfCryptError> {
        let key = Self::alloc_and_init()?;

        // SAFETY: `key` is initialised.  `pub_key` is a valid slice.
        let rc = unsafe {
            wc_ecc_import_x963(pub_key.as_ptr(), len_as_u32(pub_key.len()), key)
        };
        if rc != 0 {
            unsafe { wc_ecc_key_free(key) };
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_ecc_import_x963",
            });
        }

        Ok(Self { key })
    }

    /// Export the public key in X9.63 uncompressed format (0x04 || x || y).
    pub fn export_public_x963(&self) -> Result<Vec<u8>, WolfCryptError> {
        let mut buf = vec![0u8; MAX_X963_PUB_SIZE];
        let mut out_len: u32 = buf.len() as u32;

        // SAFETY: `self.key` is a valid, initialised key.  `buf` is large
        // enough for any supported curve.  `out_len` receives the actual size.
        let rc = unsafe {
            wc_ecc_export_x963(self.key, buf.as_mut_ptr(), &mut out_len)
        };
        check(rc, "wc_ecc_export_x963")?;

        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Export the raw private scalar as a big-endian byte string.
    pub fn export_private(&self) -> Result<Vec<u8>, WolfCryptError> {
        let mut buf = vec![0u8; MAX_PRIV_KEY_SIZE];
        let mut out_len: u32 = buf.len() as u32;

        // SAFETY: `self.key` is a valid key with a private component.
        let rc = unsafe {
            wc_ecc_export_private_only(self.key, buf.as_mut_ptr(), &mut out_len)
        };
        check(rc, "wc_ecc_export_private_only")?;

        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Compute an ECDH shared secret with `peer`.
    ///
    /// `self` must hold a private key and `peer` must hold a public key
    /// (or both may be full keypairs).
    pub fn ecdh_shared_secret(&mut self, peer: &mut EccKey) -> Result<Vec<u8>, WolfCryptError> {
        let mut buf = vec![0u8; MAX_SHARED_SECRET_SIZE];
        let mut out_len: u32 = buf.len() as u32;

        // SAFETY: both keys are valid and initialised.
        let rc = unsafe {
            wc_ecc_shared_secret(self.key, peer.key, buf.as_mut_ptr(), &mut out_len)
        };
        check(rc, "wc_ecc_shared_secret")?;

        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Sign a message hash with this key's private component.
    ///
    /// Returns a DER-encoded ECDSA signature.
    pub fn sign_hash(
        &mut self,
        hash: &[u8],
        rng: &mut WolfRng,
    ) -> Result<Vec<u8>, WolfCryptError> {
        let mut buf = vec![0u8; MAX_DER_SIG_SIZE];
        let mut out_len: u32 = buf.len() as u32;

        // SAFETY: `self.key` holds a private key.  `rng.rng` is a valid
        // WC_RNG.  `hash` is the digest to sign.
        let rc = unsafe {
            wc_ecc_sign_hash(
                hash.as_ptr(),
                len_as_u32(hash.len()),
                buf.as_mut_ptr(),
                &mut out_len,
                &mut rng.rng,
                self.key,
            )
        };
        check(rc, "wc_ecc_sign_hash")?;

        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Verify a DER-encoded ECDSA signature against a message hash.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
    /// well-formed but does not match, or `Err` on structural/parsing errors.
    pub fn verify_hash(&mut self, sig: &[u8], hash: &[u8]) -> Result<bool, WolfCryptError> {
        let mut result: i32 = 0;

        // SAFETY: `self.key` holds a public key.  `sig` and `hash` are valid
        // slices.  `result` receives 1 if valid, 0 otherwise.
        let rc = unsafe {
            wc_ecc_verify_hash(
                sig.as_ptr(),
                len_as_u32(sig.len()),
                hash.as_ptr(),
                len_as_u32(hash.len()),
                &mut result,
                self.key,
            )
        };
        check(rc, "wc_ecc_verify_hash")?;

        Ok(result == 1)
    }

    /// Validate that this key's components are consistent and on the curve.
    pub fn check_key(&mut self) -> Result<(), WolfCryptError> {
        // SAFETY: `self.key` is a valid, initialised key.
        let rc = unsafe { wc_ecc_check_key(self.key) };
        check(rc, "wc_ecc_check_key")
    }
}

impl Drop for EccKey {
    fn drop(&mut self) {
        // SAFETY: `self.key` was allocated by `wc_ecc_key_new` and initialised
        // by `wc_ecc_init_ex` during construction.  `wc_ecc_key_free` frees
        // the key material and deallocates the struct.
        if !self.key.is_null() {
            unsafe { wc_ecc_key_free(self.key) };
        }
    }
}

// -----------------------------------------------------------------------
// DER ↔ raw (r, s) signature conversion helpers
// -----------------------------------------------------------------------

/// Convert a DER-encoded ECDSA signature to raw (r, s) byte arrays.
///
/// Returns `(r, s)` where each is a big-endian unsigned integer with no
/// leading zeros stripped (wolfSSL handles padding).
pub fn ecc_sig_der_to_rs(
    der_sig: &[u8],
) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), WolfCryptError> {
    // Max ECC field size is 66 bytes (P-521). Each component can't exceed that.
    let mut r = [0u8; 66];
    let mut s = [0u8; 66];
    let mut r_len = r.len() as u32;
    let mut s_len = s.len() as u32;

    let rc = unsafe {
        wolfcrypt_rs::wc_ecc_sig_to_rs(
            der_sig.as_ptr(),
            len_as_u32(der_sig.len()),
            r.as_mut_ptr(),
            &mut r_len,
            s.as_mut_ptr(),
            &mut s_len,
        )
    };
    check(rc, "wc_ecc_sig_to_rs")?;

    Ok((r[..r_len as usize].to_vec(), s[..s_len as usize].to_vec()))
}

/// Convert raw (r, s) byte arrays to a DER-encoded ECDSA signature.
pub fn ecc_sig_rs_to_der(
    r: &[u8],
    s: &[u8],
) -> Result<alloc::vec::Vec<u8>, WolfCryptError> {
    // Max DER signature: ~140 bytes for P-521 (SEQUENCE { INTEGER(66+1), INTEGER(66+1) } + overhead)
    let mut out = [0u8; 144];
    let mut out_len = out.len() as u32;

    let rc = unsafe {
        wolfcrypt_rs::wc_ecc_rs_raw_to_sig(
            r.as_ptr(),
            len_as_u32(r.len()),
            s.as_ptr(),
            len_as_u32(s.len()),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    check(rc, "wc_ecc_rs_raw_to_sig")?;

    Ok(out[..out_len as usize].to_vec())
}
