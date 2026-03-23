//! Classic Diffie-Hellman key agreement using FFDHE named groups (RFC 7919).
//!
//! Provides [`DhSecret`] for generating DH key pairs and computing shared
//! secrets over predefined finite-field groups (FFDHE2048, FFDHE3072,
//! FFDHE4096).
//!
//! There is no standard RustCrypto trait for classic DH, so this module
//! exposes a custom API backed by wolfSSL's OpenSSL-compatible DH functions.
//!
//! Gated on `cfg(wolfssl_openssl_extra)` and `cfg(wolfssl_dh)`.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_int;

use crate::error::{len_as_c_int, WolfCryptError};

/// Predefined FFDHE group selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfdheGroup {
    /// FFDHE2048 (RFC 7919) — 2048-bit prime.
    Ffdhe2048,
    /// FFDHE3072 (RFC 7919) — 3072-bit prime.
    Ffdhe3072,
    /// FFDHE4096 (RFC 7919) — 4096-bit prime.
    Ffdhe4096,
}

impl FfdheGroup {
    fn nid(self) -> c_int {
        match self {
            FfdheGroup::Ffdhe2048 => wolfcrypt_rs::NID_ffdhe2048,
            FfdheGroup::Ffdhe3072 => wolfcrypt_rs::NID_ffdhe3072,
            FfdheGroup::Ffdhe4096 => wolfcrypt_rs::NID_ffdhe4096,
        }
    }
}

/// A DH key pair for classic Diffie-Hellman key exchange.
///
/// Wraps a heap-allocated wolfSSL `DH` structure. The private and public
/// key components are generated inside wolfSSL.
pub struct DhSecret {
    dh: *mut wolfcrypt_rs::DH,
}

// SAFETY: The DH struct is heap-allocated and self-contained; it is safe to
// move ownership to another thread.
unsafe impl Send for DhSecret {}

impl Drop for DhSecret {
    fn drop(&mut self) {
        if !self.dh.is_null() {
            // SAFETY: `self.dh` was allocated by `DH_new_by_nid` and is non-null.
            unsafe { wolfcrypt_rs::DH_free(self.dh) };
        }
    }
}

impl DhSecret {
    /// Generate a new DH key pair using the specified FFDHE group.
    ///
    /// Calls `DH_new_by_nid` to load the named group parameters, then
    /// `DH_generate_key` to produce a fresh private/public key pair.
    pub fn generate(group: FfdheGroup) -> Result<Self, WolfCryptError> {
        // SAFETY: `DH_new_by_nid` returns a heap-allocated DH or NULL on error.
        let dh = unsafe { wolfcrypt_rs::DH_new_by_nid(group.nid()) };
        if dh.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: `dh` is a valid, fully-parametrized DH structure.
        // `DH_generate_key` returns 1 on success (OpenSSL convention).
        let rc = unsafe { wolfcrypt_rs::DH_generate_key(dh) };
        if rc != 1 {
            unsafe { wolfcrypt_rs::DH_free(dh) };
            return Err(WolfCryptError::Ffi { code: rc, func: "DH_generate_key" });
        }

        Ok(Self { dh })
    }

    /// Generate a DH key pair using FFDHE2048 (convenience wrapper).
    pub fn generate_ffdhe2048() -> Result<Self, WolfCryptError> {
        Self::generate(FfdheGroup::Ffdhe2048)
    }

    /// Return the public key as big-endian bytes.
    ///
    /// Allocates a `Vec` because the internal BIGNUM is owned by the DH
    /// struct and cannot be borrowed out.  The cost is negligible next to
    /// the modular exponentiation in `generate`.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut pub_key: *const wolfcrypt_rs::BIGNUM = core::ptr::null();
        // SAFETY: `self.dh` was successfully generated. `DH_get0_key` writes
        // internal pointers (not copies) into the out-params. We only read
        // `pub_key`; `priv_key` is ignored via NULL.
        unsafe {
            wolfcrypt_rs::DH_get0_key(
                self.dh as *const wolfcrypt_rs::DH,
                &mut pub_key,
                core::ptr::null_mut(),
            );
        }
        assert!(!pub_key.is_null(), "DH_get0_key returned null pub_key");

        // SAFETY: `pub_key` is a valid BIGNUM owned by the DH struct.
        let len = unsafe { wolfcrypt_rs::BN_num_bytes(pub_key) } as usize;
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` is `len` bytes, which is the correct size for this BIGNUM.
        unsafe { wolfcrypt_rs::BN_bn2bin(pub_key, buf.as_mut_ptr()) };
        buf
    }

    /// Return the DH parameter size in bytes (size of the shared secret).
    pub fn size(&self) -> usize {
        // SAFETY: `self.dh` is a valid DH structure.
        let s = unsafe { wolfcrypt_rs::DH_size(self.dh) };
        s as usize
    }

    /// Compute the shared secret given the peer's public key bytes (big-endian).
    ///
    /// Takes `&self` (not `self`) because classic DH keys are commonly reused
    /// across multiple peers — unlike ECDH ephemeral keys, which are consumed
    /// after a single exchange.
    ///
    /// Returns the shared secret wrapped in `Zeroizing` so the key material
    /// is automatically zeroized on drop. Uses `DH_compute_key_padded`
    /// to produce a fixed-length output (padded to the DH size), which avoids
    /// timing side-channels from variable-length results.
    pub fn compute_shared_secret(&self, peer_pub_bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, WolfCryptError> {
        // Convert peer public key bytes to BIGNUM.
        // SAFETY: `BN_bin2bn` with NULL `ret` allocates a new BIGNUM.
        let peer_bn = unsafe {
            wolfcrypt_rs::BN_bin2bn(
                peer_pub_bytes.as_ptr(),
                len_as_c_int(peer_pub_bytes.len()),
                core::ptr::null_mut(),
            )
        };
        if peer_bn.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        let dh_size = self.size();
        let mut secret = vec![0u8; dh_size];

        // SAFETY: `secret` has `dh_size` bytes, `peer_bn` is a valid BIGNUM,
        // and `self.dh` holds a generated key pair. `DH_compute_key_padded`
        // returns the number of bytes written (== dh_size) or -1 on error.
        let rc = unsafe {
            wolfcrypt_rs::DH_compute_key_padded(
                secret.as_mut_ptr(),
                peer_bn as *const wolfcrypt_rs::BIGNUM,
                self.dh,
            )
        };

        // Free the temporary BIGNUM regardless of outcome.
        unsafe { wolfcrypt_rs::BN_free(peer_bn) };

        if rc < 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "DH_compute_key_padded" });
        }

        // Truncate to actual length (should equal dh_size for padded variant).
        secret.truncate(rc as usize);
        Ok(zeroize::Zeroizing::new(secret))
    }
}
