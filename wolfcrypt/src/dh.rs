//! Classic Diffie-Hellman key agreement using FFDHE named groups (RFC 7919).
//!
//! Provides [`DhSecret`] for generating DH key pairs and computing shared
//! secrets over predefined finite-field groups (FFDHE2048, FFDHE3072,
//! FFDHE4096).
//!
//! There is no standard RustCrypto trait for classic DH, so this module
//! exposes a custom API backed by wolfCrypt's native wc_Dh* functions.
//!
//! Gated on `cfg(wolfssl_dh)`.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::WolfCryptError;

// Named-group constants match wolfssl/wolfcrypt/dh.h WC_FFDHE_* enum.
const WC_FFDHE_2048: i32 = 256;
const WC_FFDHE_3072: i32 = 257;
const WC_FFDHE_4096: i32 = 258;

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
    fn wc_name(self) -> i32 {
        match self {
            FfdheGroup::Ffdhe2048 => WC_FFDHE_2048,
            FfdheGroup::Ffdhe3072 => WC_FFDHE_3072,
            FfdheGroup::Ffdhe4096 => WC_FFDHE_4096,
        }
    }

    fn byte_size(self) -> usize {
        match self {
            FfdheGroup::Ffdhe2048 => 256,
            FfdheGroup::Ffdhe3072 => 384,
            FfdheGroup::Ffdhe4096 => 512,
        }
    }
}

/// A DH key pair for classic Diffie-Hellman key exchange.
///
/// Wraps a heap-allocated wolfCrypt `DhKey` context managed by C shims in
/// `compat_shim.c`.  The private and public key components are generated
/// inside wolfCrypt and never exposed directly.
pub struct DhSecret {
    ctx: *mut core::ffi::c_void,
    group_sz: usize,
}

// SAFETY: The DhKey context is heap-allocated and self-contained.
unsafe impl Send for DhSecret {}

impl Drop for DhSecret {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: ctx was allocated by wolfcrypt_dh_new.
            unsafe { wolfcrypt_rs::wolfcrypt_dh_free(self.ctx) };
        }
    }
}

impl DhSecret {
    /// Generate a new DH key pair using the specified FFDHE group.
    pub fn generate(group: FfdheGroup) -> Result<Self, WolfCryptError> {
        // SAFETY: wolfcrypt_dh_new allocates a DhKey, initialises it with the
        // named group, and returns NULL on any error.
        let ctx = unsafe {
            wolfcrypt_rs::wolfcrypt_dh_new(group.wc_name(), group.byte_size() as u32)
        };
        if ctx.is_null() {
            return Err(WolfCryptError::ALLOC_FAILED);
        }

        // SAFETY: ctx is a valid, fully-parametrised DhKey context.
        let rc = unsafe { wolfcrypt_rs::wolfcrypt_dh_generate_keypair(ctx) };
        if rc != 0 {
            unsafe { wolfcrypt_rs::wolfcrypt_dh_free(ctx) };
            return Err(WolfCryptError::Ffi { code: rc, func: "wolfcrypt_dh_generate_keypair" });
        }

        Ok(Self { ctx, group_sz: group.byte_size() })
    }

    /// Generate a DH key pair using FFDHE2048 (convenience wrapper).
    pub fn generate_ffdhe2048() -> Result<Self, WolfCryptError> {
        Self::generate(FfdheGroup::Ffdhe2048)
    }

    /// Return the public key as big-endian bytes, zero-padded to the group size.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.group_sz];
        let mut len = self.group_sz as u32;
        // SAFETY: buf is group_sz bytes, which is the declared output size.
        let rc = unsafe {
            wolfcrypt_rs::wolfcrypt_dh_public_key(self.ctx, buf.as_mut_ptr(), &mut len)
        };
        assert_eq!(rc, 0, "wolfcrypt_dh_public_key failed");
        buf.truncate(len as usize);
        buf
    }

    /// Return the DH parameter size in bytes (size of the shared secret).
    pub fn size(&self) -> usize {
        self.group_sz
    }

    /// Compute the shared secret given the peer's public key bytes (big-endian).
    ///
    /// Takes `&self` (not `self`) because classic DH keys are commonly reused
    /// across multiple peers — unlike ECDH ephemeral keys, which are consumed
    /// after a single exchange.
    ///
    /// Returns the shared secret wrapped in `Zeroizing` so the key material
    /// is automatically zeroized on drop.  The output is always padded to
    /// the group size to avoid timing side-channels from variable-length results.
    pub fn compute_shared_secret(
        &self,
        peer_pub_bytes: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, WolfCryptError> {
        let mut secret = vec![0u8; self.group_sz];
        let mut sz = self.group_sz as u32;

        // SAFETY: peer_pub_bytes is a valid slice; secret is group_sz bytes.
        let rc = unsafe {
            wolfcrypt_rs::wolfcrypt_dh_agree(
                self.ctx,
                peer_pub_bytes.as_ptr(),
                peer_pub_bytes.len() as u32,
                secret.as_mut_ptr(),
                &mut sz,
            )
        };

        if rc != 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "wolfcrypt_dh_agree" });
        }

        secret.truncate(sz as usize);
        Ok(zeroize::Zeroizing::new(secret))
    }
}
