//! Blake2b and Blake2s hash functions backed by wolfCrypt.
//!
//! Provides [`Blake2b`] and [`Blake2s`] with a bespoke (non-trait) streaming
//! API: [`new`](Blake2b::new) / [`new_keyed`](Blake2b::new_keyed) /
//! [`update`](Blake2b::update) / [`finalize`](Blake2b::finalize).
//!
//! Both types support variable output lengths:
//! - Blake2b: 1..=64 bytes
//! - Blake2s: 1..=32 bytes
//!
//! There is no standard RustCrypto trait for variable-output keyed hashes,
//! so these types expose a standalone API similar to [`crate::hkdf`].

#[cfg(any(wolfssl_blake2b, wolfssl_blake2s))]
use crate::error::{check, len_as_u32, WolfCryptError};
#[cfg(any(wolfssl_blake2b, wolfssl_blake2s))]
use alloc::vec::Vec;

// ============================================================
// Blake2b
// ============================================================

/// Blake2b hash function with variable output length (1..=64 bytes).
///
/// Wraps wolfCrypt's native `Blake2b` implementation.
///
/// # Examples
///
/// ```ignore
/// use wolfcrypt::blake2::Blake2b;
///
/// let mut hasher = Blake2b::new(32).unwrap();
/// hasher.update(b"hello world").unwrap();
/// let digest = hasher.finalize().unwrap();
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(wolfssl_blake2b)]
pub struct Blake2b {
    ctx: wolfcrypt_rs::WcBlake2b,
    digest_size: u32,
}

// SAFETY: WcBlake2b contains no thread-local state; it is safe to move
// the whole struct to another thread.
#[cfg(wolfssl_blake2b)]
unsafe impl Send for Blake2b {}

#[cfg(wolfssl_blake2b)]
impl Drop for Blake2b {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // SAFETY: WcBlake2b is repr(C); zeroing its raw bytes is safe.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2b as *mut u8,
                core::mem::size_of_val(&self.ctx),
            )
        };
        bytes.zeroize();
    }
}

#[cfg(wolfssl_blake2b)]
impl Blake2b {
    /// Maximum digest size in bytes (64).
    pub const MAX_DIGEST_SIZE: usize = 64;

    /// Create a new Blake2b hasher with the given output digest size.
    ///
    /// `digest_size` must be in `1..=64`.
    pub fn new(digest_size: usize) -> Result<Self, WolfCryptError> {
        if digest_size == 0 || digest_size > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        let mut ctx = wolfcrypt_rs::WcBlake2b::zeroed();
        let rc = unsafe {
            wolfcrypt_rs::wc_InitBlake2b(
                &mut ctx as *mut wolfcrypt_rs::WcBlake2b,
                digest_size as u32,
            )
        };
        check(rc, "wc_InitBlake2b")?;
        Ok(Self {
            ctx,
            digest_size: digest_size as u32,
        })
    }

    /// Create a new keyed Blake2b hasher (MAC mode).
    ///
    /// `key` may be up to 64 bytes.  `digest_size` must be in `1..=64`.
    pub fn new_keyed(key: &[u8], digest_size: usize) -> Result<Self, WolfCryptError> {
        if digest_size == 0 || digest_size > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        if key.is_empty() || key.len() > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        let mut ctx = wolfcrypt_rs::WcBlake2b::zeroed();
        let rc = unsafe {
            wolfcrypt_rs::wc_InitBlake2b_WithKey(
                &mut ctx as *mut wolfcrypt_rs::WcBlake2b,
                digest_size as u32,
                key.as_ptr(),
                len_as_u32(key.len()),
            )
        };
        check(rc, "wc_InitBlake2b_WithKey")?;
        Ok(Self {
            ctx,
            digest_size: digest_size as u32,
        })
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> Result<(), WolfCryptError> {
        if data.is_empty() {
            return Ok(());
        }
        let rc = unsafe {
            wolfcrypt_rs::wc_Blake2bUpdate(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2b,
                data.as_ptr(),
                len_as_u32(data.len()),
            )
        };
        check(rc, "wc_Blake2bUpdate")
    }

    /// Finalize the hash, consuming the hasher and returning the digest.
    pub fn finalize(mut self) -> Result<Vec<u8>, WolfCryptError> {
        let mut out = alloc::vec![0u8; self.digest_size as usize];
        let rc = unsafe {
            wolfcrypt_rs::wc_Blake2bFinal(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2b,
                out.as_mut_ptr(),
                self.digest_size,
            )
        };
        check(rc, "wc_Blake2bFinal")?;
        Ok(out)
    }
}

// ============================================================
// Blake2s
// ============================================================

/// Blake2s hash function with variable output length (1..=32 bytes).
///
/// Wraps wolfCrypt's native `Blake2s` implementation.
///
/// # Examples
///
/// ```ignore
/// use wolfcrypt::blake2::Blake2s;
///
/// let mut hasher = Blake2s::new(32).unwrap();
/// hasher.update(b"hello world").unwrap();
/// let digest = hasher.finalize().unwrap();
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(wolfssl_blake2s)]
pub struct Blake2s {
    ctx: wolfcrypt_rs::WcBlake2s,
    digest_size: u32,
}

// SAFETY: WcBlake2s contains no thread-local state; it is safe to move
// the whole struct to another thread.
#[cfg(wolfssl_blake2s)]
unsafe impl Send for Blake2s {}

#[cfg(wolfssl_blake2s)]
impl Drop for Blake2s {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // SAFETY: WcBlake2s is repr(C); zeroing its raw bytes is safe.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2s as *mut u8,
                core::mem::size_of_val(&self.ctx),
            )
        };
        bytes.zeroize();
    }
}

#[cfg(wolfssl_blake2s)]
impl Blake2s {
    /// Maximum digest size in bytes (32).
    pub const MAX_DIGEST_SIZE: usize = 32;

    /// Create a new Blake2s hasher with the given output digest size.
    ///
    /// `digest_size` must be in `1..=32`.
    pub fn new(digest_size: usize) -> Result<Self, WolfCryptError> {
        if digest_size == 0 || digest_size > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        let mut ctx = wolfcrypt_rs::WcBlake2s::zeroed();
        let rc = unsafe {
            wolfcrypt_rs::wc_InitBlake2s(
                &mut ctx as *mut wolfcrypt_rs::WcBlake2s,
                digest_size as u32,
            )
        };
        check(rc, "wc_InitBlake2s")?;
        Ok(Self {
            ctx,
            digest_size: digest_size as u32,
        })
    }

    /// Create a new keyed Blake2s hasher (MAC mode).
    ///
    /// `key` may be up to 32 bytes.  `digest_size` must be in `1..=32`.
    pub fn new_keyed(key: &[u8], digest_size: usize) -> Result<Self, WolfCryptError> {
        if digest_size == 0 || digest_size > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        if key.is_empty() || key.len() > Self::MAX_DIGEST_SIZE {
            return Err(WolfCryptError::InvalidInput);
        }
        let mut ctx = wolfcrypt_rs::WcBlake2s::zeroed();
        let rc = unsafe {
            wolfcrypt_rs::wc_InitBlake2s_WithKey(
                &mut ctx as *mut wolfcrypt_rs::WcBlake2s,
                digest_size as u32,
                key.as_ptr(),
                len_as_u32(key.len()),
            )
        };
        check(rc, "wc_InitBlake2s_WithKey")?;
        Ok(Self {
            ctx,
            digest_size: digest_size as u32,
        })
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> Result<(), WolfCryptError> {
        if data.is_empty() {
            return Ok(());
        }
        let rc = unsafe {
            wolfcrypt_rs::wc_Blake2sUpdate(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2s,
                data.as_ptr(),
                len_as_u32(data.len()),
            )
        };
        check(rc, "wc_Blake2sUpdate")
    }

    /// Finalize the hash, consuming the hasher and returning the digest.
    pub fn finalize(mut self) -> Result<Vec<u8>, WolfCryptError> {
        let mut out = alloc::vec![0u8; self.digest_size as usize];
        let rc = unsafe {
            wolfcrypt_rs::wc_Blake2sFinal(
                &mut self.ctx as *mut wolfcrypt_rs::WcBlake2s,
                out.as_mut_ptr(),
                self.digest_size,
            )
        };
        check(rc, "wc_Blake2sFinal")?;
        Ok(out)
    }
}
