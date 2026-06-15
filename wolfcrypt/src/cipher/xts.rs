//! AES-XTS disk-encryption cipher (wolfCrypt native API).
//!
//! XTS (XEX-based tweaked-codebook mode with ciphertext stealing) is designed
//! for storage encryption.  It does not fit the standard RustCrypto block or
//! stream cipher traits, so this module provides a bespoke API.

use crate::error::{check, WolfCryptError};

/// AES-XTS cipher state.
///
/// Wraps wolfCrypt's `XtsAes` struct.  Create with [`AesXts::new_encrypt`] or
/// [`AesXts::new_decrypt`], then call [`encrypt`](AesXts::encrypt) or
/// [`decrypt`](AesXts::decrypt) respectively.
///
/// The key is twice the normal AES key size: 32 bytes for AES-128-XTS or
/// 64 bytes for AES-256-XTS (half for the block cipher, half for the tweak).
pub struct AesXts {
    xts: wolfcrypt_rs::XtsAes,
    /// Remember the direction so we can guard against misuse.
    direction: i32,
}

// SAFETY: XtsAes contains no thread-local state; safe to move to another thread.
unsafe impl Send for AesXts {}

impl Drop for AesXts {
    fn drop(&mut self) {
        // SAFETY: self.xts was initialised by wc_AesXtsInit; we have &mut self.
        unsafe {
            wolfcrypt_rs::wc_AesXtsFree(&mut self.xts as *mut wolfcrypt_rs::XtsAes);
        }
    }
}

impl AesXts {
    /// Create an AES-XTS instance for encryption.
    ///
    /// `key` must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
    pub fn new_encrypt(key: &[u8]) -> Result<Self, WolfCryptError> {
        Self::new_inner(key, wolfcrypt_rs::AES_ENCRYPT)
    }

    /// Create an AES-XTS instance for decryption.
    ///
    /// `key` must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
    pub fn new_decrypt(key: &[u8]) -> Result<Self, WolfCryptError> {
        Self::new_inner(key, wolfcrypt_rs::AES_DECRYPT)
    }

    fn new_inner(key: &[u8], dir: i32) -> Result<Self, WolfCryptError> {
        if key.len() != 32 && key.len() != 64 {
            return Err(WolfCryptError::InvalidInput);
        }

        let mut xts = wolfcrypt_rs::XtsAes::zeroed();

        // SAFETY: `xts` is freshly zeroed; null heap + INVALID_DEVID is the standard init.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesXtsInit(
                &mut xts as *mut wolfcrypt_rs::XtsAes,
                core::ptr::null_mut(),
                wolfcrypt_rs::INVALID_DEVID,
            )
        };
        check(rc, "wc_AesXtsInit")?;

        // SAFETY: `xts` was initialised by wc_AesXtsInit; key is a valid slice.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesXtsSetKeyNoInit(
                &mut xts as *mut wolfcrypt_rs::XtsAes,
                key.as_ptr(),
                key.len() as u32,
                dir,
            )
        };
        if rc != 0 {
            // Free the already-initialized XtsAes before returning.
            // SAFETY: `xts` was initialised by wc_AesXtsInit; must free on error.
            unsafe {
                wolfcrypt_rs::wc_AesXtsFree(&mut xts as *mut wolfcrypt_rs::XtsAes);
            }
            return Err(WolfCryptError::Ffi {
                code: rc,
                func: "wc_AesXtsSetKeyNoInit",
            });
        }

        Ok(Self {
            xts,
            direction: dir,
        })
    }

    /// Encrypt `input` into `out` using the given `tweak` (data unit number).
    ///
    /// `out` must be at least as large as `input`.  `input` length must be at
    /// least 16 bytes (one AES block).  `tweak` is typically 16 bytes.
    pub fn encrypt(
        &mut self,
        out: &mut [u8],
        input: &[u8],
        tweak: &[u8],
    ) -> Result<(), WolfCryptError> {
        if self.direction != wolfcrypt_rs::AES_ENCRYPT {
            return Err(WolfCryptError::InvalidInput);
        }
        if out.len() < input.len() || input.len() < 16 {
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: `xts` is keyed for encryption; all pointers/lengths from valid slices.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesXtsEncrypt(
                &mut self.xts as *mut wolfcrypt_rs::XtsAes,
                out.as_mut_ptr(),
                input.as_ptr(),
                input.len() as u32,
                tweak.as_ptr(),
                tweak.len() as u32,
            )
        };
        check(rc, "wc_AesXtsEncrypt")?;
        Ok(())
    }

    /// Decrypt `input` into `out` using the given `tweak` (data unit number).
    ///
    /// `out` must be at least as large as `input`.  `input` length must be at
    /// least 16 bytes (one AES block).  `tweak` is typically 16 bytes.
    pub fn decrypt(
        &mut self,
        out: &mut [u8],
        input: &[u8],
        tweak: &[u8],
    ) -> Result<(), WolfCryptError> {
        if self.direction != wolfcrypt_rs::AES_DECRYPT {
            return Err(WolfCryptError::InvalidInput);
        }
        if out.len() < input.len() || input.len() < 16 {
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: `xts` is keyed for decryption; all pointers/lengths from valid slices.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesXtsDecrypt(
                &mut self.xts as *mut wolfcrypt_rs::XtsAes,
                out.as_mut_ptr(),
                input.as_ptr(),
                input.len() as u32,
                tweak.as_ptr(),
                tweak.len() as u32,
            )
        };
        check(rc, "wc_AesXtsDecrypt")?;
        Ok(())
    }
}
