//! AES-GCM streaming (incremental) encrypt and decrypt.
//!
//! Unlike the one-shot [`crate::aead::Aes128Gcm`] / [`crate::aead::Aes256Gcm`]
//! types, these structs allow feeding plaintext/ciphertext and AAD in
//! arbitrary-sized chunks via an `update` / `finalize` pattern.
//!
//! This is a bespoke API — there is no standard RustCrypto trait for
//! streaming AEAD as of `aead` 0.5.
//!
//! # Example
//!
//! ```ignore
//! let mut enc = AesGcmEncStream::new(&key, &iv)?;
//! enc.update_aad(&aad)?;
//! enc.update(&pt[..32], &mut ct[..32])?;
//! enc.update(&pt[32..], &mut ct[32..])?;
//! let mut tag = [0u8; 16];
//! enc.finalize(&mut tag)?;
//! ```

use core::ffi::c_void;

use crate::error::{check, len_as_u32, WolfCryptError};

// ---------------------------------------------------------------------------
// AesGcmEncStream
// ---------------------------------------------------------------------------

/// AES-GCM streaming encryptor.
///
/// Created via [`AesGcmEncStream::new`], then fed AAD and plaintext
/// incrementally.  The authentication tag is produced by [`finalize`],
/// which consumes the stream.
///
/// [`finalize`]: AesGcmEncStream::finalize
pub struct AesGcmEncStream {
    aes: wolfcrypt_rs::WcAes,
}

// SAFETY: WcAes contains no thread-local state; it is safe to move the
// whole struct to another thread.
unsafe impl Send for AesGcmEncStream {}

impl AesGcmEncStream {
    /// Begin encryption with the given key and IV.
    ///
    /// Accepted key lengths: 16 (AES-128), 24 (AES-192), 32 (AES-256).
    /// The IV is typically 12 bytes for GCM.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, WolfCryptError> {
        let mut aes = wolfcrypt_rs::WcAes::zeroed();

        // SAFETY: `aes` is freshly zeroed; null heap + INVALID_DEVID is the
        // standard init pattern.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesInit(
                &mut aes as *mut wolfcrypt_rs::WcAes,
                core::ptr::null_mut::<c_void>(),
                wolfcrypt_rs::INVALID_DEVID,
            )
        };
        check(rc, "wc_AesInit")?;

        // SAFETY: `aes` is initialised by wc_AesInit.  key/iv point to valid
        // slices of the stated lengths.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmEncryptInit(
                &mut aes as *mut wolfcrypt_rs::WcAes,
                key.as_ptr(),
                len_as_u32(key.len()),
                iv.as_ptr(),
                len_as_u32(iv.len()),
            )
        };
        check(rc, "wc_AesGcmEncryptInit")?;

        Ok(Self { aes })
    }

    /// Feed additional authenticated data (AAD).
    ///
    /// Must be called **before** any [`update`](Self::update) call.
    /// May be called multiple times to feed AAD in chunks.
    pub fn update_aad(&mut self, aad: &[u8]) -> Result<(), WolfCryptError> {
        // SAFETY: Pass null out/in with zero length to feed AAD only.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmEncryptUpdate(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                aad.as_ptr(),
                len_as_u32(aad.len()),
            )
        };
        check(rc, "wc_AesGcmEncryptUpdate")
    }

    /// Encrypt a chunk of plaintext.
    ///
    /// `out` must be at least `plaintext.len()` bytes.  Can be called
    /// multiple times to stream data in arbitrary-sized pieces.
    pub fn update(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<(), WolfCryptError> {
        if out.len() < plaintext.len() {
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: Pass null AAD with zero length to encrypt plaintext only.
        // `out` is at least as large as `plaintext`.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmEncryptUpdate(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                out.as_mut_ptr(),
                plaintext.as_ptr(),
                len_as_u32(plaintext.len()),
                core::ptr::null(),
                0,
            )
        };
        check(rc, "wc_AesGcmEncryptUpdate")
    }

    /// Finalize encryption and produce the authentication tag.
    ///
    /// `tag` is typically 16 bytes.  Consumes the stream; the underlying
    /// AES state is freed on drop.
    pub fn finalize(mut self, tag: &mut [u8]) -> Result<(), WolfCryptError> {
        // SAFETY: the stream has been initialised and updated.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmEncryptFinal(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                tag.as_mut_ptr(),
                len_as_u32(tag.len()),
            )
        };
        check(rc, "wc_AesGcmEncryptFinal")
        // `self` is dropped here, calling wc_AesFree via Drop.
    }
}

impl Drop for AesGcmEncStream {
    fn drop(&mut self) {
        // SAFETY: We have exclusive access (&mut self).
        unsafe {
            wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
        }
    }
}

// ---------------------------------------------------------------------------
// AesGcmDecStream
// ---------------------------------------------------------------------------

/// AES-GCM streaming decryptor.
///
/// Created via [`AesGcmDecStream::new`], then fed AAD and ciphertext
/// incrementally.  Tag verification happens in [`finalize`].
///
/// # Security
///
/// Decrypted output is **unauthenticated** until [`finalize`] returns
/// `Ok(())`.  Do not use the output if finalize fails.
///
/// [`finalize`]: AesGcmDecStream::finalize
pub struct AesGcmDecStream {
    aes: wolfcrypt_rs::WcAes,
}

// SAFETY: WcAes contains no thread-local state; it is safe to move the
// whole struct to another thread.
unsafe impl Send for AesGcmDecStream {}

impl AesGcmDecStream {
    /// Begin decryption with the given key and IV.
    ///
    /// Accepted key lengths: 16 (AES-128), 24 (AES-192), 32 (AES-256).
    /// The IV is typically 12 bytes for GCM.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, WolfCryptError> {
        let mut aes = wolfcrypt_rs::WcAes::zeroed();

        // SAFETY: `aes` is freshly zeroed; null heap + INVALID_DEVID.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesInit(
                &mut aes as *mut wolfcrypt_rs::WcAes,
                core::ptr::null_mut::<c_void>(),
                wolfcrypt_rs::INVALID_DEVID,
            )
        };
        check(rc, "wc_AesInit")?;

        // SAFETY: `aes` is initialised by wc_AesInit.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmDecryptInit(
                &mut aes as *mut wolfcrypt_rs::WcAes,
                key.as_ptr(),
                len_as_u32(key.len()),
                iv.as_ptr(),
                len_as_u32(iv.len()),
            )
        };
        check(rc, "wc_AesGcmDecryptInit")?;

        Ok(Self { aes })
    }

    /// Feed additional authenticated data (AAD).
    ///
    /// Must be called **before** any [`update`](Self::update) call.
    /// May be called multiple times to feed AAD in chunks.
    pub fn update_aad(&mut self, aad: &[u8]) -> Result<(), WolfCryptError> {
        // SAFETY: Pass null out/in with zero length to feed AAD only.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmDecryptUpdate(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                aad.as_ptr(),
                len_as_u32(aad.len()),
            )
        };
        check(rc, "wc_AesGcmDecryptUpdate")
    }

    /// Decrypt a chunk of ciphertext.
    ///
    /// `out` must be at least `ciphertext.len()` bytes.  Can be called
    /// multiple times to stream data in arbitrary-sized pieces.
    ///
    /// **Warning:** output is unauthenticated until [`finalize`](Self::finalize)
    /// succeeds.
    pub fn update(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), WolfCryptError> {
        if out.len() < ciphertext.len() {
            return Err(WolfCryptError::InvalidInput);
        }

        // SAFETY: Pass null AAD with zero length to decrypt ciphertext only.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmDecryptUpdate(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                out.as_mut_ptr(),
                ciphertext.as_ptr(),
                len_as_u32(ciphertext.len()),
                core::ptr::null(),
                0,
            )
        };
        check(rc, "wc_AesGcmDecryptUpdate")
    }

    /// Finalize decryption and verify the authentication tag.
    ///
    /// Returns `Ok(())` if the tag is valid, `Err` if authentication fails.
    /// Consumes the stream; the underlying AES state is freed on drop.
    pub fn finalize(mut self, tag: &[u8]) -> Result<(), WolfCryptError> {
        // SAFETY: the stream has been initialised and updated.
        // wc_AesGcmDecryptFinal takes a *const u8 tag for verification.
        let rc = unsafe {
            wolfcrypt_rs::wc_AesGcmDecryptFinal(
                &mut self.aes as *mut wolfcrypt_rs::WcAes,
                tag.as_ptr(),
                len_as_u32(tag.len()),
            )
        };
        check(rc, "wc_AesGcmDecryptFinal")
        // `self` is dropped here, calling wc_AesFree via Drop.
    }
}

impl Drop for AesGcmDecStream {
    fn drop(&mut self) {
        // SAFETY: We have exclusive access (&mut self).
        unsafe {
            wolfcrypt_rs::wc_AesFree(&mut self.aes as *mut wolfcrypt_rs::WcAes);
        }
    }
}
