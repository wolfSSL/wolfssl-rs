//! AES Key Wrap (RFC 3394) backed by wolfCrypt.
//!
//! Provides [`aes_wrap_key`] and [`aes_unwrap_key`] which implement the
//! AES Key Wrap algorithm per RFC 3394 using wolfSSL's OpenSSL-compatible
//! `AES_wrap_key` / `AES_unwrap_key` functions.
//!
//! The Key Encryption Key (KEK) must be 16, 24, or 32 bytes (AES-128/192/256).
//! The plaintext (key data) must be a multiple of 8 bytes and at least 16 bytes.
//! The ciphertext is always 8 bytes longer than the plaintext.
//!
//! # Example
//!
//! ```ignore
//! use wolfcrypt::keywrap::{aes_wrap_key, aes_unwrap_key};
//!
//! let kek = [0u8; 16];
//! let key_data = [0x42u8; 16];
//! let wrapped = aes_wrap_key(&kek, &key_data).unwrap();
//! let unwrapped = aes_unwrap_key(&kek, &wrapped).unwrap();
//! assert_eq!(&key_data[..], &unwrapped[..]);
//! ```

use core::ffi::c_uint;
use core::ptr;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::{check, WolfCryptError};
use wolfcrypt_rs::{AES_KEY, AES_set_encrypt_key, AES_set_decrypt_key, AES_wrap_key, AES_unwrap_key};

/// RAII guard that zeroizes the key schedule in an `AES_KEY` on drop.
///
/// Ensures the key material is cleared on every exit path (success, error,
/// or panic) without requiring manual cleanup at each `return`.
struct AesKeyGuard(AES_KEY);

impl Drop for AesKeyGuard {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // SAFETY: We have exclusive access (&mut self). AES_KEY is a plain
        // C struct with no Rust drop glue. Zeroing its raw bytes is safe.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut self.0 as *mut AES_KEY as *mut u8,
                core::mem::size_of::<AES_KEY>(),
            )
        };
        bytes.zeroize();
    }
}

/// Wrap `plaintext` key data under `kek` per RFC 3394.
///
/// - `kek` must be 16, 24, or 32 bytes.
/// - `plaintext` must be a multiple of 8 bytes and at least 16 bytes.
/// - Returns ciphertext of `plaintext.len() + 8` bytes on success.
pub fn aes_wrap_key(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
    if plaintext.len() < 16 || plaintext.len() % 8 != 0 {
        return Err(WolfCryptError::INVALID_INPUT);
    }
    match kek.len() {
        16 | 24 | 32 => {}
        _ => return Err(WolfCryptError::INVALID_INPUT),
    }

    unsafe {
        let mut guard = AesKeyGuard(AES_KEY::zeroed());
        let rc = AES_set_encrypt_key(kek.as_ptr(), (kek.len() * 8) as c_uint, &mut guard.0);
        check(rc, "AES_set_encrypt_key")?;

        let mut out = vec![0u8; plaintext.len() + 8];
        let rc = AES_wrap_key(
            &guard.0,
            ptr::null(), // default IV (A6A6A6A6 A6A6A6A6)
            out.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "AES_wrap_key" });
        }
        let out_len = rc as usize;
        if out_len > out.len() {
            return Err(WolfCryptError::Ffi { code: -1, func: "AES_wrap_key (output length)" });
        }
        out.truncate(out_len);
        Ok(out)
    }
}

/// Unwrap `ciphertext` under `kek` per RFC 3394.
///
/// - `kek` must be 16, 24, or 32 bytes.
/// - `ciphertext` must be a multiple of 8 bytes and at least 24 bytes.
/// - Returns the original key data (`ciphertext.len() - 8` bytes) on success.
pub fn aes_unwrap_key(kek: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WolfCryptError> {
    if ciphertext.len() < 24 || ciphertext.len() % 8 != 0 {
        return Err(WolfCryptError::INVALID_INPUT);
    }
    match kek.len() {
        16 | 24 | 32 => {}
        _ => return Err(WolfCryptError::INVALID_INPUT),
    }

    unsafe {
        let mut guard = AesKeyGuard(AES_KEY::zeroed());
        let rc = AES_set_decrypt_key(kek.as_ptr(), (kek.len() * 8) as c_uint, &mut guard.0);
        check(rc, "AES_set_decrypt_key")?;

        let mut out = vec![0u8; ciphertext.len()];
        let rc = AES_unwrap_key(
            &guard.0,
            ptr::null(), // default IV (A6A6A6A6 A6A6A6A6)
            out.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len(),
        );
        if rc <= 0 {
            return Err(WolfCryptError::Ffi { code: rc, func: "AES_unwrap_key" });
        }
        let out_len = rc as usize;
        if out_len > out.len() {
            return Err(WolfCryptError::Ffi { code: -1, func: "AES_unwrap_key (output length)" });
        }
        out.truncate(out_len);
        Ok(out)
    }
}
