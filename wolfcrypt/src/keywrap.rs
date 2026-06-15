//! AES Key Wrap (RFC 3394) backed by wolfCrypt.
//!
//! Provides [`aes_wrap_key`] and [`aes_unwrap_key`] which implement the
//! AES Key Wrap algorithm per RFC 3394 using wolfCrypt's native
//! `wc_AesKeyWrap` / `wc_AesKeyUnWrap` functions.
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

use core::ptr;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::WolfCryptError;
use wolfcrypt_rs::{wc_AesKeyUnWrap, wc_AesKeyWrap};

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

    let mut out = vec![0u8; plaintext.len() + 8];
    // SAFETY: kek/plaintext are valid slices; out is plaintext.len()+8 bytes.
    let rc = unsafe {
        wc_AesKeyWrap(
            kek.as_ptr(),
            kek.len() as u32,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            ptr::null(), // default IV (A6A6A6A6 A6A6A6A6)
        )
    };
    if rc <= 0 {
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_AesKeyWrap",
        });
    }
    let out_len = rc as usize;
    if out_len > out.len() {
        return Err(WolfCryptError::Ffi {
            code: -1,
            func: "wc_AesKeyWrap (output length)",
        });
    }
    out.truncate(out_len);
    Ok(out)
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

    let mut out = vec![0u8; ciphertext.len()];
    // SAFETY: kek/ciphertext are valid slices; out is ciphertext.len() bytes.
    let rc = unsafe {
        wc_AesKeyUnWrap(
            kek.as_ptr(),
            kek.len() as u32,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            ptr::null(), // default IV (A6A6A6A6 A6A6A6A6)
        )
    };
    if rc <= 0 {
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_AesKeyUnWrap",
        });
    }
    let out_len = rc as usize;
    if out_len > out.len() {
        return Err(WolfCryptError::Ffi {
            code: -1,
            func: "wc_AesKeyUnWrap (output length)",
        });
    }
    out.truncate(out_len);
    Ok(out)
}
