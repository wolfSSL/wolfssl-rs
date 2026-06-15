//! AES-CCM authenticated encryption (wolfCrypt native API).
//!
//! Provides `Aes128Ccm` and `Aes256Ccm` implementing the RustCrypto
//! [`aead`](aead_trait) 0.5 traits (`AeadCore`, `AeadInPlace`, `KeySizeUser`,
//! `KeyInit`), plus standalone `aes_ccm_encrypt` / `aes_ccm_decrypt` functions
//! that accept variable-length nonces (7–13 bytes) and tags (4–16 bytes).
//!
//! # Nonce size
//!
//! CCM permits nonces from 7 to 13 bytes.  The `AeadCore` trait
//! implementation fixes `NonceSize = U13` (13 bytes) because trait-level
//! associated types must be a single constant.  Use the standalone functions
//! when you need a different nonce length.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use aead_trait::generic_array::GenericArray;
use aead_trait::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use typenum::{U0, U13, U16, U32};

use crate::error::{check, len_as_u32, WolfCryptError};

// ---------------------------------------------------------------------------
// Trait-based API (AeadInPlace)
// ---------------------------------------------------------------------------

/// Internal macro to stamp out an AES-CCM wrapper for a given key size.
///
/// Each generated type holds an `UnsafeCell<WcAes>` because wolfCrypt's
/// `wc_AesCcmEncrypt` may mutate internal state.  `UnsafeCell` makes the
/// type `!Sync`, preventing concurrent access from multiple threads.
macro_rules! impl_aes_ccm {
    ($name:ident, $key_size:ty, $key_len:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            // SAFETY: UnsafeCell is needed because wc_AesCcmEncrypt may mutate
            // the WcAes struct internally.  The type is !Sync (UnsafeCell opts
            // out), preventing data races.
            aes: UnsafeCell<wolfcrypt_rs::WcAes>,
        }

        // SAFETY: WcAes contains no thread-local state; it is safe to move
        // the whole struct to another thread.
        unsafe impl Send for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let mut aes = wolfcrypt_rs::WcAes::zeroed();

                // SAFETY: `aes` is freshly zeroed and we pass null heap with
                // INVALID_DEVID, which is the standard init pattern.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesInit(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        core::ptr::null_mut::<c_void>(),
                        wolfcrypt_rs::INVALID_DEVID,
                    )
                };
                assert_eq!(rc, 0, "wc_AesInit failed (OOM or invalid device)");

                // SAFETY: `aes` has been initialised by `wc_AesInit`.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCcmSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_len,
                    )
                };
                assert_eq!(rc, 0, "wc_AesCcmSetKey failed (invalid key length)");

                Self {
                    aes: UnsafeCell::new(aes),
                }
            }
        }

        impl AeadCore for $name {
            /// Fixed to 13 bytes (the maximum CCM nonce length).
            /// Use the standalone functions for shorter nonces.
            type NonceSize = U13;
            type TagSize = U16;
            type CiphertextOverhead = U0;
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &aead_trait::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> aead_trait::Result<aead_trait::Tag<Self>> {
                let mut tag = GenericArray::<u8, U16>::default();

                let aad_ptr = if associated_data.is_empty() {
                    core::ptr::null()
                } else {
                    associated_data.as_ptr()
                };
                let (in_ptr, out_ptr) = if buffer.is_empty() {
                    (core::ptr::null(), core::ptr::null_mut())
                } else {
                    (buffer.as_ptr(), buffer.as_mut_ptr())
                };

                // SAFETY: We have exclusive logical access (&self + !Sync).
                // out == in is supported by wolfCrypt for in-place operation.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCcmEncrypt(
                        self.aes.get(),
                        out_ptr,
                        in_ptr,
                        len_as_u32(buffer.len()),
                        nonce.as_ptr(),
                        13,
                        tag.as_mut_ptr(),
                        16,
                        aad_ptr,
                        len_as_u32(associated_data.len()),
                    )
                };

                if rc == 0 {
                    Ok(tag)
                } else {
                    Err(aead_trait::Error)
                }
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &aead_trait::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &aead_trait::Tag<Self>,
            ) -> aead_trait::Result<()> {
                let aad_ptr = if associated_data.is_empty() {
                    core::ptr::null()
                } else {
                    associated_data.as_ptr()
                };
                let (in_ptr, out_ptr) = if buffer.is_empty() {
                    (core::ptr::null(), core::ptr::null_mut())
                } else {
                    (buffer.as_ptr(), buffer.as_mut_ptr())
                };

                // SAFETY: We have exclusive logical access (&self + !Sync).
                // out == in is supported by wolfCrypt for in-place operation.
                let rc = unsafe {
                    wolfcrypt_rs::wc_AesCcmDecrypt(
                        self.aes.get(),
                        out_ptr,
                        in_ptr,
                        len_as_u32(buffer.len()),
                        nonce.as_ptr(),
                        13,
                        tag.as_ptr(),
                        16,
                        aad_ptr,
                        len_as_u32(associated_data.len()),
                    )
                };

                if rc == 0 {
                    Ok(())
                } else {
                    Err(aead_trait::Error)
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: We have &mut self, so exclusive access is guaranteed.
                unsafe {
                    wolfcrypt_rs::wc_AesFree(self.aes.get_mut());
                }
            }
        }
    };
}

impl_aes_ccm!(
    Aes128Ccm,
    typenum::U16,
    16,
    "AES-128-CCM AEAD cipher, implementing `AeadInPlace` and `KeyInit`.\n\n\
     The trait-level nonce size is fixed to 13 bytes.  Use the standalone\n\
     `aes_ccm_encrypt` / `aes_ccm_decrypt` functions for variable nonce lengths."
);

impl_aes_ccm!(
    Aes256Ccm,
    U32,
    32,
    "AES-256-CCM AEAD cipher, implementing `AeadInPlace` and `KeyInit`.\n\n\
     The trait-level nonce size is fixed to 13 bytes.  Use the standalone\n\
     `aes_ccm_encrypt` / `aes_ccm_decrypt` functions for variable nonce lengths."
);

// ---------------------------------------------------------------------------
// Standalone (variable nonce/tag) API
// ---------------------------------------------------------------------------

/// Encrypt and authenticate with AES-CCM.
///
/// - `key`: 16, 24, or 32 bytes (AES-128, AES-192, AES-256).
/// - `nonce`: 7–13 bytes.
/// - `aad`: additional authenticated data (may be empty).
/// - `plaintext`: data to encrypt.
/// - `ciphertext`: output buffer, must be at least `plaintext.len()` bytes.
/// - `tag`: output buffer for the authentication tag (4–16 bytes).
pub fn aes_ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) -> Result<(), WolfCryptError> {
    if ciphertext.len() < plaintext.len() {
        return Err(WolfCryptError::InvalidInput);
    }
    if tag.is_empty() || tag.len() > 16 {
        return Err(WolfCryptError::InvalidInput);
    }
    if nonce.len() < wolfcrypt_rs::CCM_NONCE_MIN_SZ as usize
        || nonce.len() > wolfcrypt_rs::CCM_NONCE_MAX_SZ as usize
    {
        return Err(WolfCryptError::InvalidInput);
    }

    let mut aes = wolfcrypt_rs::WcAes::zeroed();

    // SAFETY: `aes` is freshly zeroed; null heap + INVALID_DEVID is the standard init.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesInit(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            core::ptr::null_mut::<c_void>(),
            wolfcrypt_rs::INVALID_DEVID,
        )
    };
    check(rc, "wc_AesInit")?;

    // SAFETY: `aes` was initialised by wc_AesInit; key slice is valid.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesCcmSetKey(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            key.as_ptr(),
            len_as_u32(key.len()),
        )
    };
    if rc != 0 {
        // SAFETY: `aes` was initialised by wc_AesInit; we must free before returning.
        unsafe {
            wolfcrypt_rs::wc_AesFree(&mut aes);
        }
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_AesCcmSetKey",
        });
    }

    let aad_ptr = if aad.is_empty() {
        core::ptr::null()
    } else {
        aad.as_ptr()
    };

    // SAFETY: `aes` is keyed; all pointers/lengths derive from valid slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesCcmEncrypt(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            ciphertext.as_mut_ptr(),
            plaintext.as_ptr(),
            len_as_u32(plaintext.len()),
            nonce.as_ptr(),
            len_as_u32(nonce.len()),
            tag.as_mut_ptr(),
            len_as_u32(tag.len()),
            aad_ptr,
            len_as_u32(aad.len()),
        )
    };

    // SAFETY: `aes` was initialised by wc_AesInit; freeing after use.
    unsafe {
        wolfcrypt_rs::wc_AesFree(&mut aes);
    }

    check(rc, "wc_AesCcmEncrypt")?;
    Ok(())
}

/// Decrypt and verify with AES-CCM.
///
/// - `key`: 16, 24, or 32 bytes.
/// - `nonce`: 7–13 bytes (must match what was used for encryption).
/// - `aad`: additional authenticated data (must match encryption).
/// - `ciphertext`: data to decrypt.
/// - `plaintext`: output buffer, must be at least `ciphertext.len()` bytes.
/// - `tag`: the authentication tag to verify (4–16 bytes).
///
/// Returns `Err` if the tag does not verify (authentication failure).
pub fn aes_ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8],
) -> Result<(), WolfCryptError> {
    if plaintext.len() < ciphertext.len() {
        return Err(WolfCryptError::InvalidInput);
    }
    if tag.is_empty() || tag.len() > 16 {
        return Err(WolfCryptError::InvalidInput);
    }
    if nonce.len() < wolfcrypt_rs::CCM_NONCE_MIN_SZ as usize
        || nonce.len() > wolfcrypt_rs::CCM_NONCE_MAX_SZ as usize
    {
        return Err(WolfCryptError::InvalidInput);
    }

    let mut aes = wolfcrypt_rs::WcAes::zeroed();

    // SAFETY: `aes` is freshly zeroed; null heap + INVALID_DEVID is the standard init.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesInit(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            core::ptr::null_mut::<c_void>(),
            wolfcrypt_rs::INVALID_DEVID,
        )
    };
    check(rc, "wc_AesInit")?;

    // SAFETY: `aes` was initialised by wc_AesInit; key slice is valid.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesCcmSetKey(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            key.as_ptr(),
            len_as_u32(key.len()),
        )
    };
    if rc != 0 {
        // SAFETY: `aes` was initialised by wc_AesInit; we must free before returning.
        unsafe {
            wolfcrypt_rs::wc_AesFree(&mut aes);
        }
        return Err(WolfCryptError::Ffi {
            code: rc,
            func: "wc_AesCcmSetKey",
        });
    }

    let aad_ptr = if aad.is_empty() {
        core::ptr::null()
    } else {
        aad.as_ptr()
    };

    // SAFETY: `aes` is keyed; all pointers/lengths derive from valid slices.
    let rc = unsafe {
        wolfcrypt_rs::wc_AesCcmDecrypt(
            &mut aes as *mut wolfcrypt_rs::WcAes,
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            len_as_u32(ciphertext.len()),
            nonce.as_ptr(),
            len_as_u32(nonce.len()),
            tag.as_ptr(),
            len_as_u32(tag.len()),
            aad_ptr,
            len_as_u32(aad.len()),
        )
    };

    // SAFETY: `aes` was initialised by wc_AesInit; freeing after use.
    unsafe {
        wolfcrypt_rs::wc_AesFree(&mut aes);
    }

    check(rc, "wc_AesCcmDecrypt")?;
    Ok(())
}
