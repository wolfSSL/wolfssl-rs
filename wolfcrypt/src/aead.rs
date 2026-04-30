//! AEAD (Authenticated Encryption with Associated Data) backed by wolfCrypt.
//!
//! Provides AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 implementations
//! that satisfy the RustCrypto [`aead`](aead_trait) 0.5 traits (`AeadCore`,
//! `AeadInPlace`, `KeySizeUser`, `KeyInit`).

use core::cell::UnsafeCell;
use core::ffi::c_void;

use aead_trait::generic_array::GenericArray;
use aead_trait::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use typenum::{U0, U12, U16, U32};

use crate::error::len_as_u32;

pub use aead_trait;

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

/// Internal macro to stamp out an AES-GCM wrapper for a given key size.
///
/// Each generated type holds an `UnsafeCell<WcAes>` because wolfCrypt's
/// `wc_AesGcmEncrypt` mutates internal state (e.g. `aes->gcm.aadLen` when
/// `OPENSSL_EXTRA` is defined).  `UnsafeCell` makes the type `!Sync`,
/// preventing concurrent access from multiple threads.
#[cfg(wolfssl_aes_gcm)]
macro_rules! impl_aes_gcm {
    ($name:ident, $key_size:ty, $key_len:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            // SAFETY: UnsafeCell is needed because wc_AesGcmEncrypt may mutate
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
                    wolfcrypt_rs::wc_AesGcmSetKey(
                        &mut aes as *mut wolfcrypt_rs::WcAes,
                        key.as_ptr(),
                        $key_len,
                    )
                };
                assert_eq!(rc, 0, "wc_AesGcmSetKey failed (invalid key length)");

                Self {
                    aes: UnsafeCell::new(aes),
                }
            }
        }

        impl AeadCore for $name {
            type NonceSize = U12;
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
                    wolfcrypt_rs::wc_AesGcmEncrypt(
                        self.aes.get(),
                        out_ptr,
                        in_ptr,
                        len_as_u32(buffer.len()),
                        nonce.as_ptr(),
                        12,
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
                    wolfcrypt_rs::wc_AesGcmDecrypt(
                        self.aes.get(),
                        out_ptr,
                        in_ptr,
                        len_as_u32(buffer.len()),
                        nonce.as_ptr(),
                        12,
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

#[cfg(wolfssl_aes_gcm)]
impl_aes_gcm!(
    Aes128Gcm,
    typenum::U16,
    16,
    "AES-128-GCM AEAD cipher, implementing `AeadInPlace` and `KeyInit`."
);

#[cfg(all(wolfssl_aes_gcm, wolfssl_aes_192))]
impl_aes_gcm!(
    Aes192Gcm,
    typenum::U24,
    24,
    "AES-192-GCM AEAD cipher, implementing `AeadInPlace` and `KeyInit`."
);

#[cfg(wolfssl_aes_gcm)]
impl_aes_gcm!(
    Aes256Gcm,
    U32,
    32,
    "AES-256-GCM AEAD cipher, implementing `AeadInPlace` and `KeyInit`."
);

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 AEAD backed by wolfCrypt's streaming API.
///
/// Uses `wc_ChaCha20Poly1305_Init` / `UpdateAad` / `UpdateData` / `Final`
/// to encrypt and decrypt **in-place** without heap allocation.  The
/// underlying `wc_Chacha_Process` XORs each byte with the keystream, which
/// is safe when the input and output pointers are identical.
#[cfg(wolfssl_chacha20_poly1305)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

// SAFETY: The struct holds only inert key bytes; no interior mutability,
// no thread-local state.
#[cfg(wolfssl_chacha20_poly1305)]
unsafe impl Send for ChaCha20Poly1305 {}
#[cfg(wolfssl_chacha20_poly1305)]
unsafe impl Sync for ChaCha20Poly1305 {}

#[cfg(wolfssl_chacha20_poly1305)]
impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

#[cfg(wolfssl_chacha20_poly1305)]
impl KeySizeUser for ChaCha20Poly1305 {
    type KeySize = U32;
}

#[cfg(wolfssl_chacha20_poly1305)]
impl KeyInit for ChaCha20Poly1305 {
    fn new(key: &GenericArray<u8, U32>) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_slice());
        Self { key: k }
    }
}

#[cfg(wolfssl_chacha20_poly1305)]
impl AeadCore for ChaCha20Poly1305 {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

#[cfg(wolfssl_chacha20_poly1305)]
impl AeadInPlace for ChaCha20Poly1305 {
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead_trait::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead_trait::Result<aead_trait::Tag<Self>> {
        let mut tag = GenericArray::<u8, U16>::default();
        // Stack-local AEAD context (~192 bytes) — no heap allocation.
        let mut aead = wolfcrypt_rs::ChaChaPoly_Aead::zeroed();

        // SAFETY: `aead` is zero-initialized, `key` and `nonce` point to
        // 32 and 12 valid bytes respectively. `1` = encrypt direction.
        let rc = unsafe {
            wolfcrypt_rs::wc_ChaCha20Poly1305_Init(
                &mut aead,
                self.key.as_ptr(),
                nonce.as_ptr(),
                1, // encrypt
            )
        };
        if rc != 0 {
            return Err(aead_trait::Error);
        }

        // Feed AAD (may be empty).
        if !associated_data.is_empty() {
            // SAFETY: `aead` is initialized, pointer/len from a valid slice.
            let rc = unsafe {
                wolfcrypt_rs::wc_ChaCha20Poly1305_UpdateAad(
                    &mut aead,
                    associated_data.as_ptr(),
                    len_as_u32(associated_data.len()),
                )
            };
            if rc != 0 {
                return Err(aead_trait::Error);
            }
        }

        // Encrypt in-place: input == output pointer.
        // SAFETY: `wc_Chacha_Process` (called internally) XORs byte-by-byte,
        // reading each byte before writing, so in == out is safe.
        //
        // We always call UpdateData even when buffer is empty because
        // wolfCrypt's state machine requires at least one UpdateAad or
        // UpdateData call before Final (state must be AAD or DATA, not
        // READY).  With empty AAD + empty PT, skipping both leaves the
        // state at READY and Final returns BAD_STATE_E.  Calling
        // UpdateData with len=0 transitions to DATA without processing
        // any bytes, which is correct per RFC 8439.
        {
            // When buffer is empty, as_ptr()/as_mut_ptr() on an empty
            // slice may return a dangling pointer.  UpdateData requires
            // non-null inData/outData, so use a stack sentinel.
            let (in_ptr, out_ptr) = if buffer.is_empty() {
                let sentinel: *const u8 = &0u8;
                (sentinel, sentinel as *mut u8)
            } else {
                (buffer.as_ptr(), buffer.as_mut_ptr())
            };
            let rc = unsafe {
                wolfcrypt_rs::wc_ChaCha20Poly1305_UpdateData(
                    &mut aead,
                    in_ptr,
                    out_ptr,
                    len_as_u32(buffer.len()),
                )
            };
            if rc != 0 {
                return Err(aead_trait::Error);
            }
        }

        // Finalize: compute the authentication tag.
        // SAFETY: `aead` has been through Init+UpdateAad+UpdateData.
        // `tag` is exactly 16 bytes.
        let rc = unsafe { wolfcrypt_rs::wc_ChaCha20Poly1305_Final(&mut aead, tag.as_mut_ptr()) };
        if rc != 0 {
            return Err(aead_trait::Error);
        }

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead_trait::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead_trait::Tag<Self>,
    ) -> aead_trait::Result<()> {
        let mut aead = wolfcrypt_rs::ChaChaPoly_Aead::zeroed();

        // SAFETY: same as encrypt, but direction = 0 (decrypt).
        let rc = unsafe {
            wolfcrypt_rs::wc_ChaCha20Poly1305_Init(
                &mut aead,
                self.key.as_ptr(),
                nonce.as_ptr(),
                0, // decrypt
            )
        };
        if rc != 0 {
            return Err(aead_trait::Error);
        }

        if !associated_data.is_empty() {
            let rc = unsafe {
                wolfcrypt_rs::wc_ChaCha20Poly1305_UpdateAad(
                    &mut aead,
                    associated_data.as_ptr(),
                    len_as_u32(associated_data.len()),
                )
            };
            if rc != 0 {
                return Err(aead_trait::Error);
            }
        }

        // Decrypt in-place.  Always call UpdateData (even when empty) to
        // transition the state machine past READY — see encrypt comment.
        {
            let (in_ptr, out_ptr) = if buffer.is_empty() {
                let sentinel: *const u8 = &0u8;
                (sentinel, sentinel as *mut u8)
            } else {
                (buffer.as_ptr(), buffer.as_mut_ptr())
            };
            let rc = unsafe {
                wolfcrypt_rs::wc_ChaCha20Poly1305_UpdateData(
                    &mut aead,
                    in_ptr,
                    out_ptr,
                    len_as_u32(buffer.len()),
                )
            };
            if rc != 0 {
                return Err(aead_trait::Error);
            }
        }

        // Finalize and verify the tag.
        //
        // IMPORTANT: the buffer already contains decrypted plaintext at this
        // point.  If tag verification fails, we MUST zero it before returning
        // to prevent the caller from observing unauthenticated plaintext.
        let mut computed_tag = [0u8; 16];
        let rc = unsafe {
            wolfcrypt_rs::wc_ChaCha20Poly1305_Final(&mut aead, computed_tag.as_mut_ptr())
        };
        if rc != 0 {
            zeroize::Zeroize::zeroize(buffer);
            return Err(aead_trait::Error);
        }

        // Constant-time tag comparison via wolfCrypt.
        let rc = unsafe {
            wolfcrypt_rs::wc_ChaCha20Poly1305_CheckTag(computed_tag.as_ptr(), tag.as_ptr())
        };
        if rc != 0 {
            zeroize::Zeroize::zeroize(buffer);
            return Err(aead_trait::Error);
        }

        Ok(())
    }
}
