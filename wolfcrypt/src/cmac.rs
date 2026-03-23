//! AES-CMAC algorithms backed by wolfCrypt's CMAC_CTX API.
//!
//! Each type implements the RustCrypto [`digest`](digest_trait) 0.10 MAC traits
//! (`OutputSizeUser`, `KeySizeUser`, `KeyInit`, `Update`, `FixedOutput`,
//! `MacMarker`) so they satisfy the blanket `Mac` impl automatically.
//!
//! Callers should `use digest_trait::Mac` for the full API:
//! `new_from_slice()`, `update()`, `finalize()`, `verify_slice()`.

use core::ffi::c_void;
use digest_trait::{FixedOutput, KeyInit, OutputSizeUser, Update};
use generic_array::GenericArray;
use typenum::*;

/// Internal macro that stamps out a complete AES-CMAC wrapper for one key size.
///
/// The generated struct holds a heap-allocated `CMAC_CTX` and delegates
/// all operations to wolfCrypt through the OpenSSL-compat CMAC layer.
macro_rules! impl_cmac {
    (
        $name:ident,
        $cipher_fn:path,
        $key_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut wolfcrypt_rs::CMAC_CTX,
        }

        // SAFETY: CMAC_CTX is heap-allocated and only accessed through
        // &self / &mut self.  wolfCrypt's CMAC layer is thread-safe when a
        // context is used from a single thread, which Rust's ownership
        // rules enforce.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl $name {
            /// Return the cipher descriptor pointer for this CMAC's AES variant.
            #[inline]
            fn evp_cipher() -> *const wolfcrypt_rs::EVP_CIPHER {
                // SAFETY: EVP_aes_*_cbc functions return a static const pointer.
                unsafe { $cipher_fn() }
            }
        }

        // ------------------------------------------------------------------
        // core / RustCrypto trait impls
        // ------------------------------------------------------------------

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.ctx was allocated via CMAC_CTX_new and
                // is only freed once here.
                unsafe {
                    wolfcrypt_rs::CMAC_CTX_free(self.ctx);
                }
            }
        }

        #[$cfg_gate]
        impl OutputSizeUser for $name {
            // CMAC output is always one AES block = 16 bytes.
            type OutputSize = U16;
        }

        #[$cfg_gate]
        impl crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        #[$cfg_gate]
        impl KeyInit for $name {
            /// Create from a fixed-size key (KeySize bytes).
            fn new(key: &GenericArray<u8, <Self as crypto_common::KeySizeUser>::KeySize>) -> Self {
                Self::init_with_key(key.as_slice())
                    .expect("CMAC_Init failed with correct key size")
            }

            /// Create from a variable-length key.
            /// Returns `InvalidLength` if `key.len()` does not match the
            /// expected AES key size.
            fn new_from_slice(key: &[u8]) -> Result<Self, crypto_common::InvalidLength> {
                Self::init_with_key(key).ok_or(crypto_common::InvalidLength)
            }
        }

        #[$cfg_gate]
        impl $name {
            /// Shared initialisation: allocate a CMAC_CTX and key it.
            /// Returns `None` if the key length is wrong or allocation fails.
            fn init_with_key(key: &[u8]) -> Option<Self> {
                use typenum::Unsigned;
                let expected_len = <$key_size as Unsigned>::USIZE;
                if key.len() != expected_len {
                    return None;
                }

                // SAFETY: CMAC_CTX_new returns a heap-allocated context
                // or NULL on OOM.
                let ctx = unsafe { wolfcrypt_rs::CMAC_CTX_new() };
                if ctx.is_null() {
                    return None;
                }

                // SAFETY: ctx is non-null and freshly allocated. key pointer
                // and length are guaranteed correct by the slice reference.
                // CMAC_Init with a non-null key sets the key and cipher.
                let rc = unsafe {
                    wolfcrypt_rs::CMAC_Init(
                        ctx,
                        key.as_ptr() as *const c_void,
                        key.len(),
                        Self::evp_cipher(),
                        core::ptr::null_mut(),
                    )
                };
                if rc != 1 {
                    unsafe { wolfcrypt_rs::CMAC_CTX_free(ctx) };
                    return None;
                }
                Some(Self { ctx })
            }
        }

        #[$cfg_gate]
        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                // SAFETY: self.ctx is valid. data pointer and length are
                // guaranteed correct by the slice reference.
                unsafe {
                    let rc = wolfcrypt_rs::CMAC_Update(
                        self.ctx,
                        data.as_ptr(),
                        data.len(),
                    );
                    assert_eq!(rc, 1, "CMAC_Update failed (context not initialized)");
                }
            }
        }

        #[$cfg_gate]
        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
                let mut len: usize = 0;
                // SAFETY: out is exactly OutputSize (16) bytes. self.ctx is
                // valid. After this call, Drop will free the context.
                unsafe {
                    let rc = wolfcrypt_rs::CMAC_Final(
                        self.ctx,
                        out.as_mut_ptr(),
                        &mut len,
                    );
                    assert_eq!(rc, 1, "CMAC_Final failed (context not initialized)");
                }
                debug_assert_eq!(len, 16);
                // Drop runs after this and frees self.ctx.
            }
        }

        #[$cfg_gate]
        impl digest_trait::MacMarker for $name {}
    };
}

// ======================================================================
// Stamp out both AES-CMAC types
// ======================================================================

impl_cmac!(
    WolfCmacAes128,
    wolfcrypt_rs::EVP_aes_128_cbc,
    U16,
    cfg(all(wolfssl_openssl_extra, wolfssl_cmac))
);

impl_cmac!(
    WolfCmacAes256,
    wolfcrypt_rs::EVP_aes_256_cbc,
    U32,
    cfg(all(wolfssl_openssl_extra, wolfssl_cmac))
);
