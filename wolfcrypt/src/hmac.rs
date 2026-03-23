//! HMAC algorithms backed by wolfCrypt's HMAC_CTX API.
//!
//! Each type implements the RustCrypto [`hmac`](hmac_trait) 0.12 traits
//! (`OutputSizeUser`, `KeySizeUser`, `KeyInit`, `Update`, `FixedOutput`,
//! `MacMarker`) so they satisfy the blanket `Mac` impl automatically.
//!
//! Callers should `use hmac_trait::Mac` for the full API:
//! `new_from_slice()`, `update()`, `finalize()`, `verify_slice()`.

use core::ffi::c_void;
use digest_trait::{FixedOutput, KeyInit, OutputSizeUser, Update};
use generic_array::GenericArray;
use typenum::*;
use crate::error::len_as_c_int;

/// Internal macro that stamps out a complete HMAC wrapper for one algorithm.
///
/// The generated struct holds a heap-allocated `HMAC_CTX` and delegates
/// all operations to wolfCrypt through the OpenSSL-compat HMAC layer.
macro_rules! impl_hmac {
    (
        $name:ident,
        $evp_fn:path,
        $output_size:ty,
        $key_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut wolfcrypt_rs::HMAC_CTX,
        }

        // SAFETY: HMAC_CTX is heap-allocated and only accessed through
        // &self / &mut self.  wolfCrypt's HMAC layer is thread-safe when a
        // context is used from a single thread, which Rust's ownership
        // rules enforce.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl $name {
            /// Return the algorithm descriptor pointer for this HMAC's hash.
            #[inline]
            fn evp_md() -> *const wolfcrypt_rs::EVP_MD {
                // SAFETY: EVP_sha* functions return a static const pointer.
                unsafe { $evp_fn() }
            }
        }

        // ------------------------------------------------------------------
        // core / RustCrypto trait impls
        // ------------------------------------------------------------------

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.ctx was allocated via HMAC_CTX_new and
                // is only freed once here.
                unsafe {
                    wolfcrypt_rs::HMAC_CTX_free(self.ctx);
                }
            }
        }

        #[$cfg_gate]
        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        #[$cfg_gate]
        impl crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        #[$cfg_gate]
        impl $name {
            /// Shared initialisation: allocate an HMAC_CTX and key it.
            fn init_with_key(key: &[u8]) -> Self {
                // SAFETY: HMAC_CTX_new returns a heap-allocated context
                // or NULL on OOM.
                let ctx = unsafe { wolfcrypt_rs::HMAC_CTX_new() };
                assert!(!ctx.is_null(), "HMAC_CTX_new returned NULL");

                // SAFETY: ctx is non-null and freshly allocated. key pointer
                // and length are guaranteed correct by the slice reference.
                // HMAC_Init_ex with a non-null key sets the key and algorithm.
                unsafe {
                    let rc = wolfcrypt_rs::HMAC_Init_ex(
                        ctx,
                        key.as_ptr() as *const c_void,
                        len_as_c_int(key.len()),
                        Self::evp_md(),
                        core::ptr::null_mut(),
                    );
                    assert_eq!(rc, 1, "HMAC_Init_ex failed (OOM or invalid algorithm)");
                }
                Self { ctx }
            }
        }

        #[$cfg_gate]
        impl KeyInit for $name {
            /// Create from a fixed-size key (KeySize bytes).
            fn new(key: &GenericArray<u8, <Self as crypto_common::KeySizeUser>::KeySize>) -> Self {
                Self::init_with_key(key.as_slice())
            }

            /// Create from a variable-length key.  HMAC accepts any key size
            /// per RFC 2104, so this never returns `InvalidLength`.
            fn new_from_slice(key: &[u8]) -> Result<Self, crypto_common::InvalidLength> {
                Ok(Self::init_with_key(key))
            }
        }

        #[$cfg_gate]
        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                // SAFETY: self.ctx is valid. data pointer and length are
                // guaranteed correct by the slice reference.
                unsafe {
                    let rc = wolfcrypt_rs::HMAC_Update(
                        self.ctx,
                        data.as_ptr(),
                        data.len(),
                    );
                    assert_eq!(rc, 1, "HMAC_Update failed (context not initialized)");
                }
            }
        }

        #[$cfg_gate]
        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
                let mut len: u32 = 0;
                // SAFETY: out is exactly OutputSize bytes. self.ctx is
                // valid. After this call, Drop will free the context.
                unsafe {
                    let rc = wolfcrypt_rs::HMAC_Final(
                        self.ctx,
                        out.as_mut_ptr(),
                        &mut len,
                    );
                    assert_eq!(rc, 1, "HMAC_Final failed (context not initialized)");
                }
                // Drop runs after this and frees self.ctx.
            }
        }

        #[$cfg_gate]
        impl digest_trait::MacMarker for $name {}
    };
}

// ======================================================================
// Stamp out HMAC types
// ======================================================================

impl_hmac!(
    WolfHmacSha1,
    wolfcrypt_rs::EVP_sha1,
    U20,
    U20,
    cfg(all(wolfssl_openssl_extra, wolfssl_hmac))
);

impl_hmac!(
    WolfHmacSha256,
    wolfcrypt_rs::EVP_sha256,
    U32,
    U32,
    cfg(all(wolfssl_openssl_extra, wolfssl_hmac))
);

impl_hmac!(
    WolfHmacSha384,
    wolfcrypt_rs::EVP_sha384,
    U48,
    U48,
    cfg(all(wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha384))
);

impl_hmac!(
    WolfHmacSha512,
    wolfcrypt_rs::EVP_sha512,
    U64,
    U64,
    cfg(all(wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha512))
);
