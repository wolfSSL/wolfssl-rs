//! Digest (hash) algorithms backed by wolfCrypt's EVP_MD API.
//!
//! Each type implements the RustCrypto [`digest`](digest_trait) 0.10 traits
//! (`OutputSizeUser`, `BlockSizeUser`, `Update`, `FixedOutput`,
//! `FixedOutputReset`, `Reset`, `HashMarker`) so they satisfy the
//! blanket `Digest` impl automatically.
//!
//! Callers should `use digest_trait::Digest` (re-exported as
//! `wolfcrypt::digest::digest_trait`) for the full API:
//! `new()`, `update()`, `finalize()`, `finalize_reset()`, `reset()`.

use core::ffi::c_void;
use generic_array::GenericArray;
use typenum::*;

// Re-export the trait crate types we use in our public API.
pub use digest_trait;

/// Internal macro that stamps out a complete digest wrapper for one algorithm.
///
/// The generated struct holds a heap-allocated `EVP_MD_CTX` and delegates
/// all hashing to wolfCrypt through the OpenSSL-compat EVP layer.
macro_rules! impl_digest {
    (
        $name:ident,
        $evp_fn:path,
        $output_size:ty,
        $block_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut wolfcrypt_rs::EVP_MD_CTX,
        }

        // SAFETY: EVP_MD_CTX is heap-allocated and only accessed through
        // &self / &mut self.  wolfCrypt's EVP layer is thread-safe when a
        // context is used from a single thread, which Rust's ownership
        // rules enforce.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl $name {
            /// Return the algorithm descriptor pointer for this hash.
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
        impl Default for $name {
            fn default() -> Self {
                // SAFETY: EVP_MD_CTX_new returns a heap-allocated context
                // or NULL on OOM.
                let ctx = unsafe { wolfcrypt_rs::EVP_MD_CTX_new() };
                assert!(!ctx.is_null(), "EVP_MD_CTX_new returned NULL");
                // SAFETY: ctx is non-null and freshly allocated.
                unsafe {
                    let rc = wolfcrypt_rs::EVP_DigestInit_ex(
                        ctx,
                        Self::evp_md(),
                        core::ptr::null_mut(),
                    );
                    assert_eq!(rc, 1, "EVP_DigestInit_ex failed (OOM or invalid algorithm)");
                }
                Self { ctx }
            }
        }

        #[$cfg_gate]
        impl Clone for $name {
            fn clone(&self) -> Self {
                // SAFETY: Allocate a fresh context and deep-copy state.
                let new_ctx = unsafe { wolfcrypt_rs::EVP_MD_CTX_new() };
                assert!(!new_ctx.is_null(), "EVP_MD_CTX_new returned NULL");
                // SAFETY: both contexts are valid, non-overlapping.
                unsafe {
                    let rc = wolfcrypt_rs::EVP_MD_CTX_copy(new_ctx, self.ctx);
                    assert_eq!(rc, 1, "EVP_MD_CTX_copy failed (OOM)");
                }
                Self { ctx: new_ctx }
            }
        }

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self.ctx was allocated via EVP_MD_CTX_new and
                // is only freed once here.
                unsafe {
                    wolfcrypt_rs::EVP_MD_CTX_free(self.ctx);
                }
            }
        }

        #[$cfg_gate]
        impl digest_trait::OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        #[$cfg_gate]
        impl digest_trait::core_api::BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        #[$cfg_gate]
        impl digest_trait::Update for $name {
            fn update(&mut self, data: &[u8]) {
                // SAFETY: self.ctx is valid. data pointer and length are
                // guaranteed correct by the slice reference.
                unsafe {
                    let rc = wolfcrypt_rs::EVP_DigestUpdate(
                        self.ctx,
                        data.as_ptr() as *const c_void,
                        data.len(),
                    );
                    assert_eq!(rc, 1, "EVP_DigestUpdate failed (context not initialized)");
                }
            }
        }

        #[$cfg_gate]
        impl digest_trait::FixedOutput for $name {
            fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
                let mut len: u32 = 0;
                // SAFETY: out is exactly OutputSize bytes. self.ctx is
                // valid. After this call, Drop will free the context.
                unsafe {
                    let rc = wolfcrypt_rs::EVP_DigestFinal(
                        self.ctx,
                        out.as_mut_ptr(),
                        &mut len,
                    );
                    assert_eq!(rc, 1, "EVP_DigestFinal failed (context not initialized)");
                }
                // Drop runs after this and frees self.ctx.
            }
        }

        #[$cfg_gate]
        impl digest_trait::FixedOutputReset for $name {
            fn finalize_into_reset(
                &mut self,
                out: &mut GenericArray<u8, Self::OutputSize>,
            ) {
                let mut len: u32 = 0;
                // SAFETY: ctx is valid, out has correct size.
                unsafe {
                    let rc = wolfcrypt_rs::EVP_DigestFinal(
                        self.ctx,
                        out.as_mut_ptr(),
                        &mut len,
                    );
                    assert_eq!(rc, 1, "EVP_DigestFinal failed (context not initialized)");
                }
                // Re-initialise for reuse.
                // SAFETY: ctx is still allocated (DigestFinal does not free it).
                unsafe {
                    let rc = wolfcrypt_rs::EVP_DigestInit_ex(
                        self.ctx,
                        Self::evp_md(),
                        core::ptr::null_mut(),
                    );
                    assert_eq!(rc, 1, "EVP_DigestInit_ex failed after finalize_into_reset (OOM or invalid algorithm)");
                }
            }
        }

        #[$cfg_gate]
        impl digest_trait::Reset for $name {
            fn reset(&mut self) {
                // SAFETY: ctx is valid. cleanup + re-init is the
                // documented way to reset an EVP_MD_CTX.
                unsafe {
                    wolfcrypt_rs::EVP_MD_CTX_cleanup(self.ctx);
                    let rc = wolfcrypt_rs::EVP_DigestInit_ex(
                        self.ctx,
                        Self::evp_md(),
                        core::ptr::null_mut(),
                    );
                    assert_eq!(rc, 1, "EVP_DigestInit_ex failed in reset (OOM or invalid algorithm)");
                }
            }
        }

        #[$cfg_gate]
        impl digest_trait::HashMarker for $name {}
    };
}

// ======================================================================
// Stamp out all nine digest types
// ======================================================================

impl_digest!(Sha1,       wolfcrypt_rs::EVP_sha1,       U20, U64,  cfg(wolfssl_openssl_extra));
impl_digest!(Sha224,     wolfcrypt_rs::EVP_sha224,      U28, U64,  cfg(all(wolfssl_openssl_extra, wolfssl_sha224)));
impl_digest!(Sha256,     wolfcrypt_rs::EVP_sha256,      U32, U64,  cfg(wolfssl_openssl_extra));
impl_digest!(Sha384,     wolfcrypt_rs::EVP_sha384,      U48, U128, cfg(all(wolfssl_openssl_extra, wolfssl_sha384)));
impl_digest!(Sha512,     wolfcrypt_rs::EVP_sha512,      U64, U128, cfg(all(wolfssl_openssl_extra, wolfssl_sha512)));
impl_digest!(Sha512_256, wolfcrypt_rs::EVP_sha512_256,  U32, U128, cfg(all(wolfssl_openssl_extra, wolfssl_sha512)));
impl_digest!(Sha3_256,   wolfcrypt_rs::EVP_sha3_256,    U32, U136, cfg(all(wolfssl_openssl_extra, wolfssl_sha3)));
impl_digest!(Sha3_384,   wolfcrypt_rs::EVP_sha3_384,    U48, U104, cfg(all(wolfssl_openssl_extra, wolfssl_sha3)));
impl_digest!(Sha3_512,   wolfcrypt_rs::EVP_sha3_512,    U64, U72,  cfg(all(wolfssl_openssl_extra, wolfssl_sha3)));
