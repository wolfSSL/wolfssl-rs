//! Digest (hash) algorithms backed by wolfCrypt.
//!
//! Each type implements the RustCrypto [`digest`](digest_trait) 0.10 traits
//! (`OutputSizeUser`, `BlockSizeUser`, `Update`, `FixedOutput`,
//! `FixedOutputReset`, `Reset`, `HashMarker`) so they satisfy the
//! blanket `Digest` impl automatically.
//!
//! All implementations use the native `wc_Sha*` functions via heap-allocated
//! context shims in `compat_shim.c`.  This works in any build that includes
//! the corresponding wolfCrypt SHA source files.
//!
//! Callers should `use digest_trait::Digest` (re-exported as
//! `wolfcrypt::digest::digest_trait`) for the full API:
//! `new()`, `update()`, `finalize()`, `finalize_reset()`, `reset()`.

use generic_array::GenericArray;
use typenum::*;

// Re-export the trait crate types we use in our public API.
pub use digest_trait;

// ======================================================================
// Native wc_Sha* digest types.
//
// The context is heap-allocated by compat_shim.c so Rust never needs
// to know the layout of wc_Sha256 / wc_Sha512 / wc_Sha3 / etc.
// ======================================================================

/// Internal macro that stamps out a native wc_Sha* digest wrapper.
///
/// The generated struct holds an opaque heap-allocated context pointer
/// and delegates all operations to C shim wrappers in compat_shim.c.
macro_rules! impl_digest_native {
    (
        $name:ident,
        $new_fn:path,
        $update_fn:path,
        $final_fn:path,
        $free_fn:path,
        $copy_fn:path,
        $output_size:ty,
        $block_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut core::ffi::c_void,
        }

        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl Default for $name {
            fn default() -> Self {
                let ctx = unsafe { $new_fn() };
                assert!(!ctx.is_null(), concat!(stringify!($name), ": context allocation failed"));
                Self { ctx }
            }
        }

        #[$cfg_gate]
        impl Clone for $name {
            fn clone(&self) -> Self {
                let mut new_ctx: *mut core::ffi::c_void = core::ptr::null_mut();
                let rc = unsafe { $copy_fn(self.ctx, &mut new_ctx) };
                assert_eq!(rc, 0, concat!(stringify!($name), ": clone (copy) failed"));
                Self { ctx: new_ctx }
            }
        }

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                if !self.ctx.is_null() {
                    unsafe { $free_fn(self.ctx) };
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
                let rc = unsafe {
                    $update_fn(self.ctx, data.as_ptr(), data.len() as u32)
                };
                assert_eq!(rc, 0, concat!(stringify!($name), ": update failed"));
            }
        }

        #[$cfg_gate]
        impl digest_trait::FixedOutput for $name {
            fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
                let rc = unsafe { $final_fn(self.ctx, out.as_mut_ptr()) };
                assert_eq!(rc, 0, concat!(stringify!($name), ": finalize failed"));
                // Prevent Drop from double-freeing — free is our responsibility here.
                let ctx = self.ctx;
                self.ctx = core::ptr::null_mut();
                unsafe { $free_fn(ctx) };
            }
        }

        #[$cfg_gate]
        impl digest_trait::FixedOutputReset for $name {
            fn finalize_into_reset(
                &mut self,
                out: &mut GenericArray<u8, Self::OutputSize>,
            ) {
                let rc = unsafe { $final_fn(self.ctx, out.as_mut_ptr()) };
                assert_eq!(rc, 0, concat!(stringify!($name), ": finalize_into_reset failed"));
                // Re-init: free old context, allocate a fresh one.
                unsafe { $free_fn(self.ctx) };
                self.ctx = unsafe { $new_fn() };
                assert!(!self.ctx.is_null(), concat!(stringify!($name), ": re-init after reset failed"));
            }
        }

        #[$cfg_gate]
        impl digest_trait::Reset for $name {
            fn reset(&mut self) {
                unsafe { $free_fn(self.ctx) };
                self.ctx = unsafe { $new_fn() };
                assert!(!self.ctx.is_null(), concat!(stringify!($name), ": reset failed"));
            }
        }

        #[$cfg_gate]
        impl digest_trait::HashMarker for $name {}
    };
}

impl_digest_native!(
    Sha256,
    wolfcrypt_rs::wolfcrypt_sha256_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha256_update,
    wolfcrypt_rs::wolfcrypt_sha256_final,
    wolfcrypt_rs::wolfcrypt_sha256_free,
    wolfcrypt_rs::wolfcrypt_sha256_copy,
    U32, U64,
    cfg(wolfssl_sha256)
);

impl_digest_native!(
    Sha384,
    wolfcrypt_rs::wolfcrypt_sha384_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha384_update,
    wolfcrypt_rs::wolfcrypt_sha384_final,
    wolfcrypt_rs::wolfcrypt_sha384_free,
    wolfcrypt_rs::wolfcrypt_sha384_copy,
    U48, U128,
    cfg(wolfssl_sha384)
);

impl_digest_native!(
    Sha1,
    wolfcrypt_rs::wolfcrypt_sha1_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha1_update,
    wolfcrypt_rs::wolfcrypt_sha1_final,
    wolfcrypt_rs::wolfcrypt_sha1_free,
    wolfcrypt_rs::wolfcrypt_sha1_copy,
    U20, U64,
    cfg(wolfssl_sha1)
);

impl_digest_native!(
    Sha224,
    wolfcrypt_rs::wolfcrypt_sha224_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha224_update,
    wolfcrypt_rs::wolfcrypt_sha224_final,
    wolfcrypt_rs::wolfcrypt_sha224_free,
    wolfcrypt_rs::wolfcrypt_sha224_copy,
    U28, U64,
    cfg(wolfssl_sha224)
);

impl_digest_native!(
    Sha512,
    wolfcrypt_rs::wolfcrypt_sha512_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha512_update,
    wolfcrypt_rs::wolfcrypt_sha512_final,
    wolfcrypt_rs::wolfcrypt_sha512_free,
    wolfcrypt_rs::wolfcrypt_sha512_copy,
    U64, U128,
    cfg(wolfssl_sha512)
);

impl_digest_native!(
    Sha512_256,
    wolfcrypt_rs::wolfcrypt_sha512_256_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha512_256_update,
    wolfcrypt_rs::wolfcrypt_sha512_256_final,
    wolfcrypt_rs::wolfcrypt_sha512_256_free,
    wolfcrypt_rs::wolfcrypt_sha512_256_copy,
    U32, U128,
    cfg(wolfssl_sha512)
);

impl_digest_native!(
    Sha3_256,
    wolfcrypt_rs::wolfcrypt_sha3_256_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha3_256_update,
    wolfcrypt_rs::wolfcrypt_sha3_256_final,
    wolfcrypt_rs::wolfcrypt_sha3_256_free,
    wolfcrypt_rs::wolfcrypt_sha3_256_copy,
    U32, U136,
    cfg(wolfssl_sha3)
);

impl_digest_native!(
    Sha3_384,
    wolfcrypt_rs::wolfcrypt_sha3_384_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha3_384_update,
    wolfcrypt_rs::wolfcrypt_sha3_384_final,
    wolfcrypt_rs::wolfcrypt_sha3_384_free,
    wolfcrypt_rs::wolfcrypt_sha3_384_copy,
    U48, U104,
    cfg(wolfssl_sha3)
);

impl_digest_native!(
    Sha3_512,
    wolfcrypt_rs::wolfcrypt_sha3_512_ctx_new,
    wolfcrypt_rs::wolfcrypt_sha3_512_update,
    wolfcrypt_rs::wolfcrypt_sha3_512_final,
    wolfcrypt_rs::wolfcrypt_sha3_512_free,
    wolfcrypt_rs::wolfcrypt_sha3_512_copy,
    U64, U72,
    cfg(wolfssl_sha3)
);
