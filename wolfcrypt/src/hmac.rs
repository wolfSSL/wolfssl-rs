//! HMAC algorithms backed by wolfCrypt's native wc_Hmac* API.
//!
//! Each type implements the RustCrypto [`hmac`](hmac_trait) 0.12 traits
//! (`OutputSizeUser`, `KeySizeUser`, `KeyInit`, `Update`, `FixedOutput`,
//! `MacMarker`) so they satisfy the blanket `Mac` impl automatically.
//!
//! Callers should `use hmac_trait::Mac` for the full API:
//! `new_from_slice()`, `update()`, `finalize()`, `verify_slice()`.

use digest_trait::{FixedOutput, KeyInit, OutputSizeUser, Update};
use generic_array::GenericArray;
use typenum::*;

/// Internal macro that stamps out a complete HMAC wrapper for one algorithm.
///
/// The generated struct holds a heap-allocated wolfCrypt `Hmac` context
/// and delegates all operations through `wolfcrypt_hmac_*` C shims.
macro_rules! impl_hmac {
    (
        $name:ident,
        $new_fn:path,
        $output_size:ty,
        $key_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut core::ffi::c_void,
        }

        // SAFETY: The Hmac context is heap-allocated and only accessed through
        // &self / &mut self.  wolfCrypt's HMAC API is thread-safe when a
        // context is used from a single thread, which Rust's ownership rules enforce.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                if !self.ctx.is_null() {
                    // SAFETY: ctx was allocated by wolfcrypt_hmac_*_new.
                    unsafe { wolfcrypt_rs::wolfcrypt_hmac_free(self.ctx) };
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
            fn init_with_key(key: &[u8]) -> Self {
                // SAFETY: key pointer and length are correct from the slice reference.
                let ctx = unsafe { $new_fn(key.as_ptr(), key.len() as u32) };
                assert!(
                    !ctx.is_null(),
                    concat!(stringify!($name), ": wolfcrypt_hmac_*_new returned NULL")
                );
                Self { ctx }
            }
        }

        #[$cfg_gate]
        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, <Self as crypto_common::KeySizeUser>::KeySize>) -> Self {
                Self::init_with_key(key.as_slice())
            }

            fn new_from_slice(key: &[u8]) -> Result<Self, crypto_common::InvalidLength> {
                Ok(Self::init_with_key(key))
            }
        }

        #[$cfg_gate]
        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                // SAFETY: ctx is valid; data pointer and length are correct.
                let rc = unsafe {
                    wolfcrypt_rs::wolfcrypt_hmac_update(self.ctx, data.as_ptr(), data.len() as u32)
                };
                assert_eq!(
                    rc, 0,
                    concat!(stringify!($name), ": wolfcrypt_hmac_update failed")
                );
            }
        }

        #[$cfg_gate]
        impl FixedOutput for $name {
            fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
                // SAFETY: out is exactly OutputSize bytes; ctx is valid.
                let rc = unsafe { wolfcrypt_rs::wolfcrypt_hmac_final(self.ctx, out.as_mut_ptr()) };
                assert_eq!(
                    rc, 0,
                    concat!(stringify!($name), ": wolfcrypt_hmac_final failed")
                );
                // Prevent Drop from double-freeing.
                let ctx = self.ctx;
                self.ctx = core::ptr::null_mut();
                unsafe { wolfcrypt_rs::wolfcrypt_hmac_free(ctx) };
            }
        }

        #[$cfg_gate]
        impl digest_trait::MacMarker for $name {}
    };
}

impl_hmac!(
    WolfHmacSha1,
    wolfcrypt_rs::wolfcrypt_hmac_sha1_new,
    U20,
    U20,
    cfg(wolfssl_hmac)
);

impl_hmac!(
    WolfHmacSha256,
    wolfcrypt_rs::wolfcrypt_hmac_sha256_new,
    U32,
    U32,
    cfg(wolfssl_hmac)
);

impl_hmac!(
    WolfHmacSha384,
    wolfcrypt_rs::wolfcrypt_hmac_sha384_new,
    U48,
    U48,
    cfg(all(wolfssl_hmac, wolfssl_sha384))
);

impl_hmac!(
    WolfHmacSha512,
    wolfcrypt_rs::wolfcrypt_hmac_sha512_new,
    U64,
    U64,
    cfg(all(wolfssl_hmac, wolfssl_sha512))
);
