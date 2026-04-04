//! AES-CMAC algorithms backed by wolfCrypt's native wc_Cmac* API.
//!
//! Each type implements the RustCrypto [`digest`](digest_trait) 0.10 MAC traits
//! (`OutputSizeUser`, `KeySizeUser`, `KeyInit`, `Update`, `FixedOutput`,
//! `MacMarker`) so they satisfy the blanket `Mac` impl automatically.
//!
//! Callers should `use digest_trait::Mac` for the full API:
//! `new_from_slice()`, `update()`, `finalize()`, `verify_slice()`.

use digest_trait::{FixedOutput, KeyInit, OutputSizeUser, Update};
use generic_array::GenericArray;
use typenum::*;

/// Internal macro that stamps out a complete AES-CMAC wrapper for one key size.
///
/// The generated struct holds a heap-allocated wolfCrypt `Cmac` context
/// and delegates all operations through `wolfcrypt_cmac_*` C shims.
macro_rules! impl_cmac {
    (
        $name:ident,
        $new_fn:path,
        $key_size:ty,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        pub struct $name {
            ctx: *mut core::ffi::c_void,
        }

        // SAFETY: The Cmac context is heap-allocated and only accessed through
        // &self / &mut self.  Thread-safety is enforced by Rust's ownership rules.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                if !self.ctx.is_null() {
                    // SAFETY: ctx was allocated by wolfcrypt_cmac_*_new.
                    unsafe { wolfcrypt_rs::wolfcrypt_cmac_free(self.ctx) };
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
        impl $name {
            fn init_with_key(key: &[u8]) -> Option<Self> {
                use typenum::Unsigned;
                if key.len() != <$key_size as Unsigned>::USIZE {
                    return None;
                }
                // SAFETY: key pointer is valid; length has been validated above.
                let ctx = unsafe { $new_fn(key.as_ptr()) };
                if ctx.is_null() { return None; }
                Some(Self { ctx })
            }
        }

        #[$cfg_gate]
        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, <Self as crypto_common::KeySizeUser>::KeySize>) -> Self {
                Self::init_with_key(key.as_slice())
                    .expect("wolfcrypt_cmac_*_new failed with correct key size")
            }

            fn new_from_slice(key: &[u8]) -> Result<Self, crypto_common::InvalidLength> {
                Self::init_with_key(key).ok_or(crypto_common::InvalidLength)
            }
        }

        #[$cfg_gate]
        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                // SAFETY: ctx is valid; data pointer and length are correct.
                let rc = unsafe {
                    wolfcrypt_rs::wolfcrypt_cmac_update(
                        self.ctx,
                        data.as_ptr(),
                        data.len() as u32,
                    )
                };
                assert_eq!(rc, 0, concat!(stringify!($name), ": wolfcrypt_cmac_update failed"));
            }
        }

        #[$cfg_gate]
        impl FixedOutput for $name {
            fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
                let mut out_len: u32 = 16;
                // SAFETY: out is exactly 16 bytes; ctx is valid.
                let rc = unsafe {
                    wolfcrypt_rs::wolfcrypt_cmac_final(
                        self.ctx,
                        out.as_mut_ptr(),
                        &mut out_len,
                    )
                };
                assert_eq!(rc, 0, concat!(stringify!($name), ": wolfcrypt_cmac_final failed"));
                debug_assert_eq!(out_len, 16);
                // Prevent Drop from double-freeing.
                let ctx = self.ctx;
                self.ctx = core::ptr::null_mut();
                unsafe { wolfcrypt_rs::wolfcrypt_cmac_free(ctx) };
            }
        }

        #[$cfg_gate]
        impl digest_trait::MacMarker for $name {}
    };
}

impl_cmac!(
    WolfCmacAes128,
    wolfcrypt_rs::wolfcrypt_cmac_aes128_new,
    U16,
    cfg(wolfssl_cmac)
);

impl_cmac!(
    WolfCmacAes256,
    wolfcrypt_rs::wolfcrypt_cmac_aes256_new,
    U32,
    cfg(wolfssl_cmac)
);
