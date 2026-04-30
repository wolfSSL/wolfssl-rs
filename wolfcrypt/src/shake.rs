//! SHAKE128 and SHAKE256 extendable-output functions (XOFs) backed by wolfCrypt.
//!
//! These are *not* fixed-output hashes -- they produce variable-length output.
//! There is no standard RustCrypto XOF trait in the `digest` 0.10 ecosystem
//! that fits an opaque FFI backend, so these types expose a bespoke API
//! modelled on the wolfCrypt C functions.
//!
//! # Usage
//!
//! ## Incremental absorb + fixed squeeze (`update` / `finalize`)
//!
//! ```ignore
//! use wolfcrypt::shake::Shake256;
//!
//! let mut xof = Shake256::new().unwrap();
//! xof.update(b"hello").unwrap();
//! xof.update(b" world").unwrap();
//! let mut out = [0u8; 64];
//! xof.finalize(&mut out).unwrap();
//! ```
//!
//! ## One-shot absorb + block-level squeeze (`absorb` / `squeeze_blocks`)
//!
//! ```ignore
//! use wolfcrypt::shake::Shake128;
//!
//! let mut xof = Shake128::new().unwrap();
//! xof.absorb(b"data").unwrap();
//! let mut out = [0u8; Shake128::BLOCK_SIZE * 3];
//! xof.squeeze_blocks(&mut out).unwrap();
//! ```

use crate::error::{check, len_as_u32, WolfCryptError};
use core::ffi::c_void;

/// Internal macro that stamps out a SHAKE XOF wrapper for one variant.
macro_rules! impl_shake {
    (
        $name:ident,
        $block_size:expr,
        $init_fn:path,
        $update_fn:path,
        $final_fn:path,
        $absorb_fn:path,
        $squeeze_fn:path,
        $free_fn:path,
        $cfg_gate:meta
    ) => {
        #[$cfg_gate]
        /// Extendable-output function (XOF) backed by wolfCrypt.
        ///
        /// Wraps the wolfCrypt `wc_Shake*` API.  The struct holds the
        /// C-level state inline (no heap allocation).
        pub struct $name {
            inner: wolfcrypt_rs::WcShake,
        }

        // SAFETY: WcShake is an opaque blob with no thread-local or
        // shared-mutable state.  Rust ownership rules ensure only one
        // thread accesses it at a time.
        #[$cfg_gate]
        unsafe impl Send for $name {}

        #[$cfg_gate]
        impl $name {
            /// SHAKE block size in bytes.
            ///
            /// SHAKE128 uses a 168-byte rate (1600 - 2*128 = 1344 bits).
            /// SHAKE256 uses a 136-byte rate (1600 - 2*256 = 1088 bits).
            pub const BLOCK_SIZE: usize = $block_size;

            /// Create a new, initialized SHAKE context.
            pub fn new() -> Result<Self, WolfCryptError> {
                let mut inner = wolfcrypt_rs::WcShake::zeroed();
                // SAFETY: `inner` is zero-initialized. NULL heap, default
                // devId (INVALID_DEVID = -2 in wolfCrypt).
                let rc = unsafe {
                    $init_fn(
                        &mut inner as *mut wolfcrypt_rs::WcShake,
                        core::ptr::null_mut::<c_void>(),
                        -2, // INVALID_DEVID
                    )
                };
                check(rc, stringify!($init_fn))?;
                Ok(Self { inner })
            }

            /// Incrementally absorb data into the sponge.
            ///
            /// May be called multiple times before [`finalize`](Self::finalize).
            pub fn update(&mut self, data: &[u8]) -> Result<(), WolfCryptError> {
                // SAFETY: `self.inner` is initialized. `data` pointer and
                // length are guaranteed correct by the slice reference.
                let rc = unsafe {
                    $update_fn(
                        &mut self.inner as *mut wolfcrypt_rs::WcShake,
                        data.as_ptr(),
                        len_as_u32(data.len()),
                    )
                };
                check(rc, stringify!($update_fn))
            }

            /// Squeeze `out.len()` bytes of output from the sponge.
            ///
            /// This finalizes the absorbed data and produces the XOF output.
            /// The output length is determined by the size of `out` --
            /// this is the core XOF property (variable-length output).
            ///
            /// After calling `finalize`, the context should not be reused.
            pub fn finalize(&mut self, out: &mut [u8]) -> Result<(), WolfCryptError> {
                // SAFETY: `self.inner` is initialized. `out` pointer and
                // length are guaranteed correct by the mutable slice.
                let rc = unsafe {
                    $final_fn(
                        &mut self.inner as *mut wolfcrypt_rs::WcShake,
                        out.as_mut_ptr(),
                        len_as_u32(out.len()),
                    )
                };
                check(rc, stringify!($final_fn))
            }

            /// One-shot absorb: feed all data at once (non-incremental).
            ///
            /// This is the non-incremental counterpart to [`update`](Self::update).
            /// Intended for use with [`squeeze_blocks`](Self::squeeze_blocks).
            pub fn absorb(&mut self, data: &[u8]) -> Result<(), WolfCryptError> {
                // SAFETY: same as `update`.
                let rc = unsafe {
                    $absorb_fn(
                        &mut self.inner as *mut wolfcrypt_rs::WcShake,
                        data.as_ptr(),
                        len_as_u32(data.len()),
                    )
                };
                check(rc, stringify!($absorb_fn))
            }

            /// Squeeze whole blocks from the sponge.
            ///
            /// `out.len()` **must** be a multiple of [`BLOCK_SIZE`](Self::BLOCK_SIZE).
            /// Returns [`WolfCryptError::InvalidInput`] otherwise.
            ///
            /// This is the block-level counterpart to [`finalize`](Self::finalize)
            /// and is intended for use after [`absorb`](Self::absorb).
            pub fn squeeze_blocks(&mut self, out: &mut [u8]) -> Result<(), WolfCryptError> {
                if out.len() % Self::BLOCK_SIZE != 0 {
                    return Err(WolfCryptError::InvalidInput);
                }
                let block_cnt = (out.len() / Self::BLOCK_SIZE) as u32;
                // SAFETY: `self.inner` is initialized and absorb has been
                // called.  `out` has room for `block_cnt * BLOCK_SIZE` bytes.
                let rc = unsafe {
                    $squeeze_fn(
                        &mut self.inner as *mut wolfcrypt_rs::WcShake,
                        out.as_mut_ptr(),
                        block_cnt,
                    )
                };
                check(rc, stringify!($squeeze_fn))
            }
        }

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: `self.inner` was initialized by `new()`.
                // `wc_Shake*_Free` is safe to call on an initialized context.
                unsafe {
                    $free_fn(&mut self.inner as *mut wolfcrypt_rs::WcShake);
                }
            }
        }
    };
}

impl_shake!(
    Shake128,
    168,
    wolfcrypt_rs::wc_InitShake128,
    wolfcrypt_rs::wc_Shake128_Update,
    wolfcrypt_rs::wc_Shake128_Final,
    wolfcrypt_rs::wc_Shake128_Absorb,
    wolfcrypt_rs::wc_Shake128_SqueezeBlocks,
    wolfcrypt_rs::wc_Shake128_Free,
    cfg(wolfssl_shake128)
);

impl_shake!(
    Shake256,
    136,
    wolfcrypt_rs::wc_InitShake256,
    wolfcrypt_rs::wc_Shake256_Update,
    wolfcrypt_rs::wc_Shake256_Final,
    wolfcrypt_rs::wc_Shake256_Absorb,
    wolfcrypt_rs::wc_Shake256_SqueezeBlocks,
    wolfcrypt_rs::wc_Shake256_Free,
    cfg(wolfssl_shake256)
);
