//! HKDF (HMAC-based Key Derivation Function) backed by wolfCrypt.
//!
//! Provides [`WolfHkdfSha256`], [`WolfHkdfSha384`], and [`WolfHkdfSha512`]
//! with an API that matches the RustCrypto `hkdf` 0.12 `Hkdf` type:
//! [`new`](WolfHkdfSha256::new), [`from_prk`](WolfHkdfSha256::from_prk),
//! and [`expand`](WolfHkdfSha256::expand).
//!
//! These types call wolfCrypt's native `wc_HKDF_Extract`/`wc_HKDF_Expand`
//! directly (single FFI call per operation) rather than building HKDF from
//! HMAC in Rust.  The `hkdf` crate does not define a trait — it provides
//! a concrete `Hkdf<H>` struct — so there is no trait to implement here.
//!
//! If you need the standard `hkdf::Hkdf` type for generic code, our digest
//! types (e.g. [`Sha256`](crate::Sha256)) are fully compatible:
//!
//! ```ignore
//! use hkdf::SimpleHkdf;
//! use wolfcrypt::Sha256;
//!
//! let (prk, hkdf) = SimpleHkdf::<Sha256>::extract(Some(salt), ikm);
//! ```

use crate::error::{check, len_as_u32, WolfCryptError};
use generic_array::GenericArray;
use typenum::*;

/// Internal macro that stamps out a complete HKDF wrapper for one algorithm.
macro_rules! impl_hkdf {
    (
        $name:ident,
        $hash_type:expr,
        $output_size:ty,
        $cfg_gate:meta
    ) => {
        /// HKDF wrapper holding a pseudorandom key (PRK).
        ///
        /// Created via [`extract`](Self::extract) or [`from_prk`](Self::from_prk),
        /// then used to derive output keying material via [`expand`](Self::expand).
        #[$cfg_gate]
        pub struct $name {
            prk: GenericArray<u8, $output_size>,
        }

        #[$cfg_gate]
        impl $name {
            /// Combined extract-then-expand shorthand (matches `hkdf::Hkdf::new`).
            ///
            /// Equivalent to calling [`extract`](Self::extract) and discarding
            /// the raw PRK.  Provided so call-sites that follow the `hkdf`
            /// crate's API (`Hkdf::new(salt, ikm)`) work unchanged.
            pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
                let (_prk, inst) = Self::extract(salt, ikm);
                inst
            }

            /// Perform the HKDF-Extract step, returning the PRK and an
            /// instance ready for expansion.
            ///
            /// If `salt` is `None`, an all-zero salt of hash-length bytes is
            /// used per RFC 5869 §2.2.
            pub fn extract(
                salt: Option<&[u8]>,
                ikm: &[u8],
            ) -> (GenericArray<u8, $output_size>, Self) {
                let mut prk = GenericArray::<u8, $output_size>::default();

                let (salt_ptr, salt_len) = match salt {
                    Some(s) if !s.is_empty() => (s.as_ptr(), len_as_u32(s.len())),
                    _ => (core::ptr::null(), 0u32),
                };

                let (ikm_ptr, ikm_len) = if ikm.is_empty() {
                    (core::ptr::null(), 0u32)
                } else {
                    (ikm.as_ptr(), len_as_u32(ikm.len()))
                };

                // SAFETY: prk buffer is exactly OutputSize bytes which matches
                // the hash output length. salt_ptr/ikm_ptr are valid or null
                // with corresponding zero lengths.
                let rc = unsafe {
                    wolfcrypt_rs::wc_HKDF_Extract(
                        $hash_type,
                        salt_ptr,
                        salt_len,
                        ikm_ptr,
                        ikm_len,
                        prk.as_mut_ptr(),
                    )
                };
                // wc_HKDF_Extract should not fail with valid inputs.
                assert_eq!(rc, 0, "wc_HKDF_Extract failed (invalid hash type)");

                let inst = Self { prk: prk.clone() };
                (prk, inst)
            }

            /// Create an HKDF instance from a pre-existing PRK.
            ///
            /// Returns an error if `prk` is shorter than the hash output size.
            pub fn from_prk(prk: &[u8]) -> Result<Self, WolfCryptError> {
                let hash_len = <$output_size as typenum::Unsigned>::USIZE;
                if prk.len() < hash_len {
                    return Err(WolfCryptError::INVALID_INPUT);
                }
                let mut arr = GenericArray::<u8, $output_size>::default();
                arr.copy_from_slice(&prk[..hash_len]);
                Ok(Self { prk: arr })
            }

            /// Perform the HKDF-Expand step, writing output keying material
            /// into `okm`.
            pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), WolfCryptError> {
                let (info_ptr, info_len) = if info.is_empty() {
                    (core::ptr::null(), 0u32)
                } else {
                    (info.as_ptr(), len_as_u32(info.len()))
                };

                // SAFETY: self.prk is exactly OutputSize bytes. okm is a valid
                // mutable buffer. info_ptr is valid or null with zero length.
                let rc = unsafe {
                    wolfcrypt_rs::wc_HKDF_Expand(
                        $hash_type,
                        self.prk.as_ptr(),
                        len_as_u32(self.prk.len()),
                        info_ptr,
                        info_len,
                        okm.as_mut_ptr(),
                        len_as_u32(okm.len()),
                    )
                };
                check(rc, "wc_HKDF_Expand")
            }
        }

        #[$cfg_gate]
        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                self.prk.zeroize();
            }
        }
    };
}

// ======================================================================
// Stamp out all three HKDF types
// ======================================================================

impl_hkdf!(
    WolfHkdfSha256,
    wolfcrypt_rs::WC_HASH_TYPE_SHA256,
    U32,
    cfg(wolfssl_hkdf)
);

impl_hkdf!(
    WolfHkdfSha384,
    wolfcrypt_rs::WC_HASH_TYPE_SHA384,
    U48,
    cfg(all(wolfssl_hkdf, wolfssl_sha384))
);

impl_hkdf!(
    WolfHkdfSha512,
    wolfcrypt_rs::WC_HASH_TYPE_SHA512,
    U64,
    cfg(all(wolfssl_hkdf, wolfssl_sha512))
);
