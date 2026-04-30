//! PBKDF2-HMAC key derivation backed by wolfCrypt's `wc_PBKDF2`.
//!
//! Provides standalone functions for deriving keys from passwords using
//! PBKDF2-HMAC with SHA-256, SHA-384, and SHA-512.
//!
//! These functions call wolfCrypt's native `wc_PBKDF2` directly (single FFI
//! call for the full iteration loop) rather than building PBKDF2 from HMAC
//! in Rust.  The `pbkdf2` crate's `pbkdf2_hmac` function requires a digest
//! implementing `CoreProxy`, which our EVP-based digests do not provide.
//!
//! The `pbkdf2` crate's generic `pbkdf2::<Prf>()` function additionally
//! requires `Prf: Sync`, which our EVP-based digest types cannot satisfy
//! (`EVP_MD_CTX` has interior mutable state).  If you need the generic
//! `pbkdf2` crate API, use it with a pure-Rust digest (e.g. `sha2::Sha256`)
//! instead.

use crate::error::{check, len_as_c_int, WolfCryptError};
use core::ffi::c_int;

/// Internal macro that stamps out a PBKDF2-HMAC function for one hash algorithm.
macro_rules! impl_pbkdf2 {
    (
        $fn_name:ident,
        $hash_type:expr,
        $cfg_gate:meta,
        $doc:expr
    ) => {
        #[doc = $doc]
        #[$cfg_gate]
        pub fn $fn_name(
            password: &[u8],
            salt: &[u8],
            rounds: u32,
            output: &mut [u8],
        ) -> Result<(), WolfCryptError> {
            // RFC 2898 requires a positive iteration count.  wolfCrypt's
            // wc_PBKDF2 takes `int iterations` — zero skips the loop
            // silently, and values above i32::MAX wrap negative (same
            // effect).  Catch both here.
            if rounds == 0 || rounds > c_int::MAX as u32 {
                return Err(WolfCryptError::INVALID_INPUT);
            }

            // SAFETY: All pointer/length pairs come from valid Rust slices.
            // `wc_PBKDF2` writes at most `k_len` bytes into `output`,
            // which is exactly `output.len()`. Returns 0 on success.
            let rc = unsafe {
                wolfcrypt_rs::wc_PBKDF2(
                    output.as_mut_ptr(),
                    password.as_ptr(),
                    len_as_c_int(password.len()),
                    salt.as_ptr(),
                    len_as_c_int(salt.len()),
                    rounds as c_int,
                    len_as_c_int(output.len()),
                    $hash_type,
                )
            };
            check(rc, "wc_PBKDF2")
        }
    };
}

impl_pbkdf2!(
    pbkdf2_hmac_sha256,
    wolfcrypt_rs::WC_HASH_TYPE_SHA256,
    cfg(wolfssl_pbkdf2),
    "Derive a key from `password` using PBKDF2-HMAC-SHA256.\n\n\
     Writes `output.len()` bytes of derived key material into `output`.\n\n\
     Returns an error if wolfCrypt rejects the parameters (e.g. zero-length\n\
     output or unsupported hash type)."
);

impl_pbkdf2!(
    pbkdf2_hmac_sha384,
    wolfcrypt_rs::WC_HASH_TYPE_SHA384,
    cfg(all(wolfssl_pbkdf2, wolfssl_sha384)),
    "Derive a key from `password` using PBKDF2-HMAC-SHA384.\n\n\
     Writes `output.len()` bytes of derived key material into `output`.\n\n\
     Returns an error if wolfCrypt rejects the parameters (e.g. zero-length\n\
     output or unsupported hash type)."
);

impl_pbkdf2!(
    pbkdf2_hmac_sha512,
    wolfcrypt_rs::WC_HASH_TYPE_SHA512,
    cfg(all(wolfssl_pbkdf2, wolfssl_sha512)),
    "Derive a key from `password` using PBKDF2-HMAC-SHA512.\n\n\
     Writes `output.len()` bytes of derived key material into `output`.\n\n\
     Returns an error if wolfCrypt rejects the parameters (e.g. zero-length\n\
     output or unsupported hash type)."
);
