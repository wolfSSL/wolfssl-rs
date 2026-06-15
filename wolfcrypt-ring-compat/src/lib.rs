// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT
#![cfg_attr(not(clippy), allow(unexpected_cfgs))]
#![cfg_attr(not(clippy), allow(unknown_lints))]
#![allow(clippy::doc_markdown)]
//! A [*ring*](https://github.com/briansmith/ring)-compatible crypto library using the cryptographic
//! operations provided by [*wolfSSL*](https://github.com/wolfSSL/wolfssl). It uses the
//! [*wolfcrypt-rs*](https://crates.io/crates/wolfcrypt-rs)
//! Foreign Function Interface (FFI) crate found in this repository for invoking *wolfSSL*.
//! Enable the `fips` feature to build against the FIPS 140-3 validated source.
//!
//! # Build
//!
//! `wolfcrypt-ring` is available through [crates.io](https://crates.io/crates/wolfcrypt-ring). It can
//! be added to your project in the [standard way](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
//! using `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! wolfcrypt-ring = "1"
//! ```
//! Consuming projects will need a C/C++ compiler to build.
//!
//! **Non-FIPS builds (default):**
//! * CMake is **never** required
//! * Bindgen is **never** required (pre-generated bindings are provided)
//! * Go is **never** required
//!
//! **FIPS builds:** Require **CMake**, **Go**, and potentially **bindgen** depending on the target platform.
//!
//! See the [wolfSSL documentation](https://www.wolfssl.com/documentation/) for guidance on installing build requirements.
//!
//! # Feature Flags
//!
//! #### alloc (default)
//!
//! Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
//! from the "alloc" feature of *ring*.) Currently, this is required by the `io::writer` module.
//!
//! #### ring-io (default)
//!
//! Enable feature to access the  `io`  module.
//!
//! #### ring-sig-verify (default)
//!
//! Enable feature to preserve compatibility with ring's `signature::VerificationAlgorithm::verify`
//! function. This adds a requirement on `untrusted = "0.7.1"`.
//!
//! #### fips
//!
//! Enable this feature to have wolfcrypt-ring build wolfcrypt-rs against the FIPS 140-3
//! validated wolfSSL source module. Requires `WOLFSSL_FIPS_SOURCE_DIR` to be set.
//!
//! Consult with your local FIPS compliance team to determine the version of the wolfSSL FIPS module
//! that you require. Consumers needing to remain on a previous version should pin to specific
//! versions of wolfcrypt-ring to avoid automatically being upgraded to a newer module version.
//! (See [cargo's documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
//! on how to specify dependency versions.)
//!
//! Please see the [wolfSSL FIPS documentation](https://www.wolfssl.com/license/fips/)
//! for relevant security policies and information on supported operating environments.
//! We will also update our release notes and documentation to reflect any changes in FIPS certification status.
//!
//! #### non-fips
//!
//! Enable this feature to guarantee that the non-FIPS [*wolfcrypt-rs*](https://crates.io/crates/wolfcrypt-rs)
//! crate is used for cryptographic implementations. This feature is mutually exclusive with the `fips`
//! feature - enabling both will result in a compile-time error. Use this feature when you need a
//! compile-time guarantee that your build is using the non-FIPS cryptographic module.
//!
//! #### asan
//!
//! Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
//! ["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
//! of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).
//!
//! #### bindgen
//!
//! Causes `wolfcrypt-rs` to generate fresh bindings for wolfSSL instead of using
//! the pre-generated bindings. This feature requires `libclang` to be installed. See the
//! [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)
//! for [rust-bindgen](https://github.com/rust-lang/rust-bindgen)
//!
//! #### prebuilt-nasm
//!
//! Enables the use of crate provided prebuilt NASM objects under certain conditions. This only affects builds for
//! Windows x86-64 platforms. This feature is ignored if the "fips" feature is also enabled.
//!
//! Use of prebuilt NASM objects is prevented if either of the following conditions are true:
//! * The NASM assembler is detected in the build environment
//! * `WOLFCRYPT_FFI_PREBUILT_NASM` environment variable is set with a value of `0`
//!
//! Be aware that [features are additive](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification);
//! by enabling this feature, it is enabled for all crates within the same build.
//!
//! #### dev-tests-only
//!
//! Enables the `rand::unsealed` module, which re-exports the normally sealed `SecureRandom` trait.
//! This allows consumers to provide their own implementations of `SecureRandom` (e.g., a
//! deterministic RNG) for testing purposes. When enabled, a `mut_fill` method is also available on
//! `SecureRandom`.
//!
//! This feature is restricted to **dev/debug profile builds only** — attempting to use it in a
//! release build will result in a compile-time error.
//!
//! It can be enabled in two ways:
//! * **Feature flag:** `cargo test --features dev-tests-only`
//! * **Environment variable:** `WOLFCRYPT_RING_DEV_TESTS_ONLY=1 cargo test`
//!
//! **⚠️ Warning:** This feature is intended **only** for development and testing. It must not be
//! used in production builds. The `rand::unsealed` module and `mut_fill` method are not part of the
//! stable public API and may change without notice.
//!
//! # Use of prebuilt NASM objects
//!
//! Prebuilt NASM objects are **only** applicable to Windows x86-64 platforms. They are **never** used on any other platform (Linux, macOS, etc.).
//!
//! For Windows x86 and x86-64, NASM is required for assembly code compilation. On these platforms,
//! we recommend that you install [the NASM assembler](https://www.nasm.us/). **If NASM is
//! detected in the build environment, it is always used** to compile the assembly files. Prebuilt NASM objects are only used as a fallback.
//!
//! If a NASM assembler is not available, and the "fips" feature is not enabled, then the build fails unless one of the following conditions are true:
//!
//! * You are building for `x86-64` and either:
//!    * The `WOLFCRYPT_FFI_PREBUILT_NASM` environment variable is found and has a value of "1"; OR
//!    * `WOLFCRYPT_FFI_PREBUILT_NASM` is *not found* in the environment AND the "prebuilt-nasm" feature has been enabled.
//!
//! If the above cases apply, then the crate provided prebuilt NASM objects will be used for the build. To prevent usage of prebuilt NASM
//! objects, install NASM in the build environment and/or set the variable `WOLFCRYPT_FFI_PREBUILT_NASM` to `0` in the build environment to prevent their use.
//!
//! ## About prebuilt NASM objects
//!
//! Prebuilt NASM objects are generated using automation similar to the crate provided pregenerated bindings. See the repository's
//! [GitHub workflow configuration](https://github.com/wolfSSL/wolfssl-rs) for more information.
//! The prebuilt NASM objects are checked into the repository and are available for inspection.
//! For each PR submitted, CI verifies that the NASM objects newly built from source match the
//! NASM objects currently in the repository.
//!
//! # *ring*-compatibility
//!
//! Although this library attempts to be fully compatible with *ring* (v0.16.x), there are a few places where our
//! behavior is observably different.
//!
//! * Our implementation requires the `std` library. We currently do not support a
//!   [`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
//! * `wolfcrypt-ring` supports the platforms supported by `wolfcrypt-rs` and wolfSSL. See the
//!   [wolfSSL platform support](https://www.wolfssl.com/docs/) documentation for details.
//! * `Ed25519KeyPair::from_pkcs8` and `Ed25519KeyPair::from_pkcs8_maybe_unchecked` both support
//!   parsing of v1 or v2 PKCS#8 documents. If a v2 encoded key is provided to either function,
//!   public key component, if present, will be verified to match the one derived from the encoded
//!   private key.
//!
//! # Post-Quantum Cryptography
//!
//! Details on the post-quantum algorithms supported by wolfcrypt-ring can be found in the
//! [wolfSSL documentation](https://www.wolfssl.com/documentation/).
//!
//! # Motivation
//!
//! Rust developers increasingly need to deploy applications that meet US and Canadian government
//! cryptographic requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic
//! and performant Rust, built around wolfSSL. We found that the popular ring (v0.16)
//! library fulfilled much of the cryptographic needs in the Rust community, but it did not meet the
//! needs of developers with FIPS requirements. Our intention is to contribute a drop-in replacement
//! for ring that provides FIPS support and is compatible with the ring API. Rust developers with
//! prescribed cryptographic requirements can seamlessly integrate wolfcrypt-ring into their
//! applications.

// NOTE: no_std mode still requires the `alloc` crate (a global allocator).
// This is `no_std + alloc`, not bare-metal no_std.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::exhaustive_enums)]
#![cfg_attr(wolfcrypt_ring_compat_docsrs, feature(doc_cfg))]

#[macro_use]
extern crate alloc;
extern crate wolfcrypt_rs;

/// Crate-internal prelude for no_std: re-export alloc types that the std
/// prelude normally provides. Modules that need Vec/Box/String import this.
#[cfg(not(feature = "std"))]
pub(crate) mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
}

pub mod aead;
pub mod agreement;
pub mod cmac;
pub mod constant_time;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
#[cfg(feature = "ring-io")]
pub mod io;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod signature;
pub mod test;

mod bn;
mod buffer;
mod cbb;
pub mod cipher;
mod debug;
mod ec;
mod ed25519;
pub mod encoding;
mod endian;
mod evp_pkey;
mod fips;
mod hex;
pub mod iv;
#[cfg(feature = "unstable")]
pub mod kdf;
#[cfg(all(feature = "unstable", wolfssl_mlkem))]
pub mod kem;
pub mod key_wrap;
#[cfg(all(feature = "unstable", not(feature = "fips"), wolfssl_dilithium))]
mod pqdsa;
mod ptr;
pub mod rsa;
pub mod tls_prf;
pub mod unstable;

use core::ffi::CStr;
pub(crate) use debug::derive_debug_via_id;

use crate::wolfcrypt_rs::{
    wc_GetErrorString, CRYPTO_library_init, ERR_get_error, FIPS_mode, ERR_GET_LIB, ERR_GET_REASON,
};

static START: spin::Once<()> = spin::Once::new();

#[inline]
/// Initialize the *wolfSSL* library. (This should generally not be needed.)
pub fn init() {
    // SAFETY: CRYPTO_library_init is safe to call once; guarded by spin::Once.
    START.call_once(|| unsafe {
        let _ = CRYPTO_library_init();
    });
}

#[cfg(feature = "fips")]
/// Panics if the underlying implementation is not FIPS, otherwise it returns.
///
/// # Panics
/// Panics if the underlying implementation is not FIPS.
pub fn fips_mode() {
    // PANIC-SAFETY: Documented panic; use try_fips_mode for fallible variant
    try_fips_mode().unwrap();
}

/// Indicates whether the underlying implementation is FIPS.
///
/// # Errors
/// Return an error if the underlying implementation is not FIPS, otherwise Ok.
pub fn try_fips_mode() -> Result<(), &'static str> {
    init();
    // SAFETY: FIPS_mode is a read-only query with no preconditions.
    match unsafe { FIPS_mode() } {
        1 => Ok(()),
        _ => Err("FIPS mode not enabled!"),
    }
}

#[expect(dead_code)]
unsafe fn dump_error() {
    // SAFETY: ERR_get_error/wc_GetErrorString are read-only diagnostic functions;
    // CStr::from_ptr requires the returned pointer to be a valid null-terminated C string,
    // which wc_GetErrorString guarantees.
    unsafe {
        let err = ERR_get_error();
        let lib = ERR_GET_LIB(err);
        let reason = ERR_GET_REASON(err);
        let func = 0i32;
        let error_msg = CStr::from_ptr(wc_GetErrorString(err as core::ffi::c_int));
        #[cfg(feature = "std")]
        std::eprintln!(
            "Raw Error -- {error_msg:?}\nErr: {err}, Lib: {lib}, Reason: {reason}, Func: {func}"
        );
        let _ = (error_msg, lib, reason, func);
    }
}

mod sealed {
    /// Traits that are designed to only be implemented internally in *wolfcrypt-ring*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::{dump_error, init};

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_dump() {
        // SAFETY: dump_error only calls read-only diagnostic FFI functions.
        unsafe {
            dump_error();
        }
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_fips() {
        assert!({ crate::try_fips_mode().is_err() });
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_fips() {
        crate::fips_mode();
    }
}
