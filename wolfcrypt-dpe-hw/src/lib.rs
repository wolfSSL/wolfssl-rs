//! wolfcrypt-dpe-hw: Caliptra hardware backend for wolfcrypt-dpe.
//!
//! This crate provides hardware-accelerated crypto via caliptra-drivers,
//! wired into wolfCrypt through the CryptoCb callback mechanism.
//!
//! The `caliptra-2x` feature activates all hardware paths.  Without it,
//! every function is a no-op / pure-software passthrough.
//!
//! # Target notes
//!
//! On `riscv32` bare-metal targets (e.g. `riscv32imc-unknown-none-elf`)
//! wolfSSL is not available as a linked library.  The `wolfcrypt-sys` crate
//! is therefore excluded for that architecture.  The CryptoCb registration
//! path is also excluded; a future phase will wire up caliptra-drivers
//! directly for RISC-V.

#![no_std]

use core::ffi::c_int;

// c_void is used by the hw_callback (caliptra-2x, non-riscv32 only).
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
use core::ffi::c_void;

// hw_hash implements SHA-256/384/512 and HMAC-384 dispatch, the HW dispatch
// counter, and the streaming state.  Only compiled when both caliptra-2x is
// active AND the target is non-riscv32 (wolfcrypt-sys is required).
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod hw_hash;

// Re-export the counter accessors so integration tests in tests/ can use them.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub use hw_hash::{hw_dispatch_count, reset_hw_dispatch_count};

// hw_rng implements the TRNG dispatch counter, the test error injection hook,
// and per-architecture ITRNG dispatch:
//   - non-riscv32: CryptoCb WC_ALGO_TYPE_RNG callback
//   - riscv32:     caliptra_hw_generate_seed (called from caliptra_seed.c)
#[cfg(feature = "caliptra-2x")]
pub mod hw_rng;

// hw_aes implements AES-256-GCM and AES-256-CBC dispatch via the `aes`,
// `ghash`, and `cbc` RustCrypto crates on the non-riscv32 host path.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod hw_aes;

// hw_pk implements ECC-384 sign/verify/ECDH dispatch and ML-DSA-87 stubs via
// RustCrypto's `p384` crate on the non-riscv32 host path.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod hw_pk;

// Re-export TRNG counter accessors and the error injection hook.
#[cfg(all(
    feature = "caliptra-2x",
    not(target_arch = "riscv32"),
    feature = "testing-hooks"
))]
pub use hw_rng::INJECT_TRNG_ERROR;
#[cfg(feature = "caliptra-2x")]
pub use hw_rng::{reset_trng_dispatch_count, trng_dispatch_count};

// Re-export AES dispatch counter accessors.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub use hw_aes::{aes_dispatch_count, reset_aes_dispatch_count};

// Re-export ECC and ML-DSA dispatch counter accessors.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub use hw_pk::{
    ecc_dispatch_count, mldsa_dispatch_count, reset_ecc_dispatch_count, reset_mldsa_dispatch_count,
};

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Device ID used when registering the Caliptra CryptoCb backend.
pub const HW_DEVICE_ID: c_int = 1;

/// Return value a CryptoCb callback uses to signal "not handled here;
/// fall through to software".  Mirrors wolfSSL's `CRYPTOCB_UNAVAILABLE` (-271,
/// confirmed from `wolfssl/wolfcrypt/error-crypt.h` and the generated bindings).
pub const CRYPTOCB_UNAVAILABLE: c_int = -271;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by wolfcrypt-dpe-hw functions.
///
/// Non-exhaustive: future hardware phases will add variants.
#[non_exhaustive]
#[derive(Debug)]
pub enum HwError {
    /// wolfCrypt global initialisation failed (wolfCrypt_Init returned this
    /// code).  In FIPS builds this means the mandatory power-on self-test did
    /// not complete.  `init()` returns this before attempting CryptoCb
    /// registration.
    WolfCryptInitFailed(i32),
    /// CryptoCb device registration failed.  Inner value is the wolfSSL error
    /// code returned by `wc_CryptoCb_RegisterDevice`.
    InitFailed(i32),
    /// The Caliptra ITRNG was unavailable at initialisation time or returned
    /// an error during entropy generation.
    ///
    /// On riscv32: `register_trng()` was not called before `wc_InitRng`, or
    /// `caliptra_drivers::Trng::generate()` returned an error.
    /// On non-riscv32: the OS entropy source (`wc_GenerateSeed`) failed.
    TrngUnavailable,
}

// Error category for HwError in the wolfcrypt-dpe CryptoError space.
// Uses the next available high-byte after 0x07_0000.
#[expect(dead_code)]
const ERR_HW_BASE: u32 = 0x08_0000;

// ---------------------------------------------------------------------------
// State query
// ---------------------------------------------------------------------------

/// Returns `true` when the `caliptra-2x` feature is active AND the current
/// target architecture supports wolfSSL-backed CryptoCb registration.
///
/// `init()` registers a CryptoCb device if and only if this returns `true`.
/// Tests use this to assert that init() is a true no-op on unsupported
/// configurations without relying on `WOLFSSL_LOCAL` internal symbols.
pub const fn has_caliptra_hw_backend() -> bool {
    cfg!(all(feature = "caliptra-2x", not(target_arch = "riscv32")))
}

// ---------------------------------------------------------------------------
// init()
// ---------------------------------------------------------------------------

/// Initialize the wolfCrypt hardware backend.
///
/// Without the `caliptra-2x` feature this is a no-op and always returns
/// `Ok(())`.
///
/// With `caliptra-2x` on non-RISC-V targets this:
/// 1. Calls `wolfCrypt_Init()` (idempotent; triggers FIPS POST in FIPS builds).
/// 2. Registers a CryptoCb device (ID [`HW_DEVICE_ID`]) whose callback
///    dispatches SHA-256/384/512 and HMAC-384 to the hardware path; all
///    other algorithms return [`CRYPTOCB_UNAVAILABLE`] causing wolfCrypt to
///    fall through to software.
///
/// On `riscv32` bare-metal targets this is always a no-op regardless of
/// features; the caliptra-drivers integration for RISC-V will be wired up
/// in a future phase.
pub fn init() -> Result<(), HwError> {
    #[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
    {
        // wolfCrypt_Init is required before any CryptoCb registration.
        // It is idempotent: returns 0 on the first call, 1 on subsequent calls.
        // In FIPS builds this also triggers the mandatory power-on self-test
        // (POST); skipping it means FIPS self-tests have not run.
        // SAFETY: wolfCrypt_Init has no preconditions.
        let wc_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
        if wc_rc != 0 && wc_rc != 1 {
            return Err(HwError::WolfCryptInitFailed(wc_rc));
        }

        // SAFETY: wc_CryptoCb_RegisterDevice stores (devId, cb, ctx) in a
        // global table; hw_callback is a static function so the pointer
        // is valid for the process lifetime.
        let rc = unsafe {
            wolfcrypt_sys::wc_CryptoCb_RegisterDevice(
                HW_DEVICE_ID,
                Some(hw_callback),
                core::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(HwError::InitFailed(rc));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hardware CryptoCb callback (caliptra-2x only, non-riscv32 only)
// ---------------------------------------------------------------------------

/// Main CryptoCb callback.  Dispatches hash and HMAC operations to the
/// hardware-backed implementations in `hw_hash`.  Returns
/// [`CRYPTOCB_UNAVAILABLE`] for all other algorithm types so wolfCrypt falls
/// through to software.
///
/// Only compiled when `caliptra-2x` feature is active on non-RISC-V targets.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub unsafe extern "C" fn hw_callback(
    _dev_id: c_int,
    info: *mut wolfcrypt_sys::wc_CryptoInfo,
    _ctx: *mut c_void,
) -> c_int {
    if info.is_null() {
        return CRYPTOCB_UNAVAILABLE;
    }
    let info = &mut *info;
    let algo_type = info.algo_type as u32;

    if algo_type == wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_HASH {
        hw_hash::dispatch_hash(info)
    } else if algo_type == wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_HMAC {
        hw_hash::dispatch_hmac(info)
    } else if algo_type == wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_RNG {
        hw_rng::dispatch_rng(info)
    } else if algo_type == wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_CIPHER {
        hw_aes::dispatch_cipher(info)
    } else if algo_type == wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_PK {
        hw_pk::dispatch_pk(info)
    } else {
        CRYPTOCB_UNAVAILABLE
    }
}

// ---------------------------------------------------------------------------
// Stub callback (kept for Phase 0 integration tests)
// ---------------------------------------------------------------------------

/// Stub CryptoCb callback.  Returns [`CRYPTOCB_UNAVAILABLE`] for every
/// operation so wolfCrypt falls through to software.
///
/// # Why `pub`
///
/// Integration tests live in `tests/` and form separate Rust crates; they
/// cannot access `pub(crate)` items.  `pub` is required for
/// `test_stub_callback_returns_unavailable` to take the function pointer
/// directly.  This symbol is not part of the stable public API.
///
/// Only compiled when `caliptra-2x` feature is active on non-RISC-V targets.
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub unsafe extern "C" fn stub_hw_callback(
    _dev_id: c_int,
    _info: *mut wolfcrypt_sys::wc_CryptoInfo,
    _ctx: *mut c_void,
) -> c_int {
    CRYPTOCB_UNAVAILABLE
}

/// Test-support helpers: counter reset aggregation.
///
/// Exposed as a public module so integration tests in `tests/` can call
/// `wolfcrypt_dpe_hw::test_support::reset_all_counters()`.
pub mod test_support;

/// Probe symbol: only present when `caliptra-2x` is active.
///
/// Used by `test_feature_flag_compile_guard` to verify the feature gate is
/// real at the linker level — the symbol must be absent from a library
/// compiled without `caliptra-2x`.
#[cfg(feature = "caliptra-2x")]
#[no_mangle]
pub unsafe extern "C" fn wolfcrypt_dpe_hw_caliptra2x_probe() -> c_int {
    CRYPTOCB_UNAVAILABLE
}
