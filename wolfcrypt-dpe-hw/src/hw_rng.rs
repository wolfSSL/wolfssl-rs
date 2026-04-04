//! Hardware RNG dispatch for the Caliptra ITRNG.
//!
//! # Intercept point choice
//!
//! ## Why `CUSTOM_RAND_GENERATE_BLOCK` on riscv32 (firmware target)
//!
//! The Caliptra hardware implements an AES-256-CTR-DRBG (SP 800-90A) in
//! silicon.  FIPS 140-3 / SP 800-90C requires using the hardware DRBG
//! directly rather than stacking a second software DRBG on top of it.
//! - `user_settings_cryptocb_only.h` defines
//!   `CUSTOM_RAND_GENERATE_BLOCK = caliptra_generate_random_block`, which
//!   wolfSSL calls on every `wc_RNG_GenerateBlock`, bypassing HASH-DRBG.
//! - The C shim in `caliptra_seed.c` (compiled for riscv32 + caliptra-2x)
//!   forwards `caliptra_generate_random_block(output, sz)` to
//!   `caliptra_hw_generate_seed(output, sz)` (this file).
//!
//! ## Why CryptoCb `WC_ALGO_TYPE_RNG = 4` on non-riscv32 (host / test)
//!
//! Phase 1 added `WOLF_CRYPTO_CB` to `user_settings.h` and the
//! `cryptocb.h` header to `headers.h`.  The generated bindings now expose
//! `wc_CryptoInfo.__bindgen_anon_1.rng` with fields `{rng, out, sz}`.
//! wolfSSL routes `wc_RNG_GenerateBlock` through CryptoCb with
//! `WC_ALGO_TYPE_RNG` when the `WC_RNG` was initialised via
//! `wc_InitRng_ex` with a non-`INVALID_DEVID`.  This enables per-call
//! ITRNG dispatch without touching the riscv32 build.
//!
//! ## Rejected alternative: CryptoCb `WC_ALGO_TYPE_SEED = 5`
//!
//! `WC_ALGO_TYPE_SEED` fires during `wc_InitRng` (seed-time only).
//! Per-block dispatch is not possible through that path.
//! `WC_ALGO_TYPE_RNG` fires on every `wc_RNG_GenerateBlock` call, which
//! is required by the test spec (TRNG_DISPATCH_COUNT must increment once
//! per generate call).
//!
//! # Host-path ITRNG simulation
//!
//! On the host (non-riscv32) the "ITRNG" is simulated by calling
//! `wolfcrypt_sys::wc_GenerateSeed` with a fresh `OS_Seed`.  This reads
//! `/dev/urandom` on Linux, providing the same quality of entropy the
//! hardware would produce, while keeping the implementation no_std
//! compatible (no extra crate dependencies).
//!
//! # Software PRNG fallback
//!
//! There is none.  If the ITRNG call fails (or `INJECT_TRNG_ERROR` is
//! set), `dispatch_rng` returns a non-zero error code.  The caller
//! receives an error from `wc_RNG_GenerateBlock`.

use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// TRNG dispatch counter
// ---------------------------------------------------------------------------

/// Number of successful ITRNG calls since the last [`reset_trng_dispatch_count`].
///
/// Incremented **only** after the ITRNG call completes successfully and bytes
/// have been written to the output buffer.  Never incremented on error or
/// on the software DRBG path (`INVALID_DEVID`).
static TRNG_DISPATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns the current TRNG dispatch count.
pub fn trng_dispatch_count() -> usize {
    TRNG_DISPATCH_COUNT.load(Ordering::Relaxed)
}

/// Resets the TRNG dispatch counter to zero.
///
/// Call at the start of every test to prevent counter leaks from prior tests.
pub fn reset_trng_dispatch_count() {
    TRNG_DISPATCH_COUNT.store(0, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Test error injection hook
// ---------------------------------------------------------------------------

// The phase spec calls for `thread_local!{static INJECT_TRNG_ERROR: Cell<bool>}`.
// This crate is `#![no_std]`; `thread_local!` requires std and is unavailable.
// An `AtomicBool` provides identical semantics (set before the call, clear after)
// and is no_std-compatible.  Integration tests in tests/ access it via
// `wolfcrypt_dpe_hw::INJECT_TRNG_ERROR.store(true, Ordering::Relaxed)`.
//
// Not gated on `#[cfg(test)]` because integration tests compile the library
// without cfg(test) and cannot see cfg(test) items.  Instead gated on the
// `testing-hooks` feature so this symbol is absent from production builds.
// Any binary compiled without `--features testing-hooks` will not have this
// symbol in its public ABI, satisfying FIPS 140-3 software integrity
// requirements that prohibit production-accessible entropy-disabling hooks.
#[cfg(all(not(target_arch = "riscv32"), feature = "testing-hooks"))]
pub static INJECT_TRNG_ERROR: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Non-riscv32: CryptoCb WC_ALGO_TYPE_RNG dispatch
// ---------------------------------------------------------------------------

/// Dispatch a `WC_ALGO_TYPE_RNG` CryptoCb callback.
///
/// Called from [`crate::hw_callback`] when `info.algo_type == WC_ALGO_TYPE_RNG`.
///
/// Reads `info.__bindgen_anon_1.rng.{out, sz}`, fills the output with ITRNG
/// bytes, and increments [`TRNG_DISPATCH_COUNT`] on success.
///
/// Returns 0 on success, non-zero on error.  Never returns
/// [`crate::CRYPTOCB_UNAVAILABLE`] — the hardware path is always attempted.
///
/// # Safety
/// `info` must be a valid `wc_CryptoInfo` with `algo_type == WC_ALGO_TYPE_RNG`.
#[cfg(not(target_arch = "riscv32"))]
pub(crate) unsafe fn dispatch_rng(
    info: &mut wolfcrypt_sys::wc_CryptoInfo,
) -> core::ffi::c_int {
    let rng_info = &info.__bindgen_anon_1.rng;
    let out = rng_info.out;
    let sz = rng_info.sz;

    if sz == 0 {
        // Zero-length request: benign no-op.
        return 0;
    }
    if out.is_null() {
        // Null pointer with non-zero size: caller bug; return error so wolfSSL
        // sees a failure rather than silently delivering no bytes.
        return -1;
    }

    // Test injection: simulate ITRNG hardware fault.
    // TRNG_DISPATCH_COUNT must NOT increment on error.
    // Only compiled when `testing-hooks` feature is active.
    #[cfg(feature = "testing-hooks")]
    if INJECT_TRNG_ERROR.load(Ordering::Acquire) {
        return -1;
    }

    // Host-path ITRNG simulation: obtain entropy from the OS via wolfSSL's
    // wc_GenerateSeed (reads /dev/urandom / getrandom on Linux).  A fresh
    // OS_Seed is created each call so there is no shared state with the
    // wolfSSL DRBG.  devId is set to INVALID_DEVID (-2) so that
    // wc_GenerateSeed skips its own CryptoCb lookup and goes directly to the
    // OS entropy path — avoids infinite re-entry through our own callback.
    let mut os_seed: wolfcrypt_sys::OS_Seed = core::mem::zeroed();
    os_seed.devId = wolfcrypt_sys::INVALID_DEVID;
    let rc = wolfcrypt_sys::wc_GenerateSeed(&mut os_seed, out, sz);
    if rc != 0 {
        return rc;
    }

    // Increment ONLY after a successful ITRNG call.
    TRNG_DISPATCH_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

// ---------------------------------------------------------------------------
// riscv32: caliptra_generate_random_block → caliptra_hw_generate_seed
// ---------------------------------------------------------------------------
//
// On riscv32, wolfSSL calls `caliptra_generate_random_block(output, sz)` for
// every `wc_RNG_GenerateBlock` call because `user_settings_cryptocb_only.h`
// defines:
//   #define CUSTOM_RAND_GENERATE_BLOCK caliptra_generate_random_block
//
// This bypasses wolfSSL's software HASH-DRBG entirely.  The Caliptra hardware
// implements an AES-256-CTR-DRBG (SP 800-90A) in silicon; the hardware DRBG
// IS the FIPS-approved randomness source.
//
// The C shim in `caliptra_seed.c` (compiled only for riscv32 + caliptra-2x)
// delegates to `caliptra_hw_generate_seed(output, sz)` defined below.
//
// Firmware must call `wolfcrypt_dpe_hw::hw_rng::register_trng(trng)` before
// any call to `wc_RNG_GenerateBlock()`.

#[cfg(target_arch = "riscv32")]
use caliptra_drivers::Trng;

/// Global Trng instance registered by the firmware before wolfSSL is used.
#[cfg(target_arch = "riscv32")]
static REGISTERED_TRNG: spin::Mutex<Option<Trng>> = spin::Mutex::new(None);

/// Register the Caliptra TRNG for use by wolfSSL's DRBG seed function.
///
/// **Must be called before `wc_InitRng()` in the firmware startup sequence.**
/// Takes ownership of the `Trng` instance.
#[cfg(target_arch = "riscv32")]
pub fn register_trng(trng: Trng) {
    *REGISTERED_TRNG.lock() = Some(trng);
}

/// Called by `caliptra_generate_random_block()` in `caliptra_seed.c`.
///
/// Fills `output[0..sz]` with entropy from the Caliptra ITRNG.
/// Returns 0 on success, -1 (`HwError::TrngUnavailable`) on error.
///
/// # Safety
/// `output` must be writable for `sz` bytes.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn caliptra_hw_generate_seed(output: *mut u8, sz: u32) -> i32 {
    let sz = sz as usize;
    if sz == 0 {
        return 0;
    }
    if output.is_null() {
        return -1;
    }

    let mut guard = REGISTERED_TRNG.lock();
    let trng = match guard.as_mut() {
        Some(t) => t,
        // Trng not registered — firmware did not call register_trng() before
        // wc_InitRng(). Return error so wolfSSL does not silently use bad state.
        None => return -1,
    };

    let mut filled = 0usize;
    while filled < sz {
        let chunk = match trng.generate() {
            Ok(arr) => arr,
            Err(_) => return -1,
        };
        // SAFETY: caliptra_drivers::Array4x12 is a [u32; 12] (48 bytes).
        // Reading it as bytes is safe; we copy only what is needed.
        let chunk_bytes = core::slice::from_raw_parts(
            &chunk as *const _ as *const u8,
            core::mem::size_of_val(&chunk),
        );
        let to_copy = (sz - filled).min(chunk_bytes.len());
        core::ptr::copy_nonoverlapping(chunk_bytes.as_ptr(), output.add(filled), to_copy);
        filled += to_copy;
    }

    // Increment ONLY after all requested bytes have been generated.
    TRNG_DISPATCH_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}
