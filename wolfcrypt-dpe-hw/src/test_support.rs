//! Test-support utilities for wolfcrypt-dpe-hw integration tests.
//!
//! These functions are public so integration tests in `tests/` can call them
//! as `wolfcrypt_dpe_hw::test_support::reset_all_counters()`.  They are NOT
//! part of the stable public API.

/// Reset every dispatch counter to zero.
///
/// Call at the start of each integration test to prevent counter leakage from
/// prior tests.  Equivalent to calling each `reset_*_dispatch_count()`
/// individually.
///
/// Only available with `caliptra-2x` on non-RISC-V targets (the counters only
/// exist on those configurations).
#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
pub fn reset_all_counters() {
    crate::reset_hw_dispatch_count();
    crate::reset_trng_dispatch_count();
    crate::reset_aes_dispatch_count();
    crate::reset_ecc_dispatch_count();
    crate::reset_mldsa_dispatch_count();
}
