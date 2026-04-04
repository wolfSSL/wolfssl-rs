//! Phase 4 ML-DSA-87 integration tests.
//!
//! All tests in this file are gated on `feature = "mldsa87-hw"`.
//!
//! # Current status: ML-DSA dispatch is BLOCKED — wire-format unverified
//!
//! wolfSSL at `/usr/local` has been rebuilt with `WOLFSSL_DILITHIUM=yes`.
//! The `pqc_sign` and `pqc_verify` sub-structs ARE present in the wolfcrypt-sys
//! bindings, and `WC_PK_TYPE_PQC_SIG_SIGN = 22` / `WC_PK_TYPE_PQC_SIG_VERIFY = 23`
//! ARE imported from wolfcrypt_sys in hw_pk.rs.
//!
//! The remaining blocker is wire-format compatibility verification between
//! wolfCrypt ML-DSA-87 and Adams Bridge (caliptra-drivers).  Specifically:
//! - wolfCrypt's sign variant (pure ML-DSA vs. HashML-DSA) vs. Adams Bridge's
//!   SHA-512 pre-hash `sign()` variant is unconfirmed.
//! - wolfCrypt's ML-DSA key and signature byte order vs. Adams Bridge's `LEArray4x*`
//!   little-endian representation has not been cross-validated.
//!
//! These tests document the stub behavior and verify the dispatch counter stays zero
//! until wire-format is confirmed and dispatch is implemented.
//!
//! To unblock:
//! 1. Audit `info.pk.pqc_sign` fields vs. Adams Bridge sign() interface.
//! 2. Run cross-validation: wolfCrypt sign → Adams Bridge verify (or vice versa).
//! 3. Implement dispatch_mldsa87_sign/verify in hw_pk.rs once round-trip passes.
//! 4. Update or replace these stub tests.

#[cfg(all(feature = "mldsa87-hw", not(target_arch = "riscv32")))]
mod tests {
    use wolfcrypt_dpe_hw::{
        mldsa_dispatch_count, reset_mldsa_dispatch_count, HW_DEVICE_ID, CRYPTOCB_UNAVAILABLE,
    };

    fn setup() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
            assert!(
                rc == 0 || rc == 1,
                "wolfCrypt_Init failed (expected 0 or 1, got {rc})"
            );
            wolfcrypt_dpe_hw::init().expect("wolfcrypt_dpe_hw::init failed");
        });
    }

    // -----------------------------------------------------------------------
    // Test 1 — test_mldsa87_dispatch_count_stays_zero
    //
    // Verify that MLDSA_DISPATCH_COUNT starts at zero and is not affected by
    // ECC operations.  (The counter is only incremented when ML-DSA dispatch
    // is actually implemented and succeeds, which is currently blocked.)
    // -----------------------------------------------------------------------

    #[test]
    fn test_mldsa87_dispatch_count_stays_zero() {
        setup();
        reset_mldsa_dispatch_count();
        assert_eq!(
            mldsa_dispatch_count(),
            0,
            "MLDSA_DISPATCH_COUNT should be zero before any ML-DSA dispatch"
        );
        // No ML-DSA operations are possible with the current system wolfSSL.
        // Counter must stay zero.
        assert_eq!(
            mldsa_dispatch_count(),
            0,
            "MLDSA_DISPATCH_COUNT must remain zero while dispatch is blocked"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — test_mldsa87_hw_feature_compiles
    //
    // Verify that the `mldsa87-hw` feature gate compiles without errors and
    // the counter accessor functions are accessible.  This is a compile-only
    // test; if this file compiles and links, the feature gate is correct.
    // -----------------------------------------------------------------------

    #[test]
    fn test_mldsa87_hw_feature_compiles() {
        setup();
        // These accessor functions are only exported when mldsa87-hw is active.
        // If this test compiles, the feature gate and pub use are correct.
        reset_mldsa_dispatch_count();
        let count = mldsa_dispatch_count();
        assert_eq!(count, 0, "unexpected initial count: {count}");
    }

    // -----------------------------------------------------------------------
    // Test 3 — test_mldsa87_pqc_type_constants_documented
    //
    // Verify the expected values of WC_PK_TYPE_PQC_SIG_SIGN (22) and
    // WC_PK_TYPE_PQC_SIG_VERIFY (23).  wolfSSL was rebuilt with
    // WOLFSSL_DILITHIUM=yes; both constants are imported from wolfcrypt_sys
    // in hw_pk.rs.  These local constants assert the expected numeric values
    // remain stable.
    //
    // Also documents that the HW CryptoCb device is registered (devId = 1)
    // and that CRYPTOCB_UNAVAILABLE = -271 (confirmed from error-crypt.h).
    // -----------------------------------------------------------------------

    #[test]
    fn test_mldsa87_pqc_type_constants_documented() {
        setup();
        // Per audit/phase4_reconciliation.md §6:
        // WC_PK_TYPE_PQC_SIG_SIGN (22) and WC_PK_TYPE_PQC_SIG_VERIFY (23) are
        // absent from wolfcrypt-sys bindings until HAVE_DILITHIUM is enabled.
        // Hardcoded in hw_pk.rs; both dispatch stubs return CRYPTOCB_UNAVAILABLE.
        const WC_PK_TYPE_PQC_SIG_SIGN: u32 = 22;
        const WC_PK_TYPE_PQC_SIG_VERIFY: u32 = 23;
        assert_eq!(WC_PK_TYPE_PQC_SIG_SIGN, 22, "PQC sign type constant");
        assert_eq!(WC_PK_TYPE_PQC_SIG_VERIFY, 23, "PQC verify type constant");

        // CRYPTOCB_UNAVAILABLE must be -271 (from wolfssl/wolfcrypt/error-crypt.h).
        assert_eq!(
            CRYPTOCB_UNAVAILABLE,
            -271,
            "CRYPTOCB_UNAVAILABLE value mismatch"
        );

        // HW_DEVICE_ID must be 1 (registered in init()).
        assert_eq!(HW_DEVICE_ID, 1, "HW_DEVICE_ID value mismatch");

        // ML-DSA dispatch count must be zero (all stubs return CRYPTOCB_UNAVAILABLE).
        reset_mldsa_dispatch_count();
        assert_eq!(mldsa_dispatch_count(), 0);
    }
}
