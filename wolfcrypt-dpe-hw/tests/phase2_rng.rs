//! Phase 2 integration tests: ITRNG via CryptoCb WC_ALGO_TYPE_RNG dispatch.
//!
//! All tests:
//! - Run on host (target_arch != "riscv32"), feature = "caliptra-2x".
//! - Instantiate the caliptra sw-emulator (CaliptraRootBus) following the
//!   pattern established in phase1_hash.rs.
//! - Reset TRNG_DISPATCH_COUNT at the start of each test to prevent leaks.
//!
//! The INJECT_TRNG_ERROR hook is an AtomicBool (not thread_local!+Cell)
//! because the library is #![no_std].  Tests use
//! `wolfcrypt_dpe_hw::INJECT_TRNG_ERROR.store(true, Ordering::Relaxed)`
//! in place of `INJECT_TRNG_ERROR.with(|f| f.set(true))`.
//!
//! IMPORTANT: run with `-- --test-threads=1` because TRNG_DISPATCH_COUNT and
//! INJECT_TRNG_ERROR are global singletons.

#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod tests {
    use core::sync::atomic::Ordering;

    use wolfcrypt_dpe_hw::{
        trng_dispatch_count, reset_trng_dispatch_count, HW_DEVICE_ID, INJECT_TRNG_ERROR,
    };

    // -----------------------------------------------------------------------
    // Shared setup
    // -----------------------------------------------------------------------

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

    /// Minimal sw-emulator instantiation (Pattern 2 from recon_swemulator.md).
    fn make_emulator() -> caliptra_emu_periph::CaliptraRootBus {
        caliptra_emu_periph::CaliptraRootBus::new(
            caliptra_emu_periph::CaliptraRootBusArgs::default(),
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Initialize a WC_RNG with the given devId and generate `sz` bytes.
    /// Returns (rc, output_buffer).
    unsafe fn rng_generate(dev_id: core::ffi::c_int, sz: usize) -> (i32, Vec<u8>) {
        let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();
        let init_rc = wolfcrypt_sys::wc_InitRng_ex(&mut rng, core::ptr::null_mut(), dev_id);
        if init_rc != 0 {
            wolfcrypt_sys::wc_FreeRng(&mut rng);
            return (init_rc, vec![]);
        }
        let mut output = vec![0u8; sz];
        let gen_rc = wolfcrypt_sys::wc_RNG_GenerateBlock(
            &mut rng,
            output.as_mut_ptr(),
            output.len() as u32,
        );
        wolfcrypt_sys::wc_FreeRng(&mut rng);
        (gen_rc, output)
    }

    // -----------------------------------------------------------------------
    // Test 1 — test_trng_basic_output
    // -----------------------------------------------------------------------

    #[test]
    fn test_trng_basic_output() {
        setup();
        let _emu = make_emulator();

        reset_trng_dispatch_count();
        assert_eq!(trng_dispatch_count(), 0, "counter leak from previous test");

        let before = trng_dispatch_count();
        let (rc, output) = unsafe { rng_generate(HW_DEVICE_ID, 32) };
        assert_eq!(rc, 0, "wc_RNG_GenerateBlock(CALIPTRA_DEV_ID) failed: {rc}");
        assert_eq!(
            trng_dispatch_count(),
            before + 1,
            "TRNG dispatch count must increment by exactly 1"
        );
        assert_ne!(output, vec![0u8; 32], "output must not be all-zeros");
        assert_ne!(output, vec![0xffu8; 32], "output must not be all-0xFF");
    }

    // -----------------------------------------------------------------------
    // Test 2 — test_trng_multiple_block_sizes
    // -----------------------------------------------------------------------

    #[test]
    fn test_trng_multiple_block_sizes() {
        setup();
        let _emu = make_emulator();

        reset_trng_dispatch_count();
        assert_eq!(trng_dispatch_count(), 0, "counter leak from previous test");

        let sizes: [usize; 8] = [1, 7, 16, 32, 48, 64, 128, 256];
        let before = trng_dispatch_count();

        let mut last_output: Vec<u8> = vec![];
        for &sz in &sizes {
            let (rc, output) = unsafe { rng_generate(HW_DEVICE_ID, sz) };
            assert_eq!(
                rc, 0,
                "wc_RNG_GenerateBlock(CALIPTRA_DEV_ID, sz={sz}) failed: {rc}"
            );
            assert_eq!(output.len(), sz, "output length must equal requested size");

            if !last_output.is_empty() && sz == last_output.len() {
                // Only compare buffers of the same size — statistical check.
                assert_ne!(
                    output, last_output,
                    "consecutive same-size outputs must differ (size={sz})"
                );
            }
            last_output = output;
        }

        assert_eq!(
            trng_dispatch_count(),
            before + 8,
            "TRNG dispatch count must increment by 1 per generate call (8 total)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — test_software_fallback_does_not_use_trng
    // -----------------------------------------------------------------------

    #[test]
    fn test_software_fallback_does_not_use_trng() {
        setup();
        let _emu = make_emulator();

        reset_trng_dispatch_count();
        assert_eq!(trng_dispatch_count(), 0, "counter leak from previous test");

        let before = trng_dispatch_count();

        // Use INVALID_DEVID (-2) so wolfSSL takes the software DRBG path.
        // Our CryptoCb callback is NOT invoked on this path.
        let (rc, _output) =
            unsafe { rng_generate(wolfcrypt_sys::INVALID_DEVID, 32) };
        assert_eq!(rc, 0, "wc_RNG_GenerateBlock(INVALID_DEVID) must succeed: {rc}");

        assert_eq!(
            trng_dispatch_count(),
            before,
            "TRNG was called on software path — CryptoCb callback must not fire for INVALID_DEVID"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 — test_drbg_crate_uses_hw_entropy
    //
    // Verifies that WolfRng::new_with_dev_id (wolfcrypt crate) routes
    // wc_RNG_GenerateBlock through CryptoCb so TRNG_DISPATCH_COUNT increments.
    //
    // Uses wolfcrypt_sys::wc_InitRng_ex directly to mirror what
    // WolfRng::new_with_dev_id does internally (avoids adding wolfcrypt as a
    // dev-dependency, which would cause wolfcrypt-sys to be re-compiled from
    // source in the test binary).
    // -----------------------------------------------------------------------

    #[test]
    fn test_drbg_crate_uses_hw_entropy() {
        setup();
        let _emu = make_emulator();

        reset_trng_dispatch_count();
        assert_eq!(trng_dispatch_count(), 0, "counter leak from previous test");

        // Use wc_InitRng_ex with HW_DEVICE_ID to mirror WolfRng::new_with_dev_id.
        // This routes wc_RNG_GenerateBlock through CryptoCb → dispatch_rng.
        let before = trng_dispatch_count();
        let (rc, _buf) = unsafe { rng_generate(HW_DEVICE_ID, 64) };
        assert_eq!(rc, 0, "wc_RNG_GenerateBlock (HW_DEVICE_ID path) failed: {rc}");

        assert_eq!(
            trng_dispatch_count(),
            before + 1,
            "TRNG dispatch count must increment by exactly 1 — CryptoCb callback did not fire or incremented by wrong amount"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5 — test_no_software_prng_fallback  (anti-cheat)
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_software_prng_fallback() {
        setup();
        let _emu = make_emulator();

        reset_trng_dispatch_count();
        assert_eq!(trng_dispatch_count(), 0, "counter leak from previous test");

        // Simulate ITRNG hardware fault.
        // INJECT_TRNG_ERROR is an AtomicBool (no_std adaptation of thread_local!+Cell).
        // Use Release/Acquire ordering so the store is visible to the load in
        // dispatch_rng on weakly-ordered architectures.
        //
        // ClearOnDrop ensures the flag is always cleared even if rng_generate or
        // any subsequent assertion panics and unwinds the test thread.
        struct ClearOnDrop;
        impl Drop for ClearOnDrop {
            fn drop(&mut self) {
                INJECT_TRNG_ERROR.store(false, Ordering::Release);
            }
        }
        INJECT_TRNG_ERROR.store(true, Ordering::Release);
        let _clear_guard = ClearOnDrop;

        let before = trng_dispatch_count();
        let (rc, _output) = unsafe { rng_generate(HW_DEVICE_ID, 32) };
        // _clear_guard clears the flag on drop (including on unwind).

        // The generate attempt MUST fail (non-zero rc).
        // A zero rc here means the implementation silently fell back to the
        // software PRNG, which is forbidden.
        assert_ne!(
            rc, 0,
            "TRNG error was injected but wc_RNG_GenerateBlock returned success — \
             silent software PRNG fallback is forbidden"
        );

        // TRNG_DISPATCH_COUNT must NOT have incremented — the counter only
        // increases on successful ITRNG calls.
        assert_eq!(
            trng_dispatch_count(),
            before,
            "TRNG dispatch count must not increment on ITRNG error"
        );
    }
}
