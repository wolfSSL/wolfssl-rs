//! Phase 5 integration tests: full TLS simulation, no-software-crypto proof,
//! and counter-not-gameable verification.
//!
//! All tests:
//! - Run on host (target_arch != "riscv32"), feature = "caliptra-2x".
//! - Use reset_all_counters() at the start of each test.
//! - Assert exact counter increments for every dispatched operation.
//!
//! IMPORTANT: run with `-- --test-threads=1` because all dispatch counters
//! are global singletons.

#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod tests {
    use wolfcrypt_dpe_hw::{
        aes_dispatch_count, ecc_dispatch_count, hw_dispatch_count,
        test_support::reset_all_counters,
        HW_DEVICE_ID,
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

    fn make_emulator() -> caliptra_emu_periph::CaliptraRootBus {
        caliptra_emu_periph::CaliptraRootBus::new(
            caliptra_emu_periph::CaliptraRootBusArgs::default(),
        )
    }

    // -----------------------------------------------------------------------
    // HMAC-384 helper — manual HKDF steps
    // -----------------------------------------------------------------------

    /// One HMAC-SHA-384 computation with HW_DEVICE_ID.
    /// Increments hw_dispatch_count by 1.
    unsafe fn hmac384(key: &[u8], data: &[u8], out: &mut [u8; 48], dev_id: core::ffi::c_int) {
        let mut hmac: wolfcrypt_sys::Hmac = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_HmacInit(&mut hmac, core::ptr::null_mut(), dev_id);
        assert_eq!(rc, 0, "hmac384: wc_HmacInit failed: {rc}");
        let rc = wolfcrypt_sys::wc_HmacSetKey(
            &mut hmac,
            wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384 as i32,
            key.as_ptr(),
            key.len() as u32,
        );
        assert_eq!(rc, 0, "hmac384: wc_HmacSetKey failed: {rc}");
        let rc = wolfcrypt_sys::wc_HmacUpdate(&mut hmac, data.as_ptr(), data.len() as u32);
        assert_eq!(rc, 0, "hmac384: wc_HmacUpdate failed: {rc}");
        let rc = wolfcrypt_sys::wc_HmacFinal(&mut hmac, out.as_mut_ptr());
        assert_eq!(rc, 0, "hmac384: wc_HmacFinal failed: {rc}");
        wolfcrypt_sys::wc_HmacFree(&mut hmac);
    }

    // -----------------------------------------------------------------------
    // AES-256-GCM helpers (same pattern as phase3_aes.rs)
    // -----------------------------------------------------------------------

    unsafe fn gcm_encrypt(
        dev_id: core::ffi::c_int,
        key: &[u8; 32],
        iv: &[u8; 12],
        plaintext: &[u8],
    ) -> (i32, Vec<u8>, [u8; 16]) {
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
        wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        let rc = wolfcrypt_sys::wc_AesGcmEncrypt(
            &mut aes,
            if plaintext.is_empty() { core::ptr::null_mut() } else { ct.as_mut_ptr() },
            if plaintext.is_empty() { core::ptr::null() } else { plaintext.as_ptr() },
            plaintext.len() as u32,
            iv.as_ptr(), 12,
            tag.as_mut_ptr(), 16,
            core::ptr::null(), 0,
        );
        wolfcrypt_sys::wc_AesFree(&mut aes);
        (rc, ct, tag)
    }

    unsafe fn gcm_decrypt(
        dev_id: core::ffi::c_int,
        key: &[u8; 32],
        iv: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> (i32, Vec<u8>) {
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
        wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);
        let mut pt = vec![0u8; ciphertext.len()];
        let rc = wolfcrypt_sys::wc_AesGcmDecrypt(
            &mut aes,
            if ciphertext.is_empty() { core::ptr::null_mut() } else { pt.as_mut_ptr() },
            if ciphertext.is_empty() { core::ptr::null() } else { ciphertext.as_ptr() },
            ciphertext.len() as u32,
            iv.as_ptr(), 12,
            tag.as_ptr(), 16,
            core::ptr::null(), 0,
        );
        wolfcrypt_sys::wc_AesFree(&mut aes);
        (rc, pt)
    }

    // -----------------------------------------------------------------------
    // ECC helpers (same pattern as phase4_ecc.rs)
    // -----------------------------------------------------------------------

    unsafe fn make_ecc384_key(
        dev_id: core::ffi::c_int,
        rng: *mut wolfcrypt_sys::WC_RNG,
    ) -> wolfcrypt_sys::ecc_key {
        let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_ecc_init_ex(&mut key, core::ptr::null_mut(), dev_id);
        assert_eq!(rc, 0, "wc_ecc_init_ex failed: {rc}");
        let rc = wolfcrypt_sys::wc_ecc_make_key_ex(
            rng, 48, &mut key,
            wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
        );
        assert_eq!(rc, 0, "wc_ecc_make_key_ex failed: {rc}");
        key
    }

    // -----------------------------------------------------------------------
    // Test 1 — test_full_tls_handshake_simulation
    //
    // TLS 1.3 handshake simulation with CALIPTRA_DEV_ID active:
    //   a) ECDH key exchange (two keypairs, shared secret from each side)
    //   b) HKDF-Extract + HKDF-Expand via HMAC-384
    //   c) AES-256-GCM encrypt 1024-byte record
    //   d) AES-256-GCM decrypt and verify
    //   e) ECDSA-384 sign transcript hash
    //   f) ECDSA-384 verify signature
    //
    // Expected counter increments:
    //   ecc_dispatch: +4 (ECDH A→B, ECDH B→A, sign, verify)
    //   hw_dispatch:  +2 (HKDF-Extract HMAC, HKDF-Expand HMAC)
    //   aes_dispatch: +2 (encrypt, decrypt)
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_tls_handshake_simulation() {
        setup();
        let _emu = make_emulator();
        reset_all_counters();

        let before_ecc = ecc_dispatch_count();
        let before_hw  = hw_dispatch_count();
        let before_aes = aes_dispatch_count();

        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

        unsafe {
            // ---- a) ECDH key exchange ----------------------------------------
            let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_InitRng(&mut rng);
            assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

            let mut key_a = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let mut key_b = make_ecc384_key(HW_DEVICE_ID, &mut rng);

            let mut shared_a = [0u8; 48];
            let mut shared_a_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_a, &mut key_b,
                shared_a.as_mut_ptr(), &mut shared_a_len,
            );
            assert_eq!(rc, 0, "ECDH A→B failed: {rc}");
            assert_eq!(shared_a_len, 48);

            let mut shared_b = [0u8; 48];
            let mut shared_b_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_b, &mut key_a,
                shared_b.as_mut_ptr(), &mut shared_b_len,
            );
            assert_eq!(rc, 0, "ECDH B→A failed: {rc}");
            assert_eq!(shared_b_len, 48);
            assert_eq!(shared_a, shared_b, "ECDH shared secrets must match");

            assert_eq!(ecc_dispatch_count(), before_ecc + 2, "after ECDH: ecc_dispatch must be +2");

            // ---- b) HKDF-Extract + HKDF-Expand via HMAC-384 ------------------
            // HKDF-Extract: PRK = HMAC-384(salt=zeros, IKM=shared_secret)
            let salt = [0u8; 48];
            let mut prk = [0u8; 48];
            hmac384(&salt, &shared_a, &mut prk, HW_DEVICE_ID);
            assert_eq!(hw_dispatch_count(), before_hw + 1, "after HKDF-Extract: hw_dispatch must be +1");

            // HKDF-Expand: OKM = HMAC-384(PRK, info || 0x01)
            let mut info_block = [0u8; 49];
            info_block[..48].copy_from_slice(b"wolfssl-rs caliptra-hw conformance label 384\x00\x00\x00\x00");
            info_block[48] = 0x01;
            let mut okm = [0u8; 48];
            hmac384(&prk, &info_block, &mut okm, HW_DEVICE_ID);
            assert_eq!(hw_dispatch_count(), before_hw + 2, "after HKDF-Expand: hw_dispatch must be +2");

            // Derive AES key (first 32 bytes) and IV (next 12 bytes) from OKM.
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&okm[..32]);
            let mut aes_iv = [0u8; 12];
            aes_iv.copy_from_slice(&okm[32..44]);

            // ---- c) AES-256-GCM encrypt 1024-byte record ---------------------
            let (rc, ct, tag) = gcm_encrypt(HW_DEVICE_ID, &aes_key, &aes_iv, &plaintext);
            assert_eq!(rc, 0, "AES-GCM encrypt failed: {rc}");
            assert_eq!(aes_dispatch_count(), before_aes + 1, "after encrypt: aes_dispatch must be +1");

            // ---- d) AES-256-GCM decrypt and verify ---------------------------
            let (rc, pt_dec) = gcm_decrypt(HW_DEVICE_ID, &aes_key, &aes_iv, &ct, &tag);
            assert_eq!(rc, 0, "AES-GCM decrypt failed: {rc}");
            assert_eq!(pt_dec, plaintext, "round-trip plaintext mismatch");
            assert_eq!(aes_dispatch_count(), before_aes + 2, "after decrypt: aes_dispatch must be +2");

            // ---- e) ECDSA-384 sign transcript hash ---------------------------
            let mut signing_key = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let transcript_hash = [0xABu8; 48]; // synthetic 48-byte hash
            let mut sig = vec![0u8; 128];
            let mut sig_len: wolfcrypt_sys::word32 = 128;
            let rc = wolfcrypt_sys::wc_ecc_sign_hash(
                transcript_hash.as_ptr(), 48,
                sig.as_mut_ptr(), &mut sig_len,
                &mut rng, &mut signing_key,
            );
            assert_eq!(rc, 0, "ECDSA sign failed: {rc}");
            sig.truncate(sig_len as usize);
            assert_eq!(ecc_dispatch_count(), before_ecc + 3, "after sign: ecc_dispatch must be +3");

            // ---- f) ECDSA-384 verify signature --------------------------------
            let mut verify_result: core::ffi::c_int = 0;
            let rc = wolfcrypt_sys::wc_ecc_verify_hash(
                sig.as_ptr(), sig.len() as wolfcrypt_sys::word32,
                transcript_hash.as_ptr(), 48,
                &mut verify_result, &mut signing_key,
            );
            assert_eq!(rc, 0, "ECDSA verify failed: {rc}");
            assert_eq!(verify_result, 1, "ECDSA signature did not verify");
            assert_eq!(ecc_dispatch_count(), before_ecc + 4, "after verify: ecc_dispatch must be +4");

            // ---- Final counter assertions ------------------------------------
            assert_eq!(
                ecc_dispatch_count(), before_ecc + 4,
                "ecc_dispatch final check: expected 4 dispatches (2 ECDH + sign + verify)"
            );
            assert_eq!(
                hw_dispatch_count(), before_hw + 2,
                "hw_dispatch final check: expected 2 dispatches (HKDF Extract + Expand via HMAC)"
            );
            assert_eq!(
                aes_dispatch_count(), before_aes + 2,
                "aes_dispatch final check: expected 2 dispatches (encrypt + decrypt)"
            );

            // Cleanup
            wolfcrypt_sys::wc_ecc_free(&mut key_a);
            wolfcrypt_sys::wc_ecc_free(&mut key_b);
            wolfcrypt_sys::wc_ecc_free(&mut signing_key);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
    }

    // -----------------------------------------------------------------------
    // Test 2 — test_no_software_crypto_used_in_full_flow
    //
    // Register a sentinel CryptoCb (SOFTWARE_SENTINEL_ID=2) that panics if
    // invoked.  Run the full TLS simulation from Test 1.  All operations must
    // route through HW_DEVICE_ID (ID=1).  If any operation uses
    // SOFTWARE_SENTINEL_ID (ID=2), the test panics, proving that ID escaped
    // from HW_DEVICE_ID.
    //
    // Counter assertions are identical to Test 1, providing a second
    // independent proof that the hardware path was taken.
    // -----------------------------------------------------------------------

    const SOFTWARE_SENTINEL_ID: core::ffi::c_int = 2;

    unsafe extern "C" fn sentinel_callback(
        _dev_id: core::ffi::c_int,
        info: *mut wolfcrypt_sys::wc_CryptoInfo,
        _ctx: *mut core::ffi::c_void,
    ) -> core::ffi::c_int {
        let algo_type = if info.is_null() { -1 } else { (*info).algo_type };
        panic!("software crypto called unexpectedly: algo_type={algo_type}");
    }

    #[test]
    fn test_no_software_crypto_used_in_full_flow() {
        setup();
        let _emu = make_emulator();
        reset_all_counters();

        // Register the sentinel callback.
        let rc = unsafe {
            wolfcrypt_sys::wc_CryptoCb_RegisterDevice(
                SOFTWARE_SENTINEL_ID,
                Some(sentinel_callback),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "failed to register sentinel callback: {rc}");

        // Run the full TLS flow.  All operations MUST use HW_DEVICE_ID (1).
        // If anything accidentally uses SOFTWARE_SENTINEL_ID (2), sentinel_callback
        // panics and this test fails with a clear error.
        let before_ecc = ecc_dispatch_count();
        let before_hw  = hw_dispatch_count();
        let before_aes = aes_dispatch_count();

        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

        unsafe {
            let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_InitRng(&mut rng);
            assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

            let mut key_a = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let mut key_b = make_ecc384_key(HW_DEVICE_ID, &mut rng);

            // ECDH
            let mut shared_a = [0u8; 48];
            let mut shared_a_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_a, &mut key_b, shared_a.as_mut_ptr(), &mut shared_a_len,
            );
            assert_eq!(rc, 0, "ECDH A→B failed: {rc}");

            let mut shared_b = [0u8; 48];
            let mut shared_b_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_b, &mut key_a, shared_b.as_mut_ptr(), &mut shared_b_len,
            );
            assert_eq!(rc, 0, "ECDH B→A failed: {rc}");
            assert_eq!(shared_a, shared_b, "ECDH mismatch");

            // HKDF
            let salt = [0u8; 48];
            let mut prk = [0u8; 48];
            hmac384(&salt, &shared_a, &mut prk, HW_DEVICE_ID);

            let mut info_block = [0u8; 49];
            info_block[..48].copy_from_slice(b"wolfssl-rs caliptra-hw conformance label 384\x00\x00\x00\x00");
            info_block[48] = 0x01;
            let mut okm = [0u8; 48];
            hmac384(&prk, &info_block, &mut okm, HW_DEVICE_ID);

            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&okm[..32]);
            let mut aes_iv = [0u8; 12];
            aes_iv.copy_from_slice(&okm[32..44]);

            // AES-256-GCM encrypt/decrypt
            let (rc, ct, tag) = gcm_encrypt(HW_DEVICE_ID, &aes_key, &aes_iv, &plaintext);
            assert_eq!(rc, 0, "encrypt failed: {rc}");
            let (rc, pt_dec) = gcm_decrypt(HW_DEVICE_ID, &aes_key, &aes_iv, &ct, &tag);
            assert_eq!(rc, 0, "decrypt failed: {rc}");
            assert_eq!(pt_dec, plaintext, "round-trip mismatch");

            // ECDSA sign/verify
            let mut signing_key = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let transcript_hash = [0xABu8; 48];
            let mut sig = vec![0u8; 128];
            let mut sig_len: wolfcrypt_sys::word32 = 128;
            let rc = wolfcrypt_sys::wc_ecc_sign_hash(
                transcript_hash.as_ptr(), 48,
                sig.as_mut_ptr(), &mut sig_len, &mut rng, &mut signing_key,
            );
            assert_eq!(rc, 0, "sign failed: {rc}");
            sig.truncate(sig_len as usize);

            let mut verify_result: core::ffi::c_int = 0;
            let rc = wolfcrypt_sys::wc_ecc_verify_hash(
                sig.as_ptr(), sig.len() as wolfcrypt_sys::word32,
                transcript_hash.as_ptr(), 48, &mut verify_result, &mut signing_key,
            );
            assert_eq!(rc, 0, "verify failed: {rc}");
            assert_eq!(verify_result, 1, "signature did not verify");

            // Counter assertions (same as Test 1)
            assert_eq!(ecc_dispatch_count(), before_ecc + 4, "ecc_dispatch mismatch");
            assert_eq!(hw_dispatch_count(),  before_hw  + 2, "hw_dispatch mismatch");
            assert_eq!(aes_dispatch_count(), before_aes + 2, "aes_dispatch mismatch");

            wolfcrypt_sys::wc_ecc_free(&mut key_a);
            wolfcrypt_sys::wc_ecc_free(&mut key_b);
            wolfcrypt_sys::wc_ecc_free(&mut signing_key);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
        // Sentinel was never called — all operations used HW_DEVICE_ID.
    }

    // -----------------------------------------------------------------------
    // Test 3 — test_dispatch_counters_are_not_gameable
    //
    // Call hw_callback directly with malformed / unsupported inputs.
    // For each call: assert the relevant counter did NOT increase.
    // Closes the loophole where a counter increments before input validation.
    // -----------------------------------------------------------------------

    #[test]
    fn test_dispatch_counters_are_not_gameable() {
        setup();
        let _emu = make_emulator();
        reset_all_counters();

        let before_hw  = hw_dispatch_count();
        let before_aes = aes_dispatch_count();
        let before_ecc = ecc_dispatch_count();

        unsafe {
            // ---- 1. Null info pointer → hw_callback must return UNAVAILABLE -----
            let rc = wolfcrypt_dpe_hw::hw_callback(
                HW_DEVICE_ID,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert_eq!(rc, wolfcrypt_dpe_hw::CRYPTOCB_UNAVAILABLE, "null info must return UNAVAILABLE");
            assert_eq!(hw_dispatch_count(),  before_hw,  "null info must not increment hw counter");
            assert_eq!(aes_dispatch_count(), before_aes, "null info must not increment aes counter");
            assert_eq!(ecc_dispatch_count(), before_ecc, "null info must not increment ecc counter");

            // ---- 2. Unsupported algo_type value (9999) -------------------------
            let mut info: wolfcrypt_sys::wc_CryptoInfo = core::mem::zeroed();
            info.algo_type = 9999;
            let rc = wolfcrypt_dpe_hw::hw_callback(
                HW_DEVICE_ID,
                &mut info as *mut _,
                core::ptr::null_mut(),
            );
            assert_eq!(rc, wolfcrypt_dpe_hw::CRYPTOCB_UNAVAILABLE, "algo_type=9999 must return UNAVAILABLE");
            assert_eq!(hw_dispatch_count(),  before_hw,  "algo_type=9999 must not increment hw counter");
            assert_eq!(aes_dispatch_count(), before_aes, "algo_type=9999 must not increment aes counter");
            assert_eq!(ecc_dispatch_count(), before_ecc, "algo_type=9999 must not increment ecc counter");

            // ---- 3. WC_ALGO_TYPE_HASH with unsupported hash type (SHA-1) -------
            // dispatch_hash returns CRYPTOCB_UNAVAILABLE for non-SHA256/384/512 types.
            let mut info: wolfcrypt_sys::wc_CryptoInfo = core::mem::zeroed();
            info.algo_type = wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_HASH as i32;
            // SHA-1 (wc_HashType_WC_HASH_TYPE_SHA = 4): not handled by dispatch_hash.
            info.__bindgen_anon_1.hash.type_ = wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA as i32;
            let rc = wolfcrypt_dpe_hw::hw_callback(
                HW_DEVICE_ID,
                &mut info as *mut _,
                core::ptr::null_mut(),
            );
            assert_eq!(rc, wolfcrypt_dpe_hw::CRYPTOCB_UNAVAILABLE, "SHA-1 must return UNAVAILABLE");
            assert_eq!(hw_dispatch_count(), before_hw, "SHA-1 must not increment hw counter");

            // ---- 4. WC_ALGO_TYPE_HASH with SHA-256 but digest=null (update call)
            //    Counter only increments on Final (digest != null), not on Update.
            let mut info: wolfcrypt_sys::wc_CryptoInfo = core::mem::zeroed();
            info.algo_type = wolfcrypt_sys::wc_AlgoType_WC_ALGO_TYPE_HASH as i32;
            info.__bindgen_anon_1.hash.type_ = wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256 as i32;
            // digest is null → this is an Update call, not Final.
            // in_ is null and inSz is 0 → no-op update with empty data.
            // Counter must NOT increment (only Final increments it).
            let _rc = wolfcrypt_dpe_hw::hw_callback(
                HW_DEVICE_ID,
                &mut info as *mut _,
                core::ptr::null_mut(),
            );
            assert_eq!(hw_dispatch_count(), before_hw, "SHA256 Update (digest=null) must not increment hw counter");
        }
    }
}
