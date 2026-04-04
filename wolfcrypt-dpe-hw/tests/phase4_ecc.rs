//! Phase 4 integration tests: ECC-384 sign/verify/ECDH via CryptoCb WC_ALGO_TYPE_PK.
//!
//! All tests:
//! - Run on host (target_arch != "riscv32"), feature = "caliptra-2x".
//! - Use the same sw-emulator harness established in phase1_hash.rs.
//! - Reset ECC_DISPATCH_COUNT at the start of each test to prevent counter leaks.
//!
//! IMPORTANT: run with `-- --test-threads=1` because ECC_DISPATCH_COUNT is a
//! global singleton.

// Hex literal macro: hex!("deadbeef") → [0xde, 0xad, 0xbe, 0xef].
macro_rules! hex {
    ($s:expr) => {{
        const N: usize = $s.len() / 2;
        let mut out = [0u8; N];
        let bytes = $s.as_bytes();
        let mut i = 0;
        while i < N {
            let hi = match bytes[i * 2] {
                b @ b'0'..=b'9' => b - b'0',
                b @ b'a'..=b'f' => b - b'a' + 10,
                b @ b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            let lo = match bytes[i * 2 + 1] {
                b @ b'0'..=b'9' => b - b'0',
                b @ b'a'..=b'f' => b - b'a' + 10,
                b @ b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }};
}

#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod tests {
    use wolfcrypt_dpe_hw::{ecc_dispatch_count, reset_ecc_dispatch_count, HW_DEVICE_ID};

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
    // ECC helpers
    // -----------------------------------------------------------------------

    /// Generate a fresh P-384 key pair with the given devId.
    unsafe fn make_ecc384_key(
        dev_id: core::ffi::c_int,
        rng: *mut wolfcrypt_sys::WC_RNG,
    ) -> wolfcrypt_sys::ecc_key {
        let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_ecc_init_ex(&mut key, core::ptr::null_mut(), dev_id);
        assert_eq!(rc, 0, "wc_ecc_init_ex failed: {rc}");
        let rc = wolfcrypt_sys::wc_ecc_make_key_ex(
            rng,
            48,
            &mut key,
            wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
        );
        assert_eq!(rc, 0, "wc_ecc_make_key_ex failed: {rc}");
        key
    }

    /// Sign a 48-byte hash with the given key.  Returns the DER-encoded signature.
    unsafe fn ecc384_sign(
        key: &mut wolfcrypt_sys::ecc_key,
        rng: *mut wolfcrypt_sys::WC_RNG,
        hash: &[u8; 48],
    ) -> Vec<u8> {
        let mut sig = vec![0u8; 128];
        let mut sig_len: wolfcrypt_sys::word32 = 128;
        let rc = wolfcrypt_sys::wc_ecc_sign_hash(
            hash.as_ptr(),
            48,
            sig.as_mut_ptr(),
            &mut sig_len,
            rng,
            key,
        );
        assert_eq!(rc, 0, "wc_ecc_sign_hash failed: {rc}");
        sig.truncate(sig_len as usize);
        sig
    }

    /// Verify a DER signature against a 48-byte hash.  Returns (rc, result).
    unsafe fn ecc384_verify(
        key: &mut wolfcrypt_sys::ecc_key,
        sig: &[u8],
        hash: &[u8; 48],
    ) -> (core::ffi::c_int, core::ffi::c_int) {
        let mut result: core::ffi::c_int = 0;
        let rc = wolfcrypt_sys::wc_ecc_verify_hash(
            sig.as_ptr(),
            sig.len() as wolfcrypt_sys::word32,
            hash.as_ptr(),
            48,
            &mut result,
            key,
        );
        (rc, result)
    }

    /// Export the public key from `src_key` as an uncompressed SEC1 blob
    /// (0x04 || Qx || Qy, 97 bytes), then import it into a new key with `dev_id`.
    unsafe fn import_public_from(
        src_key: &mut wolfcrypt_sys::ecc_key,
        dev_id: core::ffi::c_int,
    ) -> wolfcrypt_sys::ecc_key {
        let mut qx = [0u8; 48];
        let mut qy = [0u8; 48];
        let mut qx_len: wolfcrypt_sys::word32 = 48;
        let mut qy_len: wolfcrypt_sys::word32 = 48;
        let rc = wolfcrypt_sys::wc_ecc_export_public_raw(
            src_key,
            qx.as_mut_ptr(),
            &mut qx_len,
            qy.as_mut_ptr(),
            &mut qy_len,
        );
        assert_eq!(rc, 0, "wc_ecc_export_public_raw failed: {rc}");
        assert_eq!(qx_len, 48, "unexpected qx_len={qx_len}");
        assert_eq!(qy_len, 48, "unexpected qy_len={qy_len}");

        // SEC1 uncompressed: 0x04 || Qx || Qy
        let mut pub_bytes = [0u8; 97];
        pub_bytes[0] = 0x04;
        pub_bytes[1..49].copy_from_slice(&qx);
        pub_bytes[49..97].copy_from_slice(&qy);

        // Import into a new key (INVALID_DEVID first to allow clean import).
        let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_ecc_init_ex(
            &mut key,
            core::ptr::null_mut(),
            wolfcrypt_sys::INVALID_DEVID,
        );
        assert_eq!(rc, 0, "wc_ecc_init_ex (import dst) failed: {rc}");
        let rc = wolfcrypt_sys::wc_ecc_import_x963_ex(
            pub_bytes.as_ptr(),
            97,
            &mut key,
            wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
        );
        assert_eq!(rc, 0, "wc_ecc_import_x963_ex failed: {rc}");

        // Set devId explicitly after import (import may not preserve it).
        key.devId = dev_id;
        key
    }

    // -----------------------------------------------------------------------
    // Test 1 — test_ecdsa384_sign_verify_roundtrip
    //
    // Generate a P-384 key pair, sign a hash via the HW CryptoCb path,
    // verify via the HW CryptoCb path.  Confirm both operations dispatched.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa384_sign_verify_roundtrip() {
        setup();
        let _emu = make_emulator();
        reset_ecc_dispatch_count();
        let before = ecc_dispatch_count();
        assert_eq!(before, 0, "counter leak from previous test");

        let mut rng: wolfcrypt_sys::WC_RNG = unsafe { core::mem::zeroed() };
        let rc = unsafe { wolfcrypt_sys::wc_InitRng(&mut rng) };
        assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

        unsafe {
            let mut key = make_ecc384_key(HW_DEVICE_ID, &mut rng);

            // Sign a synthetic SHA-384 digest.
            let hash = [0x42u8; 48];
            let sig = ecc384_sign(&mut key, &mut rng, &hash);
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "sign did not increment dispatch count"
            );

            // Verify the signature.
            let (rc, result) = ecc384_verify(&mut key, &sig, &hash);
            assert_eq!(rc, 0, "wc_ecc_verify_hash failed: {rc}");
            assert_eq!(result, 1, "signature verification returned result={result}");
            assert_eq!(
                ecc_dispatch_count(),
                before + 2,
                "verify did not increment dispatch count"
            );

            wolfcrypt_sys::wc_ecc_free(&mut key);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
    }

    // -----------------------------------------------------------------------
    // Test 2 — test_ecdsa384_nist_verify_vector
    //
    // Verify a known-good RFC 6979 P-384/SHA-384 signature for message "sample".
    // Vectors from NIST FIPS 186-4 test vectors / RFC 6979 §A.2.6.
    //
    // This test does not sign; it only verifies.  Expected dispatch count: +1.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa384_nist_verify_vector() {
        setup();
        let _emu = make_emulator();
        reset_ecc_dispatch_count();
        let before = ecc_dispatch_count();
        assert_eq!(before, 0, "counter leak from previous test");

        // RFC 6979 P-384/SHA-384 "sample" test vector.
        // Source: wolfssl/wolfcrypt/test/test.c (lines ~33395-33435).
        const QX: [u8; 48] = hex!(
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
             DEF8F0EA9055866064A254515480BC13"
        );
        const QY: [u8; 48] = hex!(
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1\
             288B231C3AE0D4FE7344FD2533264720"
        );
        const R: [u8; 48] = hex!(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
             81A648152E44ACF96E36DD1E80FABE46"
        );
        const S: [u8; 48] = hex!(
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\
             A329C145786E679E7B82C71A38628AC8"
        );

        unsafe {
            // Compute SHA-384("sample").
            let msg = b"sample";
            let mut digest = [0u8; 48];
            let rc = wolfcrypt_sys::wc_Sha384Hash(
                msg.as_ptr(),
                msg.len() as wolfcrypt_sys::word32,
                digest.as_mut_ptr(),
            );
            assert_eq!(rc, 0, "wc_Sha384Hash failed: {rc}");

            // DER-encode the (R, S) signature.
            let mut sig = [0u8; 128];
            let mut sig_len: wolfcrypt_sys::word32 = 128;
            let rc = wolfcrypt_sys::wc_ecc_rs_raw_to_sig(
                R.as_ptr(),
                48,
                S.as_ptr(),
                48,
                sig.as_mut_ptr(),
                &mut sig_len,
            );
            assert_eq!(rc, 0, "wc_ecc_rs_raw_to_sig failed: {rc}");
            assert!(sig_len > 0 && sig_len <= 128, "unexpected sig_len={sig_len}");

            // Build SEC1 uncompressed public key: 0x04 || Qx || Qy.
            let mut pub_bytes = [0u8; 97];
            pub_bytes[0] = 0x04;
            pub_bytes[1..49].copy_from_slice(&QX);
            pub_bytes[49..97].copy_from_slice(&QY);

            // Import the public key with INVALID_DEVID first, then set HW_DEVICE_ID.
            let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_ecc_init_ex(
                &mut key,
                core::ptr::null_mut(),
                wolfcrypt_sys::INVALID_DEVID,
            );
            assert_eq!(rc, 0, "wc_ecc_init_ex failed: {rc}");
            let rc = wolfcrypt_sys::wc_ecc_import_x963_ex(
                pub_bytes.as_ptr(),
                97,
                &mut key,
                wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
            );
            assert_eq!(rc, 0, "wc_ecc_import_x963_ex failed: {rc}");
            key.devId = HW_DEVICE_ID;

            // Verify using the HW CryptoCb path.
            let (rc, result) = ecc384_verify(&mut key, &sig[..sig_len as usize], &digest);
            assert_eq!(rc, 0, "wc_ecc_verify_hash failed: {rc}");
            assert_eq!(result, 1, "NIST vector verification failed (result={result})");
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "verify did not increment dispatch count"
            );

            wolfcrypt_sys::wc_ecc_free(&mut key);
        }
    }

    // -----------------------------------------------------------------------
    // Test 3 — test_ecdsa384_reject_bad_signature
    //
    // Sign a hash, then corrupt the signature by flipping a bit in the r
    // component.  Verify must fail with VERIFY_SIGN_ERROR (-330).
    //
    // The dispatch count:
    //   - sign:   before → before + 1
    //   - verify: VERIFY_SIGN_ERROR is NOT counted (hardware ran but sig invalid)
    // Final count: before + 1 (only from sign).
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa384_reject_bad_signature() {
        setup();
        let _emu = make_emulator();
        reset_ecc_dispatch_count();
        let before = ecc_dispatch_count();
        assert_eq!(before, 0, "counter leak from previous test");

        let mut rng: wolfcrypt_sys::WC_RNG = unsafe { core::mem::zeroed() };
        let rc = unsafe { wolfcrypt_sys::wc_InitRng(&mut rng) };
        assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

        unsafe {
            let mut key = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let hash = [0xABu8; 48];

            // Sign — count becomes before + 1.
            let sig = ecc384_sign(&mut key, &mut rng, &hash);

            // Decode (r, s) from DER to corrupt r cleanly.
            let mut r_bytes = [0u8; 48];
            let mut s_bytes = [0u8; 48];
            let mut r_len: wolfcrypt_sys::word32 = 48;
            let mut s_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_sig_to_rs(
                sig.as_ptr(),
                sig.len() as wolfcrypt_sys::word32,
                r_bytes.as_mut_ptr(),
                &mut r_len,
                s_bytes.as_mut_ptr(),
                &mut s_len,
            );
            assert_eq!(rc, 0, "wc_ecc_sig_to_rs failed: {rc}");

            // Flip a bit in the middle of r — the DER re-encoding will remain valid.
            r_bytes[r_len as usize / 2] ^= 0x01;

            // Re-encode as DER.
            let mut bad_sig = [0u8; 128];
            let mut bad_sig_len: wolfcrypt_sys::word32 = 128;
            let rc = wolfcrypt_sys::wc_ecc_rs_raw_to_sig(
                r_bytes.as_ptr(),
                r_len,
                s_bytes.as_ptr(),
                s_len,
                bad_sig.as_mut_ptr(),
                &mut bad_sig_len,
            );
            assert_eq!(rc, 0, "wc_ecc_rs_raw_to_sig (bad sig) failed: {rc}");

            // Verify the corrupted signature — must return VERIFY_SIGN_ERROR.
            const VERIFY_SIGN_ERROR: core::ffi::c_int = -330;
            let (rc, result) =
                ecc384_verify(&mut key, &bad_sig[..bad_sig_len as usize], &hash);
            assert_eq!(
                rc, VERIFY_SIGN_ERROR,
                "expected VERIFY_SIGN_ERROR ({VERIFY_SIGN_ERROR}), got rc={rc}"
            );
            assert_eq!(result, 0, "result should be 0 on verify failure, got {result}");

            // Dispatch count: only the sign incremented; failed verify did not.
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "failed verify must NOT increment dispatch count"
            );

            wolfcrypt_sys::wc_ecc_free(&mut key);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4 — test_ecdh384_shared_secret
    //
    // Generate two P-384 key pairs, compute ECDH(A_priv, B_pub) and
    // ECDH(B_priv, A_pub).  Shared secrets must be equal and non-zero.
    // Each ECDH call dispatches once; count increments by 2.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdh384_shared_secret() {
        setup();
        let _emu = make_emulator();
        reset_ecc_dispatch_count();
        let before = ecc_dispatch_count();
        assert_eq!(before, 0, "counter leak from previous test");

        let mut rng: wolfcrypt_sys::WC_RNG = unsafe { core::mem::zeroed() };
        let rc = unsafe { wolfcrypt_sys::wc_InitRng(&mut rng) };
        assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

        unsafe {
            let mut key_a = make_ecc384_key(HW_DEVICE_ID, &mut rng);
            let mut key_b = make_ecc384_key(HW_DEVICE_ID, &mut rng);

            // ECDH: A computes shared secret using A's private key and B's public key.
            let mut shared_a = [0u8; 48];
            let mut shared_a_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_a,
                &mut key_b,
                shared_a.as_mut_ptr(),
                &mut shared_a_len,
            );
            assert_eq!(rc, 0, "wc_ecc_shared_secret (A→B) failed: {rc}");
            assert_eq!(shared_a_len, 48, "unexpected shared_a_len={shared_a_len}");
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "ECDH A→B did not increment dispatch count"
            );

            // ECDH: B computes shared secret using B's private key and A's public key.
            let mut shared_b = [0u8; 48];
            let mut shared_b_len: wolfcrypt_sys::word32 = 48;
            let rc = wolfcrypt_sys::wc_ecc_shared_secret(
                &mut key_b,
                &mut key_a,
                shared_b.as_mut_ptr(),
                &mut shared_b_len,
            );
            assert_eq!(rc, 0, "wc_ecc_shared_secret (B→A) failed: {rc}");
            assert_eq!(shared_b_len, 48, "unexpected shared_b_len={shared_b_len}");
            assert_eq!(
                ecc_dispatch_count(),
                before + 2,
                "ECDH B→A did not increment dispatch count"
            );

            // The two shared secrets must be identical.
            assert_eq!(shared_a, shared_b, "ECDH shared secrets do not match");

            // The shared secret must not be all zeros (catastrophic failure check).
            assert_ne!(shared_a, [0u8; 48], "ECDH produced an all-zeros shared secret");

            wolfcrypt_sys::wc_ecc_free(&mut key_a);
            wolfcrypt_sys::wc_ecc_free(&mut key_b);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
    }

    // -----------------------------------------------------------------------
    // Test 5 — test_ecdsa384_cross_validate_with_software
    //
    // Verify that the HW and software paths produce compatible signatures:
    //   (a) HW sign → SW verify:  wolfcrypt_dpe_hw signs; plain wolfCrypt verifies.
    //   (b) SW sign → HW verify:  plain wolfCrypt signs; wolfcrypt_dpe_hw verifies.
    //
    // Dispatch count after (a): before + 1  (only the HW sign)
    // Dispatch count after (b): before + 2  (HW sign from (a) + HW verify from (b))
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa384_cross_validate_with_software() {
        setup();
        let _emu = make_emulator();
        reset_ecc_dispatch_count();
        let before = ecc_dispatch_count();
        assert_eq!(before, 0, "counter leak from previous test");

        let mut rng: wolfcrypt_sys::WC_RNG = unsafe { core::mem::zeroed() };
        let rc = unsafe { wolfcrypt_sys::wc_InitRng(&mut rng) };
        assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

        let hash = [0x7Eu8; 48];

        unsafe {
            // --- (a) HW sign → SW verify ---

            // HW key pair.
            let mut key_hw = make_ecc384_key(HW_DEVICE_ID, &mut rng);

            // Sign with HW path.
            let sig_hw = ecc384_sign(&mut key_hw, &mut rng, &hash);
            assert_eq!(ecc_dispatch_count(), before + 1, "HW sign did not dispatch");

            // Export HW public key; import into a software (INVALID_DEVID) key.
            let mut key_sw_pub = import_public_from(&mut key_hw, wolfcrypt_sys::INVALID_DEVID);

            // Verify with software path (no dispatch expected).
            let (rc, result) = ecc384_verify(&mut key_sw_pub, &sig_hw, &hash);
            assert_eq!(rc, 0, "SW verify of HW sig failed: rc={rc}");
            assert_eq!(result, 1, "SW verify of HW sig: result={result}");
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "SW verify must not increment HW dispatch count"
            );

            // --- (b) SW sign → HW verify ---

            // Software key pair (INVALID_DEVID).
            let mut key_sw = make_ecc384_key(wolfcrypt_sys::INVALID_DEVID, &mut rng);

            // Sign with software path (no dispatch expected).
            let sig_sw = ecc384_sign(&mut key_sw, &mut rng, &hash);
            assert_eq!(
                ecc_dispatch_count(),
                before + 1,
                "SW sign must not increment HW dispatch count"
            );

            // Export SW public key; import into a hardware (HW_DEVICE_ID) key.
            let mut key_hw_pub = import_public_from(&mut key_sw, HW_DEVICE_ID);

            // Verify with HW path.
            let (rc, result) = ecc384_verify(&mut key_hw_pub, &sig_sw, &hash);
            assert_eq!(rc, 0, "HW verify of SW sig failed: rc={rc}");
            assert_eq!(result, 1, "HW verify of SW sig: result={result}");
            assert_eq!(
                ecc_dispatch_count(),
                before + 2,
                "HW verify did not increment dispatch count"
            );

            wolfcrypt_sys::wc_ecc_free(&mut key_hw);
            wolfcrypt_sys::wc_ecc_free(&mut key_sw_pub);
            wolfcrypt_sys::wc_ecc_free(&mut key_sw);
            wolfcrypt_sys::wc_ecc_free(&mut key_hw_pub);
            wolfcrypt_sys::wc_FreeRng(&mut rng);
        }
    }
}
