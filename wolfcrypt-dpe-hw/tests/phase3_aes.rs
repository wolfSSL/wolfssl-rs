//! Phase 3 integration tests: AES-256-GCM/CBC via CryptoCb WC_ALGO_TYPE_CIPHER dispatch.
//!
//! All tests:
//! - Run on host (target_arch != "riscv32"), feature = "caliptra-2x".
//! - Use the same sw-emulator harness established in phase1_hash.rs / phase2_rng.rs.
//! - Reset AES_DISPATCH_COUNT at the start of each test to prevent counter leaks.
//!
//! IMPORTANT: run with `-- --test-threads=1` because AES_DISPATCH_COUNT is a
//! global singleton.

// Hex literal macro: hex!("deadbeef") → [0xde, 0xad, 0xbe, 0xef].
// Defined before mod tests so it is in scope inside the module.
// All nibble conversion logic is inlined so no external function call is needed
// at the expansion site (macro_rules! uses call-site scope for name resolution).
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
    use wolfcrypt_dpe_hw::{aes_dispatch_count, reset_aes_dispatch_count, HW_DEVICE_ID};

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
    // AES-GCM helpers
    // -----------------------------------------------------------------------

    /// Encrypt using wc_AesGcmEncrypt.  Returns (rc, ciphertext, tag).
    unsafe fn gcm_encrypt(
        dev_id: core::ffi::c_int,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (i32, Vec<u8>, [u8; 16]) {
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
        wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);

        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        let rc = wolfcrypt_sys::wc_AesGcmEncrypt(
            &mut aes,
            if plaintext.is_empty() {
                core::ptr::null_mut()
            } else {
                ct.as_mut_ptr()
            },
            if plaintext.is_empty() {
                core::ptr::null()
            } else {
                plaintext.as_ptr()
            },
            plaintext.len() as u32,
            iv.as_ptr(),
            12,
            tag.as_mut_ptr(),
            16,
            if aad.is_empty() {
                core::ptr::null()
            } else {
                aad.as_ptr()
            },
            aad.len() as u32,
        );
        wolfcrypt_sys::wc_AesFree(&mut aes);
        (rc, ct, tag)
    }

    /// Decrypt using wc_AesGcmDecrypt.  Returns (rc, plaintext).
    unsafe fn gcm_decrypt(
        dev_id: core::ffi::c_int,
        key: &[u8; 32],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> (i32, Vec<u8>) {
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
        wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);

        let mut pt = vec![0u8; ciphertext.len()];
        let rc = wolfcrypt_sys::wc_AesGcmDecrypt(
            &mut aes,
            if ciphertext.is_empty() {
                core::ptr::null_mut()
            } else {
                pt.as_mut_ptr()
            },
            if ciphertext.is_empty() {
                core::ptr::null()
            } else {
                ciphertext.as_ptr()
            },
            ciphertext.len() as u32,
            iv.as_ptr(),
            12,
            tag.as_ptr(),
            16,
            if aad.is_empty() {
                core::ptr::null()
            } else {
                aad.as_ptr()
            },
            aad.len() as u32,
        );
        wolfcrypt_sys::wc_AesFree(&mut aes);
        (rc, pt)
    }

    // -----------------------------------------------------------------------
    // AES-CBC helper
    // -----------------------------------------------------------------------

    /// Encrypt a single block using wc_AesCbcEncrypt.  Returns (rc, ciphertext).
    unsafe fn cbc_encrypt(
        dev_id: core::ffi::c_int,
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> (i32, Vec<u8>) {
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
        wolfcrypt_sys::wc_AesSetKey(
            &mut aes,
            key.as_ptr(),
            32,
            iv.as_ptr(),
            wolfcrypt_sys::AES_ENCRYPTION as i32,
        );
        let mut ct = vec![0u8; plaintext.len()];
        let rc = wolfcrypt_sys::wc_AesCbcEncrypt(
            &mut aes,
            ct.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
        );
        wolfcrypt_sys::wc_AesFree(&mut aes);
        (rc, ct)
    }

    // -----------------------------------------------------------------------
    // Test 1 — test_aes256gcm_nist_encrypt
    //
    // NIST SP 800-38D Test Case 15: AES-256-GCM, 64-byte plaintext, empty AAD.
    // Vectors from NIST SP 800-38D Appendix B.
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes256gcm_nist_encrypt() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        // NIST SP 800-38D TC15 (AES-256-GCM, 64-byte PT, no AAD).
        const KEY: [u8; 32] =
            hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const IV: [u8; 12] = hex!("cafebabefacedbaddecaf888");
        const PT: [u8; 64] = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        const EXPECTED_CT: [u8; 64] = hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
        const EXPECTED_TAG: [u8; 16] = hex!("b094dac5d93471bdec1a502270e3cc6c");

        let before = aes_dispatch_count();
        let (rc, ct, tag) = unsafe { gcm_encrypt(HW_DEVICE_ID, &KEY, &IV, &[], &PT) };
        assert_eq!(rc, 0, "wc_AesGcmEncrypt(NIST TC15) failed: {rc}");
        assert_eq!(ct.as_slice(), EXPECTED_CT.as_slice(), "ciphertext mismatch");
        assert_eq!(tag, EXPECTED_TAG, "auth tag mismatch");
        assert_eq!(
            aes_dispatch_count(),
            before + 1,
            "AES_DISPATCH_COUNT must increment by 1"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — test_aes256gcm_nist_decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes256gcm_nist_decrypt() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        const KEY: [u8; 32] =
            hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const IV: [u8; 12] = hex!("cafebabefacedbaddecaf888");
        const CT: [u8; 64] = hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
        const TAG: [u8; 16] = hex!("b094dac5d93471bdec1a502270e3cc6c");
        const EXPECTED_PT: [u8; 64] = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        let before = aes_dispatch_count();
        let (rc, pt) = unsafe { gcm_decrypt(HW_DEVICE_ID, &KEY, &IV, &[], &CT, &TAG) };
        assert_eq!(rc, 0, "wc_AesGcmDecrypt(NIST TC15) failed: {rc}");
        assert_eq!(pt.as_slice(), EXPECTED_PT.as_slice(), "plaintext mismatch");
        assert_eq!(
            aes_dispatch_count(),
            before + 1,
            "AES_DISPATCH_COUNT must increment by 1"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — test_aes256gcm_tag_rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes256gcm_tag_rejection() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        const KEY: [u8; 32] =
            hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const IV: [u8; 12] = hex!("cafebabefacedbaddecaf888");
        const CT: [u8; 64] = hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
        // Flip the first bit of the correct tag.
        let mut bad_tag: [u8; 16] = hex!("b094dac5d93471bdec1a502270e3cc6c");
        bad_tag[0] ^= 0x01;

        let before = aes_dispatch_count();
        let (rc, _pt) = unsafe { gcm_decrypt(HW_DEVICE_ID, &KEY, &IV, &[], &CT, &bad_tag) };

        // The implementation must reach hardware (compute GHASH) before rejecting —
        // short-circuiting before hardware is forbidden.
        assert_eq!(
            aes_dispatch_count(),
            before + 1,
            "AES_DISPATCH_COUNT did not increment — implementation short-circuited \
             before calling hardware on tag-rejection path (wrong)"
        );

        assert_ne!(
            rc, 0,
            "wc_AesGcmDecrypt must fail when tag is invalid (flipped bit in tag[0])"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 — test_aes256gcm_matches_software
    //
    // For 5 deterministic test vectors (fixed values, no RNG):
    //   hw encrypt + sw decrypt → plaintext matches
    //   sw encrypt + hw decrypt → plaintext matches
    // AES_DISPATCH_COUNT must increment exactly 10 (2 hw calls per vector × 5).
    // Catches endianness and key marshaling bugs.
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes256gcm_matches_software() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        // 5 deterministic (key, iv, aad, pt) tuples.
        // Values chosen to exercise different data patterns, not truly random.
        let vectors: [([u8; 32], [u8; 12], [u8; 8], [u8; 32]); 5] = [
            (
                hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                hex!("aabbccddeeff00112233445566778899")[..12]
                    .try_into()
                    .unwrap(),
                *b"aad_vec1",
                hex!("deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718"),
            ),
            (
                hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
                hex!("000102030405060708090a0b"),
                *b"aad_vec2",
                hex!("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
            ),
            (
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("000000000000000000000000"),
                *b"aad_vec3",
                hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            ),
            (
                hex!("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80"),
                hex!("112233445566778899aabbcc"),
                *b"aad_vec4",
                hex!("0f0e0d0c0b0a09080706050403020100fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"),
            ),
            (
                hex!("a0b0c0d0e0f0a1b1c1d1e1f1a2b2c2d2e2f2a3b3c3d3e3f3a4b4c4d4e4f4a5b5"),
                hex!("010203040506070809101112"),
                *b"aad_vec5",
                hex!("55aaff0055aaff0055aaff0055aaff0055aaff0055aaff0055aaff0055aaff00"),
            ),
        ];

        let before = aes_dispatch_count();

        for (i, (key, iv, aad, pt)) in vectors.iter().enumerate() {
            // hw encrypt → sw decrypt
            let (enc_rc, ct, tag) = unsafe { gcm_encrypt(HW_DEVICE_ID, key, iv, aad, pt) };
            assert_eq!(enc_rc, 0, "hw encrypt failed for vector {i}: {enc_rc}");

            let (dec_rc, recovered) =
                unsafe { gcm_decrypt(wolfcrypt_sys::INVALID_DEVID, key, iv, aad, &ct, &tag) };
            assert_eq!(dec_rc, 0, "sw decrypt failed for vector {i}: {dec_rc}");
            assert_eq!(
                recovered.as_slice(),
                pt.as_slice(),
                "hw-encrypt→sw-decrypt plaintext mismatch for vector {i}"
            );

            // sw encrypt → hw decrypt
            let (sw_enc_rc, sw_ct, sw_tag) =
                unsafe { gcm_encrypt(wolfcrypt_sys::INVALID_DEVID, key, iv, aad, pt) };
            assert_eq!(
                sw_enc_rc, 0,
                "sw encrypt failed for vector {i}: {sw_enc_rc}"
            );

            let (hw_dec_rc, hw_recovered) =
                unsafe { gcm_decrypt(HW_DEVICE_ID, key, iv, aad, &sw_ct, &sw_tag) };
            assert_eq!(
                hw_dec_rc, 0,
                "hw decrypt failed for vector {i}: {hw_dec_rc}"
            );
            assert_eq!(
                hw_recovered.as_slice(),
                pt.as_slice(),
                "sw-encrypt→hw-decrypt plaintext mismatch for vector {i}"
            );
        }

        // 5 vectors × 2 hw operations each = 10 hw dispatches.
        assert_eq!(
            aes_dispatch_count(),
            before + 10,
            "AES_DISPATCH_COUNT must increment by 10 (2 hw calls × 5 vectors)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5 — test_aes256cbc_behavior
    //
    // CBC IS available per recon_caliptra_drivers.md §11.
    // Uses NIST SP 800-38A AES-256-CBC AESAVS test vector (Block 1).
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes256cbc_behavior() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        // NIST SP 800-38A AES-256-CBC AESAVS test vector (first encrypt block).
        const KEY: [u8; 32] =
            hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
        const PT: [u8; 16] = hex!("6bc1bee22e409f96e93d7e117393172a");
        const EXPECTED_CT: [u8; 16] = hex!("f58c4c04d6e5f1ba779eabfb5f7bfbd6");

        let before = aes_dispatch_count();
        let (rc, ct) = unsafe { cbc_encrypt(HW_DEVICE_ID, &KEY, &IV, &PT) };
        assert_eq!(
            rc, 0,
            "wc_AesCbcEncrypt(NIST AESAVS, AES-256-CBC) failed: {rc}"
        );
        assert_eq!(
            ct.as_slice(),
            EXPECTED_CT.as_slice(),
            "CBC ciphertext mismatch"
        );
        assert_eq!(
            aes_dispatch_count(),
            before + 1,
            "AES_DISPATCH_COUNT must increment by 1 for CBC hw dispatch"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6 — test_key_material_zeroized
    //
    // Verifies that dispatch_aesgcm_encrypt calls zeroize::Zeroize on its
    // local key copy after use.  Uses a heuristic stack scan: if the test key
    // pattern appears in the stack region occupied by the dispatch function's
    // frame immediately after it returns, zeroize was NOT called.
    //
    // Uses a key of sequential bytes (0x80..=0x9F repeated) for easy
    // detection.  If zeroize::Zeroize (volatile writes) ran, those bytes are
    // guaranteed to be zero at their former locations.
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_material_zeroized() {
        setup();
        let _emu = make_emulator();
        reset_aes_dispatch_count();
        assert_eq!(aes_dispatch_count(), 0, "counter leak from previous test");

        // Distinctive key pattern: sequential bytes 0x80..=0x9F stored as a
        // const in .rodata — using a const for comparison ensures the reference
        // bytes are never on the stack themselves.
        const SCAN_KEY: [u8; 32] = {
            let mut k = [0u8; 32];
            let mut i = 0usize;
            while i < 32 {
                k[i] = 0x80u8 | (i as u8 & 0x1f);
                i += 1;
            }
            k
        };

        let iv = [0x55u8; 12];
        let pt = [0xffu8; 16];

        // Create a mutable local copy for the GCM call.
        let mut test_key = SCAN_KEY;

        // Run AES-256-GCM through the HW dispatch path.
        // Inside dispatch_aesgcm_encrypt:
        //   1. key copy is made from aes->devKey onto the dispatch stack frame
        //   2. key copy is used for the AES-GCM operation
        //   3. key.zeroize() is called — zeroes the dispatch stack frame's copy
        let (rc, _ct, _tag) = unsafe { gcm_encrypt(HW_DEVICE_ID, &test_key, &iv, &[], &pt) };
        assert_eq!(rc, 0, "GCM encrypt failed: {rc}");
        assert_eq!(
            aes_dispatch_count(),
            1,
            "AES_DISPATCH_COUNT must be 1 after one dispatch"
        );

        // Zero OUR local test_key before scanning so it doesn't cause a false
        // positive when we scan our own stack frame.
        // volatile_write prevents dead-store elimination.
        unsafe { core::ptr::write_volatile(&mut test_key as *mut [u8; 32], [0u8; 32]) };
        // Note: gcm_encrypt → wc_AesFree already called ForceZero on aes->devKey.

        // Take the approximate stack pointer AFTER zeroing test_key and AFTER
        // gcm_encrypt returned so that the scan region covers the freed dispatch
        // frames but not our live variables.
        let sp_marker: u8 = 0;
        let scan_end = &sp_marker as *const u8 as usize;

        // Heuristic scan: read 8 KiB below our current frame.
        // After cleanup:
        //   - test_key: zeroed above ✓
        //   - aes->devKey (inside gcm_encrypt's frame): ForceZero'd by wc_AesFree ✓
        //   - dispatch's key copy: zeroed by key.zeroize() ✓
        // If zeroize DID run, none of these contain SCAN_KEY anymore.
        // If zeroize was REMOVED, dispatch's copy would still have SCAN_KEY bytes.
        let found = unsafe {
            let scan_start = scan_end.saturating_sub(8192);
            let len = scan_end - scan_start;
            if len >= 32 {
                let region = core::slice::from_raw_parts(scan_start as *const u8, len);
                region.windows(32).any(|w| w == SCAN_KEY)
            } else {
                false
            }
        };

        assert!(
            !found,
            "Key pattern found in stack region — dispatch_aesgcm_encrypt may \
             not be calling zeroize::Zeroize on the local key copy"
        );
    }
}
