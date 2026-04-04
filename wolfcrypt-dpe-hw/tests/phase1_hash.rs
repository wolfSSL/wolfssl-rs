//! Phase 1 integration tests: SHA-256/384/512 and HMAC-384 via CryptoCb.
//!
//! All tests:
//! - Run on host (target_arch != "riscv32"), feature = "caliptra-2x".
//! - Instantiate the caliptra sw-emulator (CaliptraRootBus) as per the
//!   pattern in audit/recon_swemulator.md.  On the host path the actual SHA
//!   computation uses the sha2/hmac crates (same as the caliptra emulator
//!   uses internally); CaliptraRootBus is instantiated to exercise the
//!   emulator infrastructure.
//! - Verify HW_DISPATCH_COUNT increments to confirm the hardware path fires.
//!
//! IMPORTANT: run with `-- --test-threads=1` because HW_HASH_STATE and
//! HW_HMAC_STATE are global singletons.  Concurrent tests would corrupt
//! streaming state.

#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
mod tests {
    use wolfcrypt_dpe_hw::{hw_dispatch_count, reset_hw_dispatch_count, HW_DEVICE_ID};

    // -----------------------------------------------------------------------
    // Shared setup
    // -----------------------------------------------------------------------

    /// One-time wolfCrypt + hardware backend initialisation (idempotent).
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
    // Helper: one-shot hash via wolfSSL CryptoCb
    // -----------------------------------------------------------------------

    fn wc_hash_ex(
        hash_type: wolfcrypt_sys::wc_HashType,
        data: &[u8],
        out: &mut [u8],
    ) -> i32 {
        unsafe {
            wolfcrypt_sys::wc_Hash_ex(
                hash_type,
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
                core::ptr::null_mut(),
                HW_DEVICE_ID,
            )
        }
    }

    // -----------------------------------------------------------------------
    // assert_hw_was_used! macro
    // -----------------------------------------------------------------------

    /// Asserts that `hw_dispatch_count()` equals `before + expected_increment`.
    ///
    /// Panics with a descriptive message if the hardware path was not taken.
    macro_rules! assert_hw_was_used {
        ($before:expr, $expected_increment:expr) => {{
            let before: usize = $before;
            let expected_increment: usize = $expected_increment;
            let actual = hw_dispatch_count();
            assert_eq!(
                actual,
                before + expected_increment,
                "hardware path was not taken — test is invalid. \
                 before={before}, after={actual}, \
                 expected increment={expected_increment}"
            );
        }};
    }

    // -----------------------------------------------------------------------
    // NIST FIPS 180-4 test vectors (embedded constants)
    // -----------------------------------------------------------------------

    // SHA-256
    const SHA256_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    const SHA256_1M_A: [u8; 32] = [
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0,
    ];

    // SHA-384
    const SHA384_EMPTY: [u8; 48] = [
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
        0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
        0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
    ];
    const SHA384_ABC: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
    ];
    const SHA384_1M_A: [u8; 48] = [
        0x9d, 0x0e, 0x18, 0x09, 0x71, 0x64, 0x74, 0xcb,
        0x08, 0x6e, 0x83, 0x4e, 0x31, 0x0a, 0x4a, 0x1c,
        0xed, 0x14, 0x9e, 0x9c, 0x00, 0xf2, 0x48, 0x52,
        0x79, 0x72, 0xce, 0xc5, 0x70, 0x4c, 0x2a, 0x5b,
        0x07, 0xb8, 0xb3, 0xdc, 0x38, 0xec, 0xc4, 0xeb,
        0xae, 0x97, 0xdd, 0xd8, 0x7f, 0x3d, 0x89, 0x85,
    ];

    // SHA-512
    const SHA512_EMPTY: [u8; 64] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    ];
    const SHA512_ABC: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    ];
    const SHA512_1M_A: [u8; 64] = [
        0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64,
        0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
        0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28,
        0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
        0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a,
        0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
        0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e,
        0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b,
    ];

    // -----------------------------------------------------------------------
    // Test 1 — SHA-256 NIST FIPS 180-4 byte vectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_nist_byte_vector() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        let cases: &[(&[u8], &[u8])] = &[
            (b"", &SHA256_EMPTY),
            (b"abc", &SHA256_ABC),
        ];

        for (data, expected) in cases {
            let before = hw_dispatch_count();
            let mut digest = [0u8; 32];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256,
                data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA256) failed: {rc}");
            assert_eq!(&digest[..], *expected, "SHA-256 digest mismatch for input len={}", data.len());
            assert_hw_was_used!(before, 1);
        }

        // 1,000,000 × 'a'
        {
            let data = vec![b'a'; 1_000_000];
            let before = hw_dispatch_count();
            let mut digest = [0u8; 32];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256,
                &data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA256, 1M×a) failed: {rc}");
            assert_eq!(&digest[..], SHA256_1M_A, "SHA-256(1M×'a') mismatch");
            assert_hw_was_used!(before, 1);
        }
    }

    // -----------------------------------------------------------------------
    // Test 2 — SHA-384 NIST FIPS 180-4 byte vectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_nist_byte_vector() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        let cases: &[(&[u8], &[u8])] = &[
            (b"", &SHA384_EMPTY),
            (b"abc", &SHA384_ABC),
        ];

        for (data, expected) in cases {
            let before = hw_dispatch_count();
            let mut digest = [0u8; 48];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA384) failed: {rc}");
            assert_eq!(&digest[..], *expected, "SHA-384 digest mismatch for input len={}", data.len());
            assert_hw_was_used!(before, 1);
        }

        {
            let data = vec![b'a'; 1_000_000];
            let before = hw_dispatch_count();
            let mut digest = [0u8; 48];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                &data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA384, 1M×a) failed: {rc}");
            assert_eq!(&digest[..], SHA384_1M_A, "SHA-384(1M×'a') mismatch");
            assert_hw_was_used!(before, 1);
        }
    }

    // -----------------------------------------------------------------------
    // Test 3 — SHA-512 NIST FIPS 180-4 byte vectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha512_nist_byte_vector() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        let cases: &[(&[u8], &[u8])] = &[
            (b"", &SHA512_EMPTY),
            (b"abc", &SHA512_ABC),
        ];

        for (data, expected) in cases {
            let before = hw_dispatch_count();
            let mut digest = [0u8; 64];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA512,
                data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA512) failed: {rc}");
            assert_eq!(&digest[..], *expected, "SHA-512 digest mismatch for input len={}", data.len());
            assert_hw_was_used!(before, 1);
        }

        {
            let data = vec![b'a'; 1_000_000];
            let before = hw_dispatch_count();
            let mut digest = [0u8; 64];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA512,
                &data,
                &mut digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA512, 1M×a) failed: {rc}");
            assert_eq!(&digest[..], SHA512_1M_A, "SHA-512(1M×'a') mismatch");
            assert_hw_was_used!(before, 1);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4 — HMAC-SHA-384 NIST vector (RFC 4231 Test Case 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac384_nist_vector() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        // RFC 4231 Test Case 1
        // Key  = 0x0b × 20 bytes
        // Data = "Hi There"
        // Source: RFC 4231 §2, confirmed against NIST CAVP HMAC test vectors.
        const HMAC384_KEY: [u8; 20] = [0x0b; 20];
        const HMAC384_DATA: &[u8] = b"Hi There";
        const HMAC384_RFC4231_TC1: [u8; 48] = [
            0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
            0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
            0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
            0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
            0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
            0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
        ];

        // Compute via CryptoCb (our hw_callback → dispatch_hmac).
        let before = hw_dispatch_count();
        let mut output = [0u8; 48];
        unsafe {
            let mut hmac_ctx: wolfcrypt_sys::Hmac = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_HmacInit(
                &mut hmac_ctx,
                core::ptr::null_mut(),
                HW_DEVICE_ID,
            );
            assert_eq!(rc, 0, "wc_HmacInit failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacSetKey(
                &mut hmac_ctx,
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384 as i32,
                HMAC384_KEY.as_ptr(),
                HMAC384_KEY.len() as u32,
            );
            assert_eq!(rc, 0, "wc_HmacSetKey failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacUpdate(
                &mut hmac_ctx,
                HMAC384_DATA.as_ptr(),
                HMAC384_DATA.len() as u32,
            );
            assert_eq!(rc, 0, "wc_HmacUpdate failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacFinal(&mut hmac_ctx, output.as_mut_ptr());
            assert_eq!(rc, 0, "wc_HmacFinal failed: {rc}");

            wolfcrypt_sys::wc_HmacFree(&mut hmac_ctx);
        }

        assert_eq!(&output[..], &HMAC384_RFC4231_TC1[..], "HMAC-SHA-384 output mismatch (RFC 4231 TC1)");
        assert_hw_was_used!(before, 1);
    }

    // -----------------------------------------------------------------------
    // Test 5 — SHA-384 hardware path matches software (endian bug catcher)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_matches_software() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        // 10 deterministic inputs of varying sizes (fixed LCG seed).
        let sizes: [usize; 10] = [1, 13, 64, 127, 256, 512, 1000, 2048, 4096, 8192];
        let mut seed: u64 = 0xdeadbeef_cafef00d;

        let before = hw_dispatch_count();
        for size in sizes {
            // Fill input deterministically.
            let mut data = vec![0u8; size];
            for b in data.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (seed >> 33) as u8;
            }

            // Hardware path (via CryptoCb).
            let mut hw_digest = [0u8; 48];
            let rc = wc_hash_ex(
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                &data,
                &mut hw_digest,
            );
            assert_eq!(rc, 0, "wc_Hash_ex(SHA384, size={size}) failed: {rc}");

            // Software reference (sha2 crate).
            let sw_digest: [u8; 48] = {
                use sha2::Digest as _;
                sha2::Sha384::digest(&data).into()
            };

            assert_eq!(
                hw_digest, sw_digest,
                "SHA-384 hardware/software mismatch at input size={size}"
            );
        }
        assert_hw_was_used!(before, 10);
    }

    // -----------------------------------------------------------------------
    // Test 6 — streaming matches one-shot
    // -----------------------------------------------------------------------

    #[test]
    fn test_streaming_matches_oneshot() {
        setup();
        let _emu = make_emulator();

        reset_hw_dispatch_count();
        assert_eq!(hw_dispatch_count(), 0, "counter leak from previous test");

        // 4096-byte input, split into 7 unequal chunks.
        let data: Vec<u8> = (0u16..4096).map(|i| (i as u8) ^ (i >> 8) as u8).collect();
        let _splits: [usize; 7] = [1, 100, 333, 512, 1000, 1500, 4096];
        // chunks[i] = data[splits[i-1]..splits[i]]  (splits[0]=1 is first chunk end)
        // We build the actual chunk boundaries:
        let boundaries: [usize; 8] = [0, 1, 101, 434, 946, 1946, 3446, 4096];

        // --- One-shot via wc_Hash_ex ---
        let before_oneshot = hw_dispatch_count();
        let mut oneshot_digest = [0u8; 48];
        let rc = wc_hash_ex(
            wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
            &data,
            &mut oneshot_digest,
        );
        assert_eq!(rc, 0, "wc_Hash_ex one-shot failed: {rc}");
        assert_hw_was_used!(before_oneshot, 1);

        // --- Streaming via wc_HashInit_ex / wc_HashUpdate / wc_HashFinal ---
        let before_stream = hw_dispatch_count();
        let mut stream_digest = [0u8; 48];
        unsafe {
            let mut hash_alg: wolfcrypt_sys::wc_HashAlg = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_HashInit_ex(
                &mut hash_alg,
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                core::ptr::null_mut(),
                HW_DEVICE_ID,
            );
            assert_eq!(rc, 0, "wc_HashInit_ex failed: {rc}");

            for i in 0..7 {
                let chunk = &data[boundaries[i]..boundaries[i + 1]];
                if chunk.is_empty() {
                    continue;
                }
                let rc = wolfcrypt_sys::wc_HashUpdate(
                    &mut hash_alg,
                    wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                    chunk.as_ptr(),
                    chunk.len() as u32,
                );
                assert_eq!(rc, 0, "wc_HashUpdate(chunk {i}) failed: {rc}");
            }

            let rc = wolfcrypt_sys::wc_HashFinal(
                &mut hash_alg,
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
                stream_digest.as_mut_ptr(),
            );
            assert_eq!(rc, 0, "wc_HashFinal failed: {rc}");

            wolfcrypt_sys::wc_HashFree(
                &mut hash_alg,
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
            );
        }
        assert_hw_was_used!(before_stream, 1);

        assert_eq!(
            oneshot_digest, stream_digest,
            "streaming and one-shot SHA-384 digests must be identical"
        );

        // Total dispatch count for both operations combined.
        assert_hw_was_used!(before_oneshot, 2);
    }
}
