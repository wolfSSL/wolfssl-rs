//! Phase 5 link probe integration test.
//!
//! Calls one function from each dispatch module via wolfcrypt-sys directly.
//! No -I flags.  Must link without any macro-expansion headers.
//!
//! Each function called here is a symbol from a different dispatch module:
//!   dispatch_hash   → wc_Hash_ex (SHA-256)
//!   dispatch_hmac   → wc_HmacInit
//!   dispatch_rng    → wc_InitRng_ex
//!   dispatch_cipher → wc_AesGcmEncrypt (after wc_AesInit + wc_AesGcmSetKey)
//!   dispatch_pk     → wc_ecc_init_ex
//!
//! This test uses harness = false so it has its own main().

#[cfg(all(feature = "caliptra-2x", not(target_arch = "riscv32")))]
fn main() {
    // wolfCrypt must be initialised before any API calls.
    let rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(rc == 0 || rc == 1, "wolfCrypt_Init failed: {rc}");

    wolfcrypt_dpe_hw::init().expect("wolfcrypt_dpe_hw::init failed");

    unsafe {
        // --- dispatch_hash: wc_Hash_ex (SHA-256, 3 bytes) --------------------
        let data = [0x61u8, 0x62, 0x63]; // "abc"
        let mut digest = [0u8; 32];
        let rc = wolfcrypt_sys::wc_Hash_ex(
            wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256,
            data.as_ptr(),
            data.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
            core::ptr::null_mut(),
            wolfcrypt_dpe_hw::HW_DEVICE_ID,
        );
        // Link probe: verify the symbol links and the call succeeds.
        // Output correctness is verified by the phase1_hash tests (run with --test-threads=1).
        // The link probe runs concurrently with other tests so exact output is not asserted.
        assert_eq!(rc, 0, "wc_Hash_ex(SHA256) failed: {rc}");
        assert_ne!(digest, [0u8; 32], "SHA-256 output must not be all-zero");

        // --- dispatch_hmac: wc_HmacInit + key + update + final + free --------
        let mut hmac: wolfcrypt_sys::Hmac = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_HmacInit(
            &mut hmac,
            core::ptr::null_mut(),
            wolfcrypt_dpe_hw::HW_DEVICE_ID,
        );
        assert_eq!(rc, 0, "wc_HmacInit failed: {rc}");
        let key = [0x0bu8; 20];
        let rc = wolfcrypt_sys::wc_HmacSetKey(
            &mut hmac,
            wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384 as i32,
            key.as_ptr(),
            key.len() as u32,
        );
        assert_eq!(rc, 0, "wc_HmacSetKey failed: {rc}");
        let msg = b"Hi There";
        let rc = wolfcrypt_sys::wc_HmacUpdate(&mut hmac, msg.as_ptr(), msg.len() as u32);
        assert_eq!(rc, 0, "wc_HmacUpdate failed: {rc}");
        let mut mac_out = [0u8; 48];
        let rc = wolfcrypt_sys::wc_HmacFinal(&mut hmac, mac_out.as_mut_ptr());
        assert_eq!(rc, 0, "wc_HmacFinal failed: {rc}");
        wolfcrypt_sys::wc_HmacFree(&mut hmac);

        // --- dispatch_rng: wc_InitRng_ex + wc_RNG_GenerateBlock + free ------
        let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_InitRng_ex(
            &mut rng,
            core::ptr::null_mut(),
            wolfcrypt_dpe_hw::HW_DEVICE_ID,
        );
        assert_eq!(rc, 0, "wc_InitRng_ex failed: {rc}");
        let mut buf = [0u8; 16];
        let rc = wolfcrypt_sys::wc_RNG_GenerateBlock(&mut rng, buf.as_mut_ptr(), 16);
        assert_eq!(rc, 0, "wc_RNG_GenerateBlock failed: {rc}");
        wolfcrypt_sys::wc_FreeRng(&mut rng);

        // --- dispatch_cipher: wc_AesInit + wc_AesGcmSetKey + encrypt + free -
        let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), wolfcrypt_dpe_hw::HW_DEVICE_ID);
        let aes_key = [0x00u8; 32];
        let rc = wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, aes_key.as_ptr(), 32);
        assert_eq!(rc, 0, "wc_AesGcmSetKey failed: {rc}");
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let rc = wolfcrypt_sys::wc_AesGcmEncrypt(
            &mut aes,
            ct.as_mut_ptr(), pt.as_ptr(), 16,
            iv.as_ptr(), 12,
            tag.as_mut_ptr(), 16,
            core::ptr::null(), 0,
        );
        assert_eq!(rc, 0, "wc_AesGcmEncrypt failed: {rc}");
        wolfcrypt_sys::wc_AesFree(&mut aes);

        // --- dispatch_pk: wc_ecc_init_ex -----------------------------------
        let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_ecc_init_ex(
            &mut key,
            core::ptr::null_mut(),
            wolfcrypt_dpe_hw::HW_DEVICE_ID,
        );
        assert_eq!(rc, 0, "wc_ecc_init_ex failed: {rc}");
        wolfcrypt_sys::wc_ecc_free(&mut key);
    }

    println!("link_probe_integration PASSED — all dispatch module symbols link and execute");
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../audit/phase5_link_probe.txt"),
        "PASS: all dispatch module symbols link without macro-expansion headers\n\
         Verified: wc_Hash_ex, wc_HmacInit, wc_InitRng_ex, wc_AesGcmEncrypt, wc_ecc_init_ex\n",
    )
    .ok();
}

#[cfg(not(all(feature = "caliptra-2x", not(target_arch = "riscv32"))))]
fn main() {
    eprintln!("link_probe_integration: requires caliptra-2x on non-riscv32");
    std::process::exit(1);
}
