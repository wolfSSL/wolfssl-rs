//! Phase 4 link probe: verify wc_ecc_sign_hash / wc_ecc_verify_hash link
//! without macro-expansion headers or extra -I flags.  If this file compiles
//! and links, the wolfcrypt-sys ECC bindings are present and complete.
//!
//! This probe runs WITHOUT wolfcrypt_dpe_hw::init() to avoid hardware
//! registration.  It uses INVALID_DEVID (software path) so the ECC
//! operations are pure wolfCrypt and require no CryptoCb callback.

fn main() {
    let init_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(init_rc == 0 || init_rc == 1, "wolfCrypt_Init failed: {init_rc}");

    // --- RNG ---
    let mut rng: wolfcrypt_sys::WC_RNG = unsafe { core::mem::zeroed() };
    let rc = unsafe { wolfcrypt_sys::wc_InitRng(&mut rng) };
    assert_eq!(rc, 0, "wc_InitRng failed: {rc}");

    // --- Key generation ---
    let mut key: wolfcrypt_sys::ecc_key = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        wolfcrypt_sys::wc_ecc_init_ex(
            &mut key,
            core::ptr::null_mut(),
            wolfcrypt_sys::INVALID_DEVID,
        )
    };
    assert_eq!(rc, 0, "wc_ecc_init_ex failed: {rc}");

    let rc = unsafe {
        wolfcrypt_sys::wc_ecc_make_key_ex(
            &mut rng,
            48,
            &mut key,
            wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
        )
    };
    assert_eq!(rc, 0, "wc_ecc_make_key_ex failed: {rc}");

    // --- Sign ---
    let hash = [0u8; 48];
    let mut sig = vec![0u8; 128];
    let mut sig_len: wolfcrypt_sys::word32 = 128;
    let rc = unsafe {
        wolfcrypt_sys::wc_ecc_sign_hash(
            hash.as_ptr(),
            48,
            sig.as_mut_ptr(),
            &mut sig_len,
            &mut rng,
            &mut key,
        )
    };
    assert_eq!(rc, 0, "wc_ecc_sign_hash failed: {rc}");
    assert!(sig_len > 0 && sig_len <= 128, "unexpected sig_len={sig_len}");

    // --- Verify ---
    let mut result: core::ffi::c_int = 0;
    let rc = unsafe {
        wolfcrypt_sys::wc_ecc_verify_hash(
            sig.as_ptr(),
            sig_len,
            hash.as_ptr(),
            48,
            &mut result,
            &mut key,
        )
    };
    assert_eq!(rc, 0, "wc_ecc_verify_hash failed: {rc}");
    assert_eq!(result, 1, "signature verification failed");

    // --- wc_ecc_shared_secret symbol probe ---
    // Just verify it links; don't call it (would need a second key pair).
    let _fn_ptr: unsafe extern "C" fn(
        *mut wolfcrypt_sys::ecc_key,
        *mut wolfcrypt_sys::ecc_key,
        *mut wolfcrypt_sys::byte,
        *mut wolfcrypt_sys::word32,
    ) -> core::ffi::c_int = wolfcrypt_sys::wc_ecc_shared_secret;
    let _ = _fn_ptr;

    // --- Cleanup ---
    unsafe {
        wolfcrypt_sys::wc_ecc_free(&mut key);
        wolfcrypt_sys::wc_FreeRng(&mut rng);
    }

    // Write result to audit file (best-effort; ignore fs errors in test env).
    let _ = std::fs::create_dir_all("./audit");
    let _ = std::fs::write("./audit/phase4_link_probe.txt", "LINK OK\n");
    println!("link_probe_pk: PASS (sig_len={sig_len}, result={result})");
}
