//! Phase 3 Step 2 validation: verify wc_AesGcmEncrypt links without
//! macro-expansion headers or extra -I flags.  If this file compiles and
//! links, the wolfcrypt-sys AES-GCM bindings are present and complete.

fn main() {
    let init_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(init_rc == 0 || init_rc == 1, "wolfCrypt_Init failed: {init_rc}");

    // Call wc_AesGcmEncrypt with zero-length input to verify the symbol links.
    let mut aes: wolfcrypt_sys::Aes = unsafe { core::mem::zeroed() };
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let mut tag = [0u8; 16];
    let rc = unsafe {
        wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), wolfcrypt_sys::INVALID_DEVID);
        wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), key.len() as u32);
        wolfcrypt_sys::wc_AesGcmEncrypt(
            &mut aes,
            core::ptr::null_mut(),
            core::ptr::null(),
            0,
            iv.as_ptr(),
            iv.len() as u32,
            tag.as_mut_ptr(),
            tag.len() as u32,
            core::ptr::null(),
            0,
        )
    };
    unsafe { wolfcrypt_sys::wc_AesFree(&mut aes) };
    assert_eq!(rc, 0, "wc_AesGcmEncrypt(empty) failed with rc={rc}");

    // Write result to audit file (best-effort; ignore fs errors in test env).
    let _ = std::fs::create_dir_all("./audit");
    let _ = std::fs::write("./audit/phase3_link_probe.txt", "LINK OK\n");
    println!("link_probe_aes: PASS (rc={rc}, tag[0]={:#04x})", tag[0]);
}
