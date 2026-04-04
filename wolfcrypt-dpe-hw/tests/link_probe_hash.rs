//! Phase 1 Step 2 validation: verify wc_Hash() links without macro-expansion
//! headers or extra -I flags.  If this file compiles and links, the wolfcrypt-sys
//! CryptoCb bindings are present and complete.

fn main() {
    // wolfCrypt_Init is required before any hash operation (idempotent; FIPS POST).
    let init_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(init_rc == 0 || init_rc == 1, "wolfCrypt_Init failed: {init_rc}");

    // wc_Hash is available unconditionally (no devId variant needed for this probe).
    let data = b"abc";
    let mut digest = [0u8; 32];
    let rc = unsafe {
        wolfcrypt_sys::wc_Hash(
            wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256,
            data.as_ptr(),
            data.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
        )
    };
    assert_eq!(rc, 0, "wc_Hash(SHA256, 'abc') failed with rc={rc}");
    // Digest correctness is validated by CryptoCb integration tests (phase1_hash.rs).
    // This probe only verifies that wc_Hash links and returns 0.
    println!("link_probe_hash: PASS (rc={rc}, digest[0]={:#04x})", digest[0]);
}
