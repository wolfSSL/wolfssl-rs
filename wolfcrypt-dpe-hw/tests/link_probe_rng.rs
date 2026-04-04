//! Phase 2 Step 2 validation: verify wc_RNG_GenerateBlock links without
//! macro-expansion headers or extra -I flags.  If this file compiles and
//! links, the wolfcrypt-sys RNG bindings are present and the wolfSSL library
//! supplies the wc_InitRng_ex / wc_RNG_GenerateBlock / wc_FreeRng symbols.

use std::fs;
use std::path::Path;

fn main() {
    let init_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(
        init_rc == 0 || init_rc == 1,
        "wolfCrypt_Init failed: {init_rc}"
    );

    let mut output = [0u8; 32];
    let rc = unsafe {
        let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();

        // Initialise with INVALID_DEVID (software path) so the probe does not
        // depend on the CryptoCb device being registered.
        let init_rc = wolfcrypt_sys::wc_InitRng(&mut rng);
        assert_eq!(init_rc, 0, "wc_InitRng failed: {init_rc}");

        let gen_rc = wolfcrypt_sys::wc_RNG_GenerateBlock(
            &mut rng,
            output.as_mut_ptr(),
            output.len() as u32,
        );

        wolfcrypt_sys::wc_FreeRng(&mut rng);
        gen_rc
    };
    assert_eq!(rc, 0, "wc_RNG_GenerateBlock failed with rc={rc}");

    // Write result to audit file as required by PROMPT-agentic.md.
    let audit_path = Path::new("./audit/phase2_link_probe.txt");
    if let Some(parent) = audit_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let result = format!(
        "link_probe_rng: PASS\nrc={rc}\noutput[0]={:#04x}\n",
        output[0]
    );
    fs::write(audit_path, &result)
        .unwrap_or_else(|e| eprintln!("warning: could not write audit file: {e}"));
    println!("link_probe_rng: PASS (rc={rc}, output[0]={:#04x})", output[0]);
}
