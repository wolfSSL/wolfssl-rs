use std::env;
use std::path::PathBuf;

fn main() {
    // ── 1. Read wolfSSL metadata from wolfcrypt-sys ──────────────────────────
    // wolfcrypt-sys has links = "wolfcrypt_sys" so DEP_WOLFCRYPT_SYS_* is
    // available to our build script.
    let wolfssl_include = env::var("DEP_WOLFCRYPT_SYS_INCLUDE")
        .expect("DEP_WOLFCRYPT_SYS_INCLUDE not set; is wolfcrypt-sys a direct dependency?");
    let wolfssl_settings = env::var("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE")
        .unwrap_or_else(|_| wolfssl_include.clone());
    let wolfssl_vendored = env::var("DEP_WOLFCRYPT_SYS_VENDORED")
        .map(|v| v == "1")
        .unwrap_or(false);
    // For pre-built wolfssl installs built with -DWOLFSSL_USER_SETTINGS, the full
    // feature set lives in user_settings.h, not options.h.  Use WOLFSSL_USER_SETTINGS
    // mode when the install provides a user_settings.h.
    let user_settings_h = PathBuf::from(&wolfssl_settings).join("user_settings.h");
    let use_user_settings = wolfssl_vendored || user_settings_h.exists();

    // ── 2. Read wolfTPM metadata from wolftpm-src ────────────────────────────
    let wolftpm_include = env::var("DEP_WOLFTPM_SRC_INCLUDE")
        .expect("DEP_WOLFTPM_SRC_INCLUDE not set; is wolftpm-src a direct dependency?");
    let wolftpm_lib = env::var("DEP_WOLFTPM_SRC_LIB")
        .expect("DEP_WOLFTPM_SRC_LIB not set");

    // ── 2a. Assert wolfTPM version is compatible ─────────────────────────────
    // wolftpm_rs_shim.c accesses WOLFTPM2_CTX::cmdBuf, an internal field that
    // is not part of wolfTPM's stable public API.  Fail the build immediately
    // if the wolfTPM version has changed rather than risking silent misbehaviour.
    // To update: verify shim.c still works, then update TESTED_VERSION_HEX.
    println!("cargo:rerun-if-changed={wolftpm_include}/wolftpm/version.h");
    check_wolftpm_version(&format!("{wolftpm_include}/wolftpm/version.h"));

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // ── 3. Compile the Rust shim and link wolftpm + wolfssl ──────────────────
    // The shim (wolftpm_rs_shim.c) wraps the internal INTERNAL_SEND_COMMAND
    // dispatch to expose a raw-bytes wolftpm_rs_transact() function.
    let mut shim = cc::Build::new();
    shim.file(manifest_dir.join("src/wolftpm_rs_shim.c"))
        .include(&wolftpm_lib)
        .include(&wolftpm_include)
        .include(format!("{wolftpm_include}/hal"))
        .include(&wolfssl_include)
        .include(&wolfssl_settings);
    if use_user_settings {
        shim.define("WOLFSSL_USER_SETTINGS", None);
    } else {
        shim.define("WOLFSSL_USE_OPTIONS_H", None);
    }
    shim.define("WOLFTPM2_NO_WOLFCRYPT", None);
    shim.compile("wolftpm_rs_shim");

    println!("cargo:rustc-link-search=native={wolftpm_lib}");
    println!("cargo:rustc-link-lib=static=wolftpm");

    let wolfssl_vendored_str = env::var("DEP_WOLFCRYPT_SYS_VENDORED").unwrap_or_default();
    if wolfssl_vendored_str == "1" {
        let wolfssl_root = env::var("DEP_WOLFCRYPT_SYS_ROOT").unwrap_or_default();
        if !wolfssl_root.is_empty() {
            println!("cargo:rustc-link-search=native={wolfssl_root}");
        }
        println!("cargo:rustc-link-lib=static=wolfssl");
    } else {
        let lib_dirs = env::var("DEP_WOLFCRYPT_SYS_LIB_DIRS").unwrap_or_default();
        for dir in lib_dirs.split(':').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-search=native={dir}");
        }
        let libcrypto =
            env::var("DEP_WOLFCRYPT_SYS_LIBCRYPTO").unwrap_or_else(|_| "wolfssl".into());
        println!("cargo:rustc-link-lib={libcrypto}");
    }

    // ── 4. Run bindgen ────────────────────────────────────────────────────────
    let bindings = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_str().unwrap())
        // wolftpm_lib is the OUT_DIR from wolftpm-src; it holds wolftpm/options.h
        .clang_arg(format!("-I{wolftpm_lib}"))
        .clang_arg(format!("-I{wolftpm_include}"))
        // hal/ directory for tpm_io.h (included by tpm2_wrap.h indirectly)
        .clang_arg(format!("-I{wolftpm_include}/hal"))
        // wolfSSL include paths
        .clang_arg(format!("-I{wolfssl_include}"))
        .clang_arg(format!("-I{wolfssl_settings}"))
        // wolfSSL settings mode
        .clang_arg(if use_user_settings {
            "-DWOLFSSL_USER_SETTINGS"
        } else {
            "-DWOLFSSL_USE_OPTIONS_H"
        })
        // Exclude the wolfSSL key-import/export helpers from the generated
        // bindings.  The compiled libwolftpm.a has them, but exposing them
        // requires re-exporting wolfcrypt-sys types (ecc_key, RsaKey, etc.)
        // which is complex.  These helpers can be added to a future version
        // once the high-level Rust API wraps them properly.
        .clang_arg("-DWOLFTPM2_NO_WOLFCRYPT")
        // Allowlist: wolfTPM wrapper types and functions
        .allowlist_type("WOLFTPM2_.*")
        .allowlist_type("wolfTPM2_.*")
        .allowlist_type("TpmDevType")
        .allowlist_type("TPM2B_.*")
        .allowlist_type("TPMA_.*")
        .allowlist_type("TPMS_.*")
        .allowlist_type("TPMT_.*")
        .allowlist_type("TPML_.*")
        .allowlist_type("TPMU_.*")
        .allowlist_function("wolfTPM2_.*")
        .allowlist_function("TPM2_.*")
        .allowlist_function("wolftpm_rs_.*")
        .allowlist_item("TPM_.*")
        .allowlist_item("TPM2_.*")
        .allowlist_item("WOLFTPM_.*")
        // Use opaque types for wolfSSL internals that we don't need to inspect
        // directly from Rust; all interaction goes through wolfTPM2_* API.
        .opaque_type("wc_.*")
        .opaque_type("RsaKey")
        .opaque_type("ecc_key")
        .opaque_type("ed25519_key")
        .opaque_type("ed448_key")
        .opaque_type("WC_RNG")
        .opaque_type("WC_SHA.*")
        .opaque_type("Hmac")
        .opaque_type("WOLFSSL.*")
        .opaque_type("Wc.*")
        // Quality settings
        .use_core()
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate wolftpm bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}

/// Assert that the wolfTPM version matches the tested release.
///
/// Reads `LIBWOLFTPM_VERSION_HEX` from `version.h` and panics if it differs
/// from the known-good value.  This catches wolfTPM upgrades before they
/// silently break the shim's internal field accesses.
///
/// To move to a new wolfTPM version:
/// 1. Verify `wolftpm_rs_shim.c` still compiles and works correctly.
/// 2. Update `TESTED_VERSION_HEX` below to the new value.
fn check_wolftpm_version(version_h_path: &str) {
    // wolfTPM commit fbbf6fe / tag v4.0.0
    const TESTED_VERSION_HEX: u64 = 0x04000000;

    let content = std::fs::read_to_string(version_h_path)
        .unwrap_or_else(|e| panic!("cannot read {version_h_path}: {e}"));

    let found = content
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("#define LIBWOLFTPM_VERSION_HEX")?;
            let token = rest.trim().strip_prefix("0x").or_else(|| rest.trim().strip_prefix("0X")).unwrap_or(rest.trim());
            u64::from_str_radix(token, 16).ok()
        })
        .unwrap_or_else(|| panic!(
            "LIBWOLFTPM_VERSION_HEX not found in {version_h_path}; \
             cannot verify wolfTPM version compatibility"
        ));

    if found != TESTED_VERSION_HEX {
        panic!(
            "wolfTPM version mismatch: {version_h_path} defines \
             LIBWOLFTPM_VERSION_HEX=0x{found:08x} but this crate was tested \
             against 0x{TESTED_VERSION_HEX:08x} (v4.0.0 / fbbf6fe).\n\
             wolftpm_rs_shim.c accesses WOLFTPM2_CTX::cmdBuf which is not a \
             stable API — review shim.c for compatibility, then update \
             TESTED_VERSION_HEX in wolftpm-sys/build.rs."
        );
    }
}
