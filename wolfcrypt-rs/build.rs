//
// Build script for wolfcrypt-rs.
//
// wolfcrypt-rs depends on wolfcrypt-sys for the compiled wolfSSL library.
// This build script reads metadata from wolfcrypt-sys, compiles compat_shim.c,
// and re-exports metadata for downstream crates (wolfcrypt-ring-compat).

use std::env;

fn main() {
    let vendored = env::var("DEP_WOLFCRYPT_SYS_VENDORED").unwrap_or_default() == "1";

    // --- Read and re-emit cfg flags from wolfcrypt-sys ---
    let active_cfgs = env::var("DEP_WOLFCRYPT_SYS_CFGS").unwrap_or_default();
    for cfg in active_cfgs.split(',').filter(|s| !s.is_empty()) {
        println!("cargo:rustc-cfg={cfg}");
    }
    let all_cfgs = env::var("DEP_WOLFCRYPT_SYS_ALL_CFGS").unwrap_or_default();
    for cfg in all_cfgs.split(',').filter(|s| !s.is_empty()) {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }

    // --- Link against wolfssl ---
    if vendored {
        let wolfcrypt_sys_out = env::var("DEP_WOLFCRYPT_SYS_ROOT")
            .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_ROOT not set — is wolfcrypt-sys a dependency?"));
        println!("cargo:rustc-link-search=native={wolfcrypt_sys_out}");
        println!("cargo:rustc-link-lib=static=wolfssl");
    } else {
        // System library: add pkg-config lib dirs and link dynamically
        let lib_dirs = env::var("DEP_WOLFCRYPT_SYS_LIB_DIRS").unwrap_or_default();
        for dir in lib_dirs.split(':').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-search=native={dir}");
        }
        println!("cargo:rustc-link-lib=wolfssl");
    }

    // --- Compile compat_shim.c ---
    let wolfssl_include = env::var("DEP_WOLFCRYPT_SYS_INCLUDE")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_INCLUDE not set — is wolfcrypt-sys a dependency?"));
    let settings_include = env::var("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE not set — is wolfcrypt-sys a dependency?"));

    let mut shim_build = cc::Build::new();
    shim_build.include(&wolfssl_include);
    shim_build.include(&settings_include);
    if vendored {
        shim_build.define("WOLFSSL_USER_SETTINGS", None);
    }
    if cfg!(feature = "fips") {
        shim_build.define("HAVE_FIPS", None);
    }
    shim_build.warnings(true);
    shim_build.flag_if_supported("-Wall");
    shim_build.flag_if_supported("-Wextra");
    shim_build.flag_if_supported("-Wno-unused-parameter");
    shim_build.flag_if_supported("-Wno-sign-compare");
    shim_build.flag_if_supported("-Wno-discarded-qualifiers");
    shim_build.opt_level(2);
    shim_build.file("src/compat_shim.c");
    shim_build.compile("wolfssl_shims");

    // --- Re-export metadata for wolfcrypt-ring-compat ---
    println!("cargo:CFGS={}", env::var("DEP_WOLFCRYPT_SYS_CFGS")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_CFGS not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:ALL_CFGS={}", env::var("DEP_WOLFCRYPT_SYS_ALL_CFGS")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_ALL_CFGS not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:INCLUDE={}", env::var("DEP_WOLFCRYPT_SYS_INCLUDE")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_INCLUDE not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:SETTINGS_INCLUDE={}", env::var("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:ROOT={}", env::var("DEP_WOLFCRYPT_SYS_ROOT")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_ROOT not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:LIBCRYPTO={}", env::var("DEP_WOLFCRYPT_SYS_LIBCRYPTO")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_LIBCRYPTO not set — is wolfcrypt-sys a dependency?")));
    println!("cargo:VENDORED={}", env::var("DEP_WOLFCRYPT_SYS_VENDORED")
        .unwrap_or_else(|_| panic!("DEP_WOLFCRYPT_SYS_VENDORED not set — is wolfcrypt-sys a dependency?")));

    // --- rerun-if-changed ---
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/compat_shim.c");
}
