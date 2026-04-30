// wolfcrypt-dpe-hw build script.
//
// Compiles `caliptra_seed.c` only when both:
//   - the `caliptra-2x` feature is enabled, AND
//   - the target architecture is `riscv32`.
//
// On non-riscv32 (host / test) targets, the CryptoCb WC_ALGO_TYPE_RNG
// callback in hw_rng.rs handles TRNG dispatch without a C shim.

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let caliptra_2x = std::env::var("CARGO_FEATURE_CALIPTRA_2X").is_ok();

    if caliptra_2x && target_arch == "riscv32" {
        // Locate the wolfSSL include dirs via DEP_WOLFSSL env vars propagated
        // from wolfcrypt-rs (which has `links = "wolfssl"`).
        let include = std::env::var("DEP_WOLFSSL_INCLUDE").unwrap_or_default();
        let settings_include = std::env::var("DEP_WOLFSSL_SETTINGS_INCLUDE").unwrap_or_default();

        let mut build = cc::Build::new();
        build
            .file("src/caliptra_seed.c")
            .define("WOLFSSL_USER_SETTINGS", None);

        if !include.is_empty() {
            build.include(&include);
        }
        if !settings_include.is_empty() {
            build.include(&settings_include);
        }

        build.compile("caliptra_seed");
        println!("cargo:rerun-if-changed=src/caliptra_seed.c");
    }
}
