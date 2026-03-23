fn main() {
    // Mirror wolfcrypt's cfg detection.
    // wolfcrypt-rs re-exports metadata from wolfcrypt-sys.
    // We read the cfg flags to gate our tests the same way.
    let cfgs = std::env::var("DEP_WOLFSSL_CFGS").unwrap_or_default();
    for cfg in cfgs.split(',').filter(|s| !s.is_empty()) {
        println!("cargo:rustc-cfg={cfg}");
    }
    let all = std::env::var("DEP_WOLFSSL_ALL_CFGS").unwrap_or_default();
    for cfg in all.split(',').filter(|s| !s.is_empty()) {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }
}
