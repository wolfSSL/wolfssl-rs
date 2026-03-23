use toml_edit::DocumentMut;

fn main() {
    // Determine which dependency is active. Exactly one must be selected.
    // Note: wolfcrypt-ring-compat-fips and wolfcrypt-rs-fips are FIPS variants
    // of their respective base crates (same dep, different feature flags).
    let dep = if cfg!(feature = "wolfcrypt-ring-compat") || cfg!(feature = "wolfcrypt-ring-compat-fips") {
        "wolfcrypt-ring-compat"
    } else if cfg!(feature = "wolfcrypt-rs") || cfg!(feature = "wolfcrypt-rs-fips") {
        "wolfcrypt-rs"
    } else {
        panic!("one of the crate features must be selected");
    };

    // Verify mutual exclusivity: count how many top-level features are active.
    let mut count = 0u32;
    if cfg!(feature = "wolfcrypt-ring-compat") { count += 1; }
    if cfg!(feature = "wolfcrypt-ring-compat-fips") { count += 1; }
    if cfg!(feature = "wolfcrypt-rs") { count += 1; }
    if cfg!(feature = "wolfcrypt-rs-fips") { count += 1; }
    assert_eq!(
        count, 1,
        "exactly one crate feature must be selected at a time"
    );

    let dep_links = get_package_links_property(&format!("../{dep}/Cargo.toml"));
    let dep_snake_case = dep.replace('-', "_");
    build_and_link(dep_links.as_ref(), &dep_snake_case);
}

fn build_and_link(links: &str, target_name: &str) {
    let prefix = links.to_uppercase();

    // ensure that the include path is exported and set up correctly
    cc::Build::new()
        .include(env(format!("DEP_{prefix}_INCLUDE")))
        .include(env(format!("DEP_{prefix}_SETTINGS_INCLUDE")))
        .define("WOLFSSL_USER_SETTINGS", None)
        .file("src/testing.c")
        .compile(&format!("testing_{target_name}"));

    // make sure the root was exported
    let root = env(format!("DEP_{}_ROOT", links.to_uppercase()));
    println!("cargo:rustc-link-search={root}");

    // ensure the libcrypto artifact is linked
    let libcrypto = env(format!("DEP_{}_LIBCRYPTO", links.to_uppercase()));
    println!("cargo:rustc-link-lib={libcrypto}");

    // Propagate cfg flags from the sys crate. This verifies that the
    // CFGS/ALL_CFGS metadata round-trip works end-to-end: sys crate
    // exports them via cargo:CFGS/ALL_CFGS, and downstream crates
    // can read and re-emit them.
    if let Ok(all_cfgs) = std::env::var(format!("DEP_{prefix}_ALL_CFGS")) {
        for cfg in all_cfgs.split(',') {
            let cfg = cfg.trim();
            if !cfg.is_empty() {
                println!("cargo:rustc-check-cfg=cfg({cfg})");
            }
        }
    }
    if let Ok(cfgs) = std::env::var(format!("DEP_{prefix}_CFGS")) {
        for cfg in cfgs.split(',') {
            let cfg = cfg.trim();
            if !cfg.is_empty() {
                println!("cargo:rustc-cfg={cfg}");
            }
        }
    }
}

fn get_package_links_property(cargo_toml_path: &str) -> String {
    let cargo_toml = std::fs::read_to_string(cargo_toml_path).unwrap();
    let cargo_toml = cargo_toml.parse::<DocumentMut>().unwrap();

    let links = cargo_toml["package"]["links"].as_str().unwrap();

    String::from(links)
}

fn env<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    println!("cargo:rerun-if-env-changed={s}");
    std::env::var(s).unwrap_or_else(|_| panic!("missing env var {s}"))
}
