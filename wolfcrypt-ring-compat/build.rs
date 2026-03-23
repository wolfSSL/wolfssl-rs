use std::env;

fn main() {
    let has_mutually_exclusive_features = cfg!(feature = "non-fips") && cfg!(feature = "fips");
    assert!(
        !has_mutually_exclusive_features,
        "`fips` and `non-fips` are mutually exclusive crate features."
    );

    println!("cargo:rustc-check-cfg=cfg(wolfcrypt_ring_compat_docsrs)");
    println!("cargo:rustc-check-cfg=cfg(disable_slow_tests)");
    println!("cargo:rustc-check-cfg=cfg(dev_tests_only)");
    if let Ok(disable) = env::var("WOLFSSL_RS_DISABLE_SLOW_TESTS") {
        if disable == "1" {
            println!("cargo:warning=### Slow tests will be disabled! ###");
            println!("cargo:rustc-cfg=disable_slow_tests");
        } else {
            println!("cargo:warning=### Slow tests are enabled: {disable}! ###");
        }
    }
    println!("cargo:rerun-if-env-changed=WOLFSSL_RS_DISABLE_SLOW_TESTS");

    let mut enable_dev_test_only = None;
    if cfg!(feature = "dev-tests-only") {
        enable_dev_test_only = Some(true);
    }
    // Environment variable can override
    if let Ok(dev_tests) = env::var("WOLFSSL_RS_DEV_TESTS_ONLY") {
        println!("cargo:warning=### WOLFSSL_RS_DEV_TESTS_ONLY: '{dev_tests}' ###");
        enable_dev_test_only = Some(dev_tests == "1");
    }
    println!("cargo:rerun-if-env-changed=WOLFSSL_RS_DEV_TESTS_ONLY");

    if let Some(dev_test_only) = enable_dev_test_only {
        if dev_test_only {
            let profile = env::var("PROFILE").unwrap();
            if !profile.contains("dev") && !profile.contains("debug") && !profile.contains("test") {
                println!("cargo:warning=### PROFILE: '{profile}' ###");
                panic!("dev-tests-only feature only allowed for dev profile builds");
            }
            println!("cargo:warning=### Enabling public testing functions! ###");
            println!("cargo:rustc-cfg=dev_tests_only");
        } else {
            println!("cargo:warning=### WOLFSSL_RS_DEV_TESTS_ONLY: Public testing functions not enabled! ###");
        }
    }

    // Both `fips` and `non-fips` features enable wolfcrypt-rs (with or without
    // the `fips` feature flag). The sys crate is always wolfcrypt-rs.
    let sys_crate = if cfg!(feature = "wolfcrypt-rs") {
        "wolfcrypt-rs"
    } else {
        panic!(
            "one of the following features must be specified: `wolfcrypt-rs`, `non-fips`, or `fips`."
        );
    };

    // When using static CRT on Windows MSVC, ignore missing PDB file warnings
    // The static CRT libraries reference PDB files from Microsoft's build servers
    // which are not available during linking
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && env::var("CARGO_CFG_TARGET_FEATURE")
            .is_ok_and(|features| features.contains("crt-static"))
    {
        println!("cargo:rustc-link-arg=/ignore:4099");
    }

    export_sys_vars(sys_crate);
}

fn export_sys_vars(_sys_crate: &str) {
    // wolfcrypt-rs always uses links = "wolfssl", regardless of FIPS mode.
    let prefix = "DEP_WOLFSSL_";

    let mut selected = String::default();
    let mut candidates = vec![];

    // Search through the DEP vars and find the correct prefix.
    // Cargo's `links` metadata produces env vars like DEP_<LINKS>_<KEY>.
    // For versioned crate names, Cargo may insert a version component:
    //   DEP_WOLFSSL_<VERSION>_INCLUDE
    // For non-versioned (our case with links = "wolfssl"):
    //   DEP_WOLFSSL_INCLUDE
    // We detect the prefix by finding the var ending in INCLUDE.
    for (name, value) in std::env::vars() {
        // if we've selected a prefix then we can go straight to exporting it
        if !selected.is_empty() {
            try_export_var(&selected, &name, &value);
            continue;
        }

        // we're still looking for a selected prefix
        if let Some(rest) = name.strip_prefix(prefix) {
            if rest == "INCLUDE" {
                // Non-versioned: DEP_WOLFSSL_INCLUDE
                selected = prefix.to_string();
                try_export_var(&selected, &name, &value);
            } else if let Some(version) = rest.strip_suffix("_INCLUDE") {
                // Versioned: DEP_WOLFSSL_<version>_INCLUDE
                selected = format!("{prefix}{version}_");
                try_export_var(&selected, &name, &value);
            } else {
                // it started with the expected prefix, but we don't know what the version is yet
                // so save it for later
                candidates.push((name, value));
            }
        }
    }

    assert!(!selected.is_empty(), "missing {prefix} include");

    // process all of the remaining candidates
    for (name, value) in candidates {
        try_export_var(&selected, &name, &value);
    }
}

fn try_export_var(selected: &str, name: &str, value: &str) {
    assert!(!selected.is_empty(), "missing selected prefix");

    if let Some(var) = name.strip_prefix(selected) {
        eprintln!("cargo:rerun-if-env-changed={name}");
        let var = var.to_lowercase();

        // ALL_CFGS: comma-separated list of every possible wolfssl_* cfg name,
        // exported by wolfcrypt-rs so we don't duplicate the list here.
        // Declare each as check-cfg so Rust doesn't warn about disabled cfgs.
        if var == "all_cfgs" {
            for cfg in value.split(',') {
                let cfg = cfg.trim();
                if !cfg.is_empty() {
                    println!("cargo:rustc-check-cfg=cfg({cfg})");
                }
            }
            return;
        }

        // CFGS: comma-separated list of *active* wolfssl_* cfg flags.
        // Re-emit them as rustc-cfg directives.
        if var == "cfgs" {
            for cfg in value.split(',') {
                let cfg = cfg.trim();
                if !cfg.is_empty() {
                    println!("cargo:rustc-cfg={cfg}");
                }
            }
            return;
        }

        println!("cargo:{var}={value}");
    }
}
