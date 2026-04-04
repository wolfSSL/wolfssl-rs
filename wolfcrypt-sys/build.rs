//
// Build script for wolfcrypt-sys: finds wolfSSL (via env vars, pkg-config,
// or wolfssl-src) and generates Rust FFI bindings via bindgen.
//
// Discovery order:
//   1. WOLFSSL_LIB_DIR + WOLFSSL_INCLUDE_DIR  → pre-built library
//   2. WOLFSSL_DIR                            → install prefix (lib/ + include/)
//   3. `vendored` feature / WOLFSSL_SRC       → compile via wolfssl-src
//   4. pkg-config                             → system library
//   5. panic with instructions

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

use wolfssl_src::parse_defines;

// ================================================================
// wolfSSL cfg configuration
// ================================================================

const ALL_WOLFSSL_CFGS: &[&str] = &[
    "wolfssl_openssl_extra",
    "wolfssl_openssl_all",
    "wolfssl_aes_gcm",
    "wolfssl_aes_128",
    "wolfssl_aes_192",
    "wolfssl_aes_256",
    "wolfssl_aes_ctr",
    "wolfssl_aes_cfb",
    "wolfssl_aes_ecb",
    "wolfssl_aes_direct",
    "wolfssl_aes_keywrap",
    "wolfssl_chacha",
    "wolfssl_poly1305",
    "wolfssl_chacha20_poly1305",
    "wolfssl_ecc",
    "wolfssl_ecc_p384",
    "wolfssl_ecc_p521",
    "wolfssl_ed25519",
    "wolfssl_curve25519",
    "wolfssl_ed448",
    "wolfssl_curve448",
    "wolfssl_sha1",
    "wolfssl_sha224",
    "wolfssl_sha384",
    "wolfssl_sha512",
    "wolfssl_sha3",
    "wolfssl_sha256",
    "wolfssl_hkdf",
    "wolfssl_pbkdf2",
    "wolfssl_dh",
    "wolfssl_rsa",
    "wolfssl_hmac",
    "wolfssl_des3",
    "wolfssl_cmac",
    "wolfssl_fips",
    "wolfssl_dilithium",
    "wolfssl_mlkem",
    "wolfssl_blake2b",
    "wolfssl_blake2s",
    "wolfssl_shake128",
    "wolfssl_shake256",
    "wolfssl_aes_xts",
    "wolfssl_aes_ofb",
    "wolfssl_aes_cts",
    "wolfssl_aes_eax",
    "wolfssl_lms",
    "wolfssl_prf",
    "wolfssl_wolfssh",
    "wolfssl_srtp_kdf",
    "wolfssl_aes_ccm",
    "wolfssl_aes_gcm_stream",
    "wolfssl_tls13_hkdf",
    "wolfssl_cryptocb",
    "wolfssl_hpke",
];

fn emit_cfg_flags(defines: &HashSet<String>) -> Vec<String> {
    for cfg in ALL_WOLFSSL_CFGS {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }

    let mut active_cfgs: Vec<String> = Vec::new();
    let mut emit = |cfg: &str| {
        println!("cargo:rustc-cfg={cfg}");
        active_cfgs.push(cfg.to_string());
    };

    let positive_map: &[(&str, &str)] = &[
        ("HAVE_AESGCM", "wolfssl_aes_gcm"),
        ("WOLFSSL_AES_128", "wolfssl_aes_128"),
        ("WOLFSSL_AES_192", "wolfssl_aes_192"),
        ("WOLFSSL_AES_256", "wolfssl_aes_256"),
        ("WOLFSSL_AES_COUNTER", "wolfssl_aes_ctr"),
        ("WOLFSSL_AES_CFB", "wolfssl_aes_cfb"),
        ("HAVE_AES_ECB", "wolfssl_aes_ecb"),
        ("WOLFSSL_AES_DIRECT", "wolfssl_aes_direct"),
        ("HAVE_AES_KEYWRAP", "wolfssl_aes_keywrap"),
        ("HAVE_CHACHA", "wolfssl_chacha"),
        ("HAVE_POLY1305", "wolfssl_poly1305"),
        ("HAVE_ECC", "wolfssl_ecc"),
        ("HAVE_ED25519", "wolfssl_ed25519"),
        ("HAVE_CURVE25519", "wolfssl_curve25519"),
        ("HAVE_ED448", "wolfssl_ed448"),
        ("HAVE_CURVE448", "wolfssl_curve448"),
        ("WOLFSSL_SHA224", "wolfssl_sha224"),
        ("WOLFSSL_SHA384", "wolfssl_sha384"),
        ("WOLFSSL_SHA512", "wolfssl_sha512"),
        ("WOLFSSL_SHA3", "wolfssl_sha3"),
        ("HAVE_HKDF", "wolfssl_hkdf"),
        ("HAVE_PBKDF2", "wolfssl_pbkdf2"),
        ("WOLFSSL_CMAC", "wolfssl_cmac"),
        ("HAVE_FIPS", "wolfssl_fips"),
        ("HAVE_DILITHIUM", "wolfssl_dilithium"),
        ("WOLFSSL_HAVE_MLKEM", "wolfssl_mlkem"),
        ("HAVE_BLAKE2B", "wolfssl_blake2b"),
        ("HAVE_BLAKE2S", "wolfssl_blake2s"),
        ("WOLFSSL_SHAKE128", "wolfssl_shake128"),
        ("WOLFSSL_SHAKE256", "wolfssl_shake256"),
        ("WOLFSSL_AES_XTS", "wolfssl_aes_xts"),
        ("WOLFSSL_AES_OFB", "wolfssl_aes_ofb"),
        ("WOLFSSL_AES_CTS", "wolfssl_aes_cts"),
        ("WOLFSSL_AES_EAX", "wolfssl_aes_eax"),
        ("HAVE_LMS", "wolfssl_lms"),
        ("WOLFSSL_HAVE_PRF", "wolfssl_prf"),
        ("WOLFSSL_WOLFSSH", "wolfssl_wolfssh"),
        ("WC_SRTP_KDF", "wolfssl_srtp_kdf"),
        ("HAVE_AESCCM", "wolfssl_aes_ccm"),
        ("WOLFSSL_AESGCM_STREAM", "wolfssl_aes_gcm_stream"),
        ("HAVE_HKDF", "wolfssl_tls13_hkdf"),
        ("WOLF_CRYPTO_CB", "wolfssl_cryptocb"),
        ("HAVE_HPKE", "wolfssl_hpke"),
    ];
    for (define, cfg) in positive_map {
        if defines.contains(*define) {
            emit(cfg);
        }
    }

    if defines.contains("OPENSSL_EXTRA") || defines.contains("OPENSSL_ALL") {
        emit("wolfssl_openssl_extra");
    }
    if defines.contains("OPENSSL_ALL") {
        emit("wolfssl_openssl_all");
    }
    if defines.contains("HAVE_CHACHA") && defines.contains("HAVE_POLY1305") {
        emit("wolfssl_chacha20_poly1305");
    }
    if !defines.contains("NO_DH") {
        emit("wolfssl_dh");
    }
    if !defines.contains("NO_RSA") {
        emit("wolfssl_rsa");
    }
    if !defines.contains("NO_HMAC") {
        emit("wolfssl_hmac");
    }
    if !defines.contains("NO_SHA") {
        emit("wolfssl_sha1");
    }
    if !defines.contains("NO_SHA256") {
        emit("wolfssl_sha256");
    }
    if !defines.contains("NO_DES3") {
        emit("wolfssl_des3");
    }
    if defines.contains("HAVE_ECC")
        && !defines.contains("NO_ECC384")
        && defines.contains("WOLFSSL_SHA384")
    {
        emit("wolfssl_ecc_p384");
    }
    if defines.contains("HAVE_ECC")
        && !defines.contains("NO_ECC521")
        && defines.contains("WOLFSSL_SHA512")
    {
        emit("wolfssl_ecc_p521");
    }

    active_cfgs
}

// ================================================================
// Bindgen
// ================================================================

fn generate_bindings(
    wolfssl_include: &Path,
    manifest_dir: &Path,
    is_fips: bool,
    vendored: bool,
    settings_include: Option<&Path>,
) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_path = out_dir.join("bindings.rs");

    let mut builder = bindgen::Builder::default()
        .header(manifest_dir.join("headers.h").to_str().unwrap())
        .clang_arg(format!("-I{}", wolfssl_include.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .use_core()
        .layout_tests(false);

    if vendored {
        if let Some(settings_dir) = settings_include {
            builder = builder.clang_arg(format!("-I{}", settings_dir.display()));
        }
        builder = builder.clang_arg("-DWOLFSSL_USER_SETTINGS");
        // For bare-metal features, add stub headers (stdio.h, pthread.h, etc.)
        // so bindgen can parse wolfSSL headers without host libc headers.
        if cfg!(any(
            feature = "riscv-bare-metal",
            feature = "cryptocb-only",
            feature = "cryptocb-pure",
        )) {
            if let Ok(stubs) = env::var("WOLFSSL_BARE_METAL_STUBS") {
                builder = builder.clang_arg(format!("-I{}", stubs));
            }
        }
    } else {
        // For system/pkg-config builds, tell settings.h to pull in options.h
        // so that all feature flags (TLS 1.3, SNI, etc.) are visible to bindgen.
        builder = builder.clang_arg("-DWOLFSSL_USE_OPTIONS_H");
    }

    if is_fips {
        builder = builder.clang_arg("-DHAVE_FIPS");
    }

    let bindings = builder
        .generate()
        .expect("bindgen failed to generate bindings");

    bindings
        .write_to_file(&bindings_path)
        .expect("failed to write bindings.rs");
}

// ================================================================
// pkg-config discovery
// ================================================================

fn try_pkg_config() -> Option<(PathBuf, Vec<PathBuf>, HashSet<String>)> {
    let lib = pkg_config::Config::new()
        .atleast_version("5.0")
        .probe("wolfssl")
        .ok()?;

    let include_dir = lib
        .include_paths
        .iter()
        .find(|p| p.join("wolfssl").join("options.h").exists())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "pkg-config found wolfssl but wolfssl/options.h not found in: {:?}",
                lib.include_paths
            );
        });

    let options_h = include_dir.join("wolfssl").join("options.h");
    let defines = parse_defines(&options_h);

    Some((include_dir, lib.link_paths, defines))
}

// ================================================================
// Main
// ================================================================

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let is_fips = cfg!(feature = "fips");

    // --- Discovery ---
    //
    //   1. WOLFSSL_LIB_DIR + WOLFSSL_INCLUDE_DIR → pre-built
    //   2. WOLFSSL_DIR                           → install prefix
    //   3. vendored feature / WOLFSSL_SRC        → wolfssl-src
    //   4. pkg-config                            → system
    //   5. panic

    if let (Ok(lib_dir), Ok(include_dir)) = (
        env::var("WOLFSSL_LIB_DIR"),
        env::var("WOLFSSL_INCLUDE_DIR"),
    ) {
        do_prebuilt(
            &PathBuf::from(lib_dir),
            &PathBuf::from(include_dir),
            &manifest_dir,
            is_fips,
        );
    } else if cfg!(feature = "vendored") {
        // vendored (and features that imply it: riscv-bare-metal, cryptocb-only)
        // always compile from source via wolfssl-src, bypassing any pre-built
        // wolfSSL pointed to by WOLFSSL_DIR.
        do_vendored(&manifest_dir, is_fips);
    } else if let Ok(prefix) = env::var("WOLFSSL_DIR") {
        let prefix = PathBuf::from(prefix);
        do_prebuilt(
            &prefix.join("lib"),
            &prefix.join("include"),
            &manifest_dir,
            is_fips,
        );
    } else if env::var("WOLFSSL_SRC").is_ok() {
        do_vendored(&manifest_dir, is_fips);
    } else if let Some((include_dir, lib_dirs, defines)) = try_pkg_config() {
        do_system(&include_dir, &lib_dirs, &manifest_dir, &defines, is_fips);
    } else {
        panic!(
            "wolfSSL not found. Either:\n  \
             - Install wolfssl and ensure pkg-config can find it\n  \
             - Set WOLFSSL_DIR to a wolfssl install prefix\n  \
             - Set WOLFSSL_LIB_DIR and WOLFSSL_INCLUDE_DIR\n  \
             - Enable the `vendored` feature and set WOLFSSL_SRC\n  \
             - Clone wolfssl: git clone https://github.com/wolfSSL/wolfssl.git\n    \
               then set WOLFSSL_SRC to the cloned path"
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=headers.h");
    println!("cargo:rerun-if-changed=user_settings.h");
    println!("cargo:rerun-if-env-changed=WOLFSSL_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_SRC");
}

/// Use a pre-built wolfssl at explicit lib/include paths.
fn do_prebuilt(
    lib_dir: &Path,
    include_dir: &Path,
    manifest_dir: &Path,
    is_fips: bool,
) {
    if !lib_dir.exists() {
        panic!("wolfssl lib dir does not exist: {}", lib_dir.display());
    }
    if !include_dir.exists() {
        panic!("wolfssl include dir does not exist: {}", include_dir.display());
    }

    // Parse options.h for cfg flags
    let options_h = include_dir.join("wolfssl").join("options.h");
    let defines = if options_h.exists() {
        parse_defines(&options_h)
    } else {
        eprintln!(
            "cargo:warning=wolfssl/options.h not found at {}; cfg flags may be incomplete",
            options_h.display()
        );
        HashSet::new()
    };

    let active_cfgs = emit_cfg_flags(&defines);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=wolfssl");

    generate_bindings(include_dir, manifest_dir, is_fips, false, None);

    emit_metadata(&active_cfgs, include_dir, include_dir, "", &[lib_dir.to_path_buf()], false);
}

/// Compile wolfssl from source via wolfssl-src.
#[cfg(feature = "vendored")]
fn do_vendored(manifest_dir: &Path, is_fips: bool) {
    let mut builder = wolfssl_src::Build::new();
    builder.fips(is_fips);

    if let Ok(src) = env::var("WOLFSSL_SRC") {
        builder.source_dir(PathBuf::from(src));
    }

    let artifacts = builder.build();
    let active_cfgs = emit_cfg_flags(&artifacts.defines);

    // For bare-metal features, bindgen must see the selected user_settings.h
    // (copied to OUT_DIR by wolfssl-src) rather than the default.
    let settings_dir = if cfg!(any(
        feature = "riscv-bare-metal",
        feature = "cryptocb-only",
        feature = "cryptocb-pure",
    )) {
        PathBuf::from(env::var("OUT_DIR").unwrap())
    } else {
        artifacts.settings_include_dir.clone()
    };
    generate_bindings(
        &artifacts.include_dir,
        manifest_dir,
        is_fips,
        true,
        Some(&settings_dir),
    );

    emit_metadata(
        &active_cfgs,
        &artifacts.include_dir,
        &artifacts.settings_include_dir,
        &artifacts.lib_dir.display().to_string(),
        &[],
        true,
    );
}

#[cfg(not(feature = "vendored"))]
fn do_vendored(_manifest_dir: &Path, _is_fips: bool) {
    panic!(
        "wolfSSL source found but the `vendored` feature is not enabled.\n\
         Add `wolfcrypt-sys = {{ features = [\"vendored\"] }}` to your Cargo.toml,\n\
         or install wolfssl and use pkg-config."
    );
}

/// Use a system-installed wolfssl found via pkg-config.
fn do_system(
    include_dir: &Path,
    lib_dirs: &[PathBuf],
    manifest_dir: &Path,
    defines: &HashSet<String>,
    is_fips: bool,
) {
    let active_cfgs = emit_cfg_flags(defines);

    generate_bindings(include_dir, manifest_dir, is_fips, false, None);

    emit_metadata(&active_cfgs, include_dir, include_dir, "", lib_dirs, false);
}

/// Parse `LIBWOLFSSL_VERSION_STRING` from `<include_dir>/wolfssl/version.h`.
fn parse_wolfssl_version(include_dir: &Path) -> String {
    let version_h = include_dir.join("wolfssl").join("version.h");
    let content = match std::fs::read_to_string(&version_h) {
        Ok(s) => s,
        Err(_) => return "unknown".to_string(),
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#define LIBWOLFSSL_VERSION_STRING") {
            let rest = rest.trim();
            if let Some(ver) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                return ver.to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Emit cargo metadata for downstream crates.
fn emit_metadata(
    active_cfgs: &[String],
    include_dir: &Path,
    settings_include_dir: &Path,
    root: &str,
    lib_dirs: &[PathBuf],
    vendored: bool,
) {
    let version = parse_wolfssl_version(include_dir);
    println!("cargo:VERSION={version}");
    println!("cargo:CFGS={}", active_cfgs.join(","));
    println!("cargo:ALL_CFGS={}", ALL_WOLFSSL_CFGS.join(","));
    println!("cargo:INCLUDE={}", include_dir.display());
    println!("cargo:SETTINGS_INCLUDE={}", settings_include_dir.display());
    println!("cargo:ROOT={root}");
    let lib_dirs_str: Vec<String> = lib_dirs.iter().map(|p| p.display().to_string()).collect();
    println!("cargo:LIB_DIRS={}", lib_dirs_str.join(":"));
    println!("cargo:LIBCRYPTO=wolfssl");
    println!("cargo:VENDORED={}", if vendored { "1" } else { "0" });
}
