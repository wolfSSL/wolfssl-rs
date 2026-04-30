use std::env;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Rerun triggers for all relevant env vars.
    println!("cargo:rerun-if-env-changed=WOLFTPM_SRC");
    println!("cargo:rerun-if-env-changed=WOLFSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_SRC");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // ----------------------------------------------------------------
    // 1. Locate wolfTPM source tree.
    // ----------------------------------------------------------------
    let wolftpm_src = locate_wolftpm_src();

    // ----------------------------------------------------------------
    // 2. Locate wolfSSL headers.
    // ----------------------------------------------------------------
    let (wolfssl_include, wolfssl_settings_include) = locate_wolfssl_headers();

    // ----------------------------------------------------------------
    // 3. Generate wolftpm/options.h in OUT_DIR.
    //
    // wolfTPM's tpm2_types.h does `#include <wolftpm/options.h>`.
    // By placing our generated file in OUT_DIR/wolftpm/ and prepending
    // OUT_DIR to the include search path we satisfy the requirement
    // without modifying the wolfTPM source tree.
    // ----------------------------------------------------------------
    let opts_dir = out_dir.join("wolftpm");
    std::fs::create_dir_all(&opts_dir).expect("create wolftpm dir in OUT_DIR");
    let opts_path = opts_dir.join("options.h");
    generate_wolftpm_options(&opts_path);

    // ----------------------------------------------------------------
    // 4. Compile wolfTPM C sources.
    // ----------------------------------------------------------------
    let mut build = cc::Build::new();

    // OUT_DIR first so our wolftpm/options.h takes priority.
    build.include(&out_dir);
    // wolfTPM root — for `wolftpm/` headers.
    build.include(&wolftpm_src);
    // wolfTPM HAL directory — for `hal/tpm_io.h` (included by tpm2_wrap.c).
    build.include(wolftpm_src.join("hal"));
    // wolfSSL headers.
    build.include(&wolfssl_include);
    if let Some(ref settings_inc) = wolfssl_settings_include {
        build.include(settings_inc);
    }

    // wolfSSL settings mode: define WOLFSSL_USER_SETTINGS only when a
    // user_settings.h is actually present, matching the conditional logic in
    // wolftpm-sys/build.rs so the shim and the wolfTPM library see the same
    // wolfSSL header configuration.
    //
    // For pre-built installs, user_settings.h lives in the include dir (e.g.
    // $WOLFSSL_DIR/include/user_settings.h).  For vendored builds,
    // wolfssl_settings_include points to the wolfssl-src crate directory that
    // holds user_settings.h.
    let user_settings_h = wolfssl_include.join("user_settings.h");
    let use_user_settings = wolfssl_settings_include.is_some() || user_settings_h.exists();
    if use_user_settings {
        build.define("WOLFSSL_USER_SETTINGS", None);
    }

    build.warnings(false);
    build.opt_level(2);

    // Core src/ files (always compiled).
    let src_dir = wolftpm_src.join("src");
    let core_sources = [
        "tpm2.c",
        "tpm2_wrap.c",
        "tpm2_packet.c",
        "tpm2_param_enc.c",
        "tpm2_util.c",
        "tpm2_crypto.c",
    ];
    for name in &core_sources {
        let path = src_dir.join(name);
        build.file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Optional / platform-specific files.  Compile when present; skip
    // gracefully if absent in older wolfTPM versions or forks.
    // tpm2_winapi.c is excluded (Windows only).
    // tpm2_spdm.c is excluded (SPDM protocol — separate dependency).
    let optional_sources = [
        "tpm2_cryptocb.c",  // wolfSSL crypto-callback integration
        "tpm2_linux.c",     // Linux /dev/tpm0 kernel driver
        "tpm2_swtpm.c",     // Software TPM (swtpm / IBM simulator)
        "tpm2_tis.c",       // TIS/SPI hardware transport
    ];
    for name in &optional_sources {
        let path = src_dir.join(name);
        if path.exists() {
            build.file(&path);
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    build.compile("wolftpm");

    // ----------------------------------------------------------------
    // 5. Emit cargo metadata for wolftpm-sys.
    // ----------------------------------------------------------------
    println!("cargo:INCLUDE={}", wolftpm_src.display());
    println!("cargo:LIB={}", out_dir.display());
}

// ----------------------------------------------------------------
// wolftpm/options.h generation
// ----------------------------------------------------------------

/// Generate a minimal `wolftpm/options.h` in `OUT_DIR/wolftpm/`.
///
/// wolfTPM's `tpm2_types.h` does `#include <wolftpm/options.h>`.
/// We supply transport-selection defines based on Cargo features.
fn generate_wolftpm_options(path: &std::path::Path) {
    let mut f = std::fs::File::create(path)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
    writeln!(f, "/* Auto-generated by wolftpm-src build.rs — do not edit */").unwrap();
    writeln!(f, "#ifndef WOLFTPM_OPTIONS_H").unwrap();
    writeln!(f, "#define WOLFTPM_OPTIONS_H").unwrap();
    writeln!(f).unwrap();

    // Transport selection from Cargo features.
    let linux_dev = env::var("CARGO_FEATURE_LINUX_DEV").is_ok();
    let swtpm = env::var("CARGO_FEATURE_SWTPM").is_ok();

    if linux_dev {
        writeln!(f, "#define WOLFTPM_LINUX_DEV").unwrap();
    }
    if swtpm {
        writeln!(f, "#define WOLFTPM_SWTPM").unwrap();
    }

    // If neither transport feature is selected, default to WOLFTPM_LINUX_DEV
    // on Linux.  This maps TPM2_IoCb to NULL (no hardware I/O callback needed)
    // and uses the kernel's /dev/tpm0 or /dev/tpmrm0 character device.
    // Without an explicit transport, wolfTPM's hal/tpm_io.h leaves TPM2_IoCb
    // undefined which prevents tpm2_wrap.c from compiling.
    if !linux_dev && !swtpm {
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        if target_os == "linux" || target_os.is_empty() {
            writeln!(f, "#define WOLFTPM_LINUX_DEV").unwrap();
        }
    }
    writeln!(f).unwrap();
    writeln!(f, "#endif /* WOLFTPM_OPTIONS_H */").unwrap();
}

// ----------------------------------------------------------------
// wolfTPM source discovery
// ----------------------------------------------------------------

fn locate_wolftpm_src() -> PathBuf {
    // Priority 1: WOLFTPM_SRC env var.
    if let Ok(val) = env::var("WOLFTPM_SRC") {
        if !val.is_empty() {
            let path = PathBuf::from(&val);
            if path.exists() {
                return path;
            }
            panic!("WOLFTPM_SRC={val} does not exist");
        }
    }

    // Priority 2: bundled submodule (wolftpm-src/wolftpm/ inside this crate).
    // Present after `git submodule update --init wolftpm-src/wolftpm`.
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wolftpm");
    if bundled.join("src").exists() {
        return bundled;
    }

    panic!(
        "wolfTPM source not found.\n\
         Options:\n\
         1. Set WOLFTPM_SRC=/path/to/wolfTPM source directory\n\
         2. Run: git submodule update --init wolftpm-src/wolftpm"
    );
}

// ----------------------------------------------------------------
// wolfSSL header discovery
// ----------------------------------------------------------------

/// Returns `(wolfssl_include, wolfssl_settings_include)`.
///
/// `wolfssl_settings_include` is `Some` only in vendored mode, pointing to the
/// directory that contains `user_settings.h` (the wolfssl-src crate directory,
/// supplied via `WOLFSSL_SETTINGS_INCLUDE`).
fn locate_wolfssl_headers() -> (PathBuf, Option<PathBuf>) {
    // Priority 1: WOLFSSL_INCLUDE_DIR — explicit include path to pre-built headers.
    if let Ok(val) = env::var("WOLFSSL_INCLUDE_DIR") {
        if !val.is_empty() {
            let path = PathBuf::from(&val);
            if path.exists() {
                return (path, None);
            }
            panic!("WOLFSSL_INCLUDE_DIR={val} does not exist");
        }
    }

    // Priority 2: WOLFSSL_DIR — install prefix; headers at $WOLFSSL_DIR/include.
    if let Ok(val) = env::var("WOLFSSL_DIR") {
        if !val.is_empty() {
            let include = PathBuf::from(&val).join("include");
            if include.exists() {
                return (include, None);
            }
            panic!("WOLFSSL_DIR={val} exists but {}/include does not", val);
        }
    }

    // Priority 3: WOLFSSL_SRC — vendored source tree.
    if let Ok(val) = env::var("WOLFSSL_SRC") {
        if !val.is_empty() {
            let path = PathBuf::from(&val);
            if !path.exists() {
                panic!("WOLFSSL_SRC={val} does not exist");
            }
            let settings_include = env::var("WOLFSSL_SETTINGS_INCLUDE")
                .map(PathBuf::from)
                .ok();
            return (path, settings_include);
        }
    }

    panic!(
        "wolfSSL headers not found. Set WOLFSSL_INCLUDE_DIR, WOLFSSL_DIR, or WOLFSSL_SRC."
    );
}
