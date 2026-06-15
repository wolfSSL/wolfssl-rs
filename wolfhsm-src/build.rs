use std::env;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Rerun triggers for all relevant env vars.
    println!("cargo:rerun-if-env-changed=WOLFHSM_SRC");
    println!("cargo:rerun-if-env-changed=WOLFSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_DIR");
    println!("cargo:rerun-if-env-changed=WOLFSSL_SRC");
    println!("cargo:rerun-if-env-changed=WOLFSSL_SETTINGS_INCLUDE");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // ----------------------------------------------------------------
    // 1. Locate wolfHSM source tree.
    // ----------------------------------------------------------------
    let wolfhsm_src = locate_wolfhsm_src();

    // ----------------------------------------------------------------
    // 2. Locate wolfSSL headers.
    // ----------------------------------------------------------------
    let (wolfssl_include, wolfssl_settings_include) = locate_wolfssl_headers();

    // ----------------------------------------------------------------
    // 3. Generate wolfhsm_cfg.h in OUT_DIR.
    //
    // wolfhsm/wh_settings.h unconditionally does `#include "wolfhsm_cfg.h"`.
    // By placing our generated file in OUT_DIR and prepending it to the
    // include search path we satisfy the requirement without modifying the
    // wolfHSM source tree.
    // ----------------------------------------------------------------
    let cfg_path = out_dir.join("wolfhsm_cfg.h");
    generate_wolfhsm_cfg(&cfg_path);

    // ----------------------------------------------------------------
    // 4. Compile wolfHSM C sources.
    // ----------------------------------------------------------------
    let mut build = cc::Build::new();

    // OUT_DIR first so our wolfhsm_cfg.h takes priority.
    build.include(&out_dir);
    // wolfHSM root — for `wolfhsm/` headers.
    build.include(&wolfhsm_src);
    // POSIX transport headers.
    build.include(wolfhsm_src.join("port").join("posix"));
    // wolfSSL headers.
    build.include(&wolfssl_include);
    if let Some(ref settings_inc) = wolfssl_settings_include {
        build.include(settings_inc);
    }

    // wolfSSL mode defines.
    // Always define WOLFSSL_USER_SETTINGS — both pre-built and vendored modes
    // use the user_settings.h mechanism (pre-built installs expose one at
    // $WOLFSSL_DIR/include/user_settings.h or $WOLFSSL_DIR/include/wolfssl/).
    build.define("WOLFSSL_USER_SETTINGS", None);

    // WOLFHSM_CFG gates the `#include "wolfhsm_cfg.h"` directive in
    // wh_settings.h.  Without it the generated file in OUT_DIR is never
    // included and the required macros (WOLFHSM_CFG_PORT_GETTIME,
    // WOLF_CRYPTO_CB) are never seen.
    build.define("WOLFHSM_CFG", None);

    // WOLF_CRYPTO_CB: the pre-built libwolfssl.a was compiled with this flag.
    // Declare it here so wolfHSM's compile-time check at wh_settings.h:379
    // passes even when the installed user_settings.h doesn't re-declare it.
    build.define("WOLF_CRYPTO_CB", None);

    // wolfHSM client build: software wolfcrypt is available via wolfSSL.
    build.define("WOLFHSM_CFG_NO_WOLFCRYPT", "0");

    build.warnings(false);
    build.opt_level(2);

    // Core src/ files (client-only subset).
    let src_dir = wolfhsm_src.join("src");
    let core_sources = [
        "wh_comm.c",
        "wh_message_comm.c",
        "wh_message_crypto.c",
        "wh_message_keystore.c",
        "wh_message_nvm.c",
        "wh_message_counter.c",
        "wh_message_auth.c",
        "wh_message_she.c",
        "wh_message_cert.c",
        "wh_message_customcb.c",
        "wh_client.c",
        "wh_client_crypto.c",
        "wh_client_nvm.c",
        "wh_client_cryptocb.c",
        "wh_client_keywrap.c",
        "wh_client_auth.c",
        "wh_client_cert.c",
        "wh_client_she.c",
        "wh_client_dma.c",
        "wh_keyid.c",
        "wh_lock.c",
        "wh_log.c",
        "wh_log_printf.c",
        "wh_log_ringbuf.c",
        "wh_utils.c",
        "wh_auth_base.c",
        "wh_crypto.c",
        "wh_dma.c",
        "wh_timeout.c",
        "wh_transport_mem.c",
    ];
    for name in &core_sources {
        let path = src_dir.join(name);
        // Fail loudly if a listed file is missing — a silent omission would
        // produce a library that links but is missing functionality at runtime.
        build.file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // POSIX port files.  All are included when present; some are optional
    // because they may not exist in every wolfHSM version or fork.
    let posix_dir = wolfhsm_src.join("port").join("posix");
    let posix_sources = [
        "posix_transport_tcp.c",
        "posix_transport_shm.c",
        "posix_transport_uds.c", // added post-v1.4.0; skip gracefully if absent
        "posix_transport_tls.c",
        "posix_lock.c",
        "posix_timeout.c",
        "posix_time.c",
    ];
    for name in &posix_sources {
        let path = posix_dir.join(name);
        if path.exists() {
            build.file(&path);
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    build.compile("wolfhsm");

    // ----------------------------------------------------------------
    // 5. Emit cargo metadata for wolfhsm-sys.
    // ----------------------------------------------------------------
    println!("cargo:INCLUDE={}", wolfhsm_src.display());
    println!("cargo:LIB={}", out_dir.display());
}

// ----------------------------------------------------------------
// wolfhsm_cfg.h generation
// ----------------------------------------------------------------

/// Generate a minimal `wolfhsm_cfg.h` in `OUT_DIR`.
///
/// wolfHSM's `wh_settings.h` unconditionally includes `wolfhsm_cfg.h`.
/// We supply:
/// - `WOLFHSM_CFG_PORT_GETTIME` mapped to the POSIX `posixGetTime` helper
///   (declared in `port/posix/posix_time.h`).
/// - `WOLF_CRYPTO_CB` so wolfHSM's crypto-callback check passes.  The
///   pre-built wolfSSL library is compiled with this flag even though the
///   installed `user_settings.h` does not re-declare it.
fn generate_wolfhsm_cfg(path: &std::path::Path) {
    let mut f = std::fs::File::create(path)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
    writeln!(f, "/* Auto-generated by wolfhsm-src build.rs — do not edit */").unwrap();
    writeln!(f, "#ifndef WOLFHSM_CFG_H_").unwrap();
    writeln!(f, "#define WOLFHSM_CFG_H_").unwrap();
    writeln!(f).unwrap();
    // Pull in the POSIX time function declaration.
    writeln!(f, "#include \"port/posix/posix_time.h\"").unwrap();
    writeln!(f).unwrap();
    // Map the wolfHSM time hook to the POSIX implementation.
    writeln!(f, "#define WOLFHSM_CFG_PORT_GETTIME posixGetTime").unwrap();
    writeln!(f).unwrap();
    // Enable client-side wolfHSM functionality (wh_Client_* APIs).
    // Without this, wh_client.c and wh_client_crypto.c compile to empty
    // translation units and all wh_Client_* symbols are absent.
    writeln!(f, "#define WOLFHSM_CFG_ENABLE_CLIENT").unwrap();
    writeln!(f).unwrap();
    // wolfHSM requires WOLF_CRYPTO_CB to be visible at compile time.
    // The pre-built libwolfssl.a is compiled with this flag; declare it here
    // so wolfHSM's header checks pass when building against the pre-built lib.
    writeln!(f, "#ifndef WOLF_CRYPTO_CB").unwrap();
    writeln!(f, "#define WOLF_CRYPTO_CB").unwrap();
    writeln!(f, "#endif").unwrap();
    writeln!(f).unwrap();
    // SHE (Secure Hardware Extension) support — enabled by the `she` Cargo feature.
    if env::var("CARGO_FEATURE_SHE").is_ok() {
        writeln!(f, "#define WOLFHSM_CFG_SHE_EXTENSION").unwrap();
        writeln!(f).unwrap();
    }
    writeln!(f, "#endif /* WOLFHSM_CFG_H_ */").unwrap();
}

// ----------------------------------------------------------------
// wolfHSM source discovery
// ----------------------------------------------------------------

fn locate_wolfhsm_src() -> PathBuf {
    // Priority 1: WOLFHSM_SRC env var.
    if let Ok(val) = env::var("WOLFHSM_SRC")
        && !val.is_empty()
    {
        let path = PathBuf::from(&val);
        if path.exists() {
            return path;
        }
        panic!("WOLFHSM_SRC={val} does not exist");
    }

    // Priority 2: bundled submodule (wolfhsm-src/wolfhsm/ inside this crate).
    // Present after `git submodule update --init wolfhsm-src/wolfhsm`.
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wolfhsm");
    if bundled.join("src").exists() {
        return bundled;
    }

    panic!(
        "wolfHSM source not found.\n\
         Options:\n\
         1. Set WOLFHSM_SRC=/path/to/wolfHSM source directory\n\
         2. Run: git submodule update --init wolfhsm-src/wolfhsm"
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
    if let Ok(val) = env::var("WOLFSSL_INCLUDE_DIR")
        && !val.is_empty()
    {
        let path = PathBuf::from(&val);
        if path.exists() {
            return (path, None);
        }
        panic!("WOLFSSL_INCLUDE_DIR={val} does not exist");
    }

    // Priority 2: WOLFSSL_DIR — install prefix; headers at $WOLFSSL_DIR/include.
    if let Ok(val) = env::var("WOLFSSL_DIR")
        && !val.is_empty()
    {
        let include = PathBuf::from(&val).join("include");
        if include.exists() {
            return (include, None);
        }
        panic!("WOLFSSL_DIR={val} exists but {}/include does not", val);
    }

    // Priority 3: WOLFSSL_SRC — vendored source tree.
    if let Ok(val) = env::var("WOLFSSL_SRC")
        && !val.is_empty()
    {
        let path = PathBuf::from(&val);
        if !path.exists() {
            panic!("WOLFSSL_SRC={val} does not exist");
        }
        // The wolfssl-src crate directory (contains user_settings.h) is
        // provided by WOLFSSL_SETTINGS_INCLUDE.
        let settings_include = env::var("WOLFSSL_SETTINGS_INCLUDE")
            .map(PathBuf::from)
            .ok();
        return (path, settings_include);
    }

    panic!(
        "wolfSSL headers not found. Set WOLFSSL_INCLUDE_DIR, WOLFSSL_DIR, or WOLFSSL_SRC."
    );
}
