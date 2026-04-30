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
    // feature set (including HAVE_DILITHIUM, WOLFSSL_WC_DILITHIUM, etc.) lives in
    // user_settings.h, not options.h.  Use WOLFSSL_USER_SETTINGS mode when the
    // install provides a user_settings.h so we get all defines consistently.
    let user_settings_h = PathBuf::from(&wolfssl_settings).join("user_settings.h");
    let use_user_settings = wolfssl_vendored || user_settings_h.exists();

    // ── 2. Read wolfHSM metadata from wolfhsm-src ────────────────────────────
    let wolfhsm_include = env::var("DEP_WOLFHSM_SRC_INCLUDE")
        .expect("DEP_WOLFHSM_SRC_INCLUDE not set; is wolfhsm-src a build-dependency?");
    let wolfhsm_lib = env::var("DEP_WOLFHSM_SRC_LIB")
        .expect("DEP_WOLFHSM_SRC_LIB not set");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // ── 3. Compile shims.c ────────────────────────────────────────────────────
    // Must come before wolfhsm/wolfssl link directives below. GNU ld resolves
    // static archives left-to-right; wolfhsm_shims calls into wolfhsm which
    // calls into wolfssl, so the link order must be shims → wolfhsm → wolfssl.
    // cc::Build::compile() emits cargo:rustc-link-lib and cargo:rustc-link-search
    // automatically — do NOT add a duplicate println! for wolfhsm_shims.
    let mut shims = cc::Build::new();
    shims
        .file(manifest_dir.join("src").join("shims.c"))
        // wolfhsm_lib is the OUT_DIR from wolfhsm-src; it holds wolfhsm_cfg.h
        .include(&wolfhsm_lib)
        .include(&wolfhsm_include)
        .include(format!("{wolfhsm_include}/port/posix"))
        .include(&wolfssl_include)
        .include(&wolfssl_settings)
        .define(
            if use_user_settings {
                "WOLFSSL_USER_SETTINGS"
            } else {
                "WOLFSSL_USE_OPTIONS_H"
            },
            None,
        )
        .define("WOLFHSM_CFG", None)
        .define("WOLF_CRYPTO_CB", None)
        .define("WOLFHSM_CFG_NO_WOLFCRYPT", Some("0"))
        .warnings(false)
        .opt_level(2);
    shims.compile("wolfhsm_shims");

    // ── 4. Link wolfhsm and wolfssl ───────────────────────────────────────────
    // These come after wolfhsm_shims in the linker command (callees after callers).
    println!("cargo:rustc-link-search=native={wolfhsm_lib}");
    println!("cargo:rustc-link-lib=static=wolfhsm");

    // wolfSSL link (handled by wolfcrypt-sys/wolfcrypt-rs, but we need it
    // explicitly here since wolfhsm-sys is a standalone sys crate).
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
        // For pre-built wolfSSL the lib name is from DEP_WOLFCRYPT_SYS_LIBCRYPTO.
        let libcrypto =
            env::var("DEP_WOLFCRYPT_SYS_LIBCRYPTO").unwrap_or_else(|_| "wolfssl".into());
        println!("cargo:rustc-link-lib={libcrypto}");
    }

    // ── 5. Run bindgen ────────────────────────────────────────────────────────
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // posix_transport_uds.{c,h} was added to wolfHSM after v1.4.0.  When using
    // the bundled submodule (which may be pinned to an older commit), provide a
    // stub header so wrapper.h can include it without error.  The stub is empty;
    // bindgen will simply find no UDS symbols, which is correct for that version.
    let uds_h = PathBuf::from(&wolfhsm_include)
        .join("port")
        .join("posix")
        .join("posix_transport_uds.h");
    if !uds_h.exists() {
        let stub_dir = out_dir.join("port").join("posix");
        std::fs::create_dir_all(&stub_dir).expect("create stub dir");
        std::fs::write(
            stub_dir.join("posix_transport_uds.h"),
            b"/* stub: posix_transport_uds not available in this wolfHSM version */\n",
        )
        .expect("write stub header");
    }
    let bindings = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_str().unwrap())
        // OUT_DIR first: stub headers (posix_transport_uds.h) live here when
        // the wolfHSM source doesn't provide them.
        .clang_arg(format!("-I{}", out_dir.display()))
        // wolfHSM include paths (wolfhsm_lib is the OUT_DIR that holds
        // the generated wolfhsm_cfg.h from wolfhsm-src)
        .clang_arg(format!("-I{wolfhsm_lib}"))
        .clang_arg(format!("-I{wolfhsm_include}"))
        .clang_arg(format!("-I{}/port/posix", wolfhsm_include))
        // wolfSSL include paths
        .clang_arg(format!("-I{wolfssl_include}"))
        .clang_arg(format!("-I{wolfssl_settings}"))
        // wolfSSL settings mode
        .clang_arg(if use_user_settings {
            "-DWOLFSSL_USER_SETTINGS"
        } else {
            "-DWOLFSSL_USE_OPTIONS_H"
        })
        // wolfHSM cfg macros
        .clang_arg("-DWOLFHSM_CFG")
        .clang_arg("-DWOLF_CRYPTO_CB")
        .clang_arg("-DWOLFHSM_CFG_NO_WOLFCRYPT=0")
        // Allowlist: capture only wolfHSM symbols, not wolfSSL internals
        .allowlist_type("wh.*")
        .allowlist_type("WH.*")
        .allowlist_type("posix_transport_.*")
        .allowlist_type("PosixTransport.*")
        .allowlist_type("posixTransport.*")
        .allowlist_type("ptt.*")
        .allowlist_type("ptu.*")
        .allowlist_type("ptshm.*")
        .allowlist_type("PTSHM.*")
        .allowlist_function("wh_Client_.*")
        .allowlist_function("wh_Comm_.*")
        .allowlist_function("posixTransportTcp_.*")
        .allowlist_function("posixTransportUds_.*")
        .allowlist_function("posixTransportShm_.*")
        .allowlist_item("WH_.*")
        .allowlist_item("WOLFHSM_.*")
        // Quality settings
        .use_core()
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate wolfhsm bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}
