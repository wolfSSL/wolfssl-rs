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
    cc::Build::new()
        .file(manifest_dir.join("src").join("shims.c"))
        // wolfhsm_lib is the OUT_DIR from wolfhsm-src; it holds wolfhsm_cfg.h
        .include(&wolfhsm_lib)
        .include(&wolfhsm_include)
        .include(format!("{wolfhsm_include}/port/posix"))
        .include(&wolfssl_include)
        .include(&wolfssl_settings)
        .define(
            if wolfssl_vendored {
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
        .opt_level(2)
        .compile("wolfhsm_shims");

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
    let bindings = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_str().unwrap())
        // wolfHSM include paths (wolfhsm_lib is the OUT_DIR that holds
        // the generated wolfhsm_cfg.h from wolfhsm-src)
        .clang_arg(format!("-I{wolfhsm_lib}"))
        .clang_arg(format!("-I{wolfhsm_include}"))
        .clang_arg(format!("-I{}/port/posix", wolfhsm_include))
        // wolfSSL include paths
        .clang_arg(format!("-I{wolfssl_include}"))
        .clang_arg(format!("-I{wolfssl_settings}"))
        // wolfSSL settings mode
        .clang_arg(if wolfssl_vendored {
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
        .allowlist_function("wh_Client_.*")
        .allowlist_function("wh_Comm_.*")
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
