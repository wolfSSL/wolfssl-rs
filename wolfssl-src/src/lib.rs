//! Compile wolfSSL from source.
//!
//! This crate provides a [`Build`] API for compiling the wolfSSL C library
//! from source via the [`cc`] crate.  It is used by `wolfcrypt-sys` when
//! the `vendored` feature is enabled (similar to the `openssl-src` /
//! `openssl-sys` pattern).
//!
//! # Usage
//!
//! ```rust,no_run
//! let artifacts = wolfssl_src::Build::new().build();
//! println!("lib dir: {}", artifacts.lib_dir.display());
//! println!("include dir: {}", artifacts.include_dir.display());
//! ```
//!
//! The builder discovers wolfSSL sources in order: `source_dir()` override,
//! `WOLFSSL_SRC` env var, or `../../wolfssl` relative to the workspace.

use std::collections::HashSet;
use std::env;
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Result of a successful wolfSSL build.
pub struct Artifacts {
    /// Directory containing the compiled `libwolfssl.a`.
    pub lib_dir: PathBuf,
    /// wolfSSL source root — use as `-I` path for headers.
    pub include_dir: PathBuf,
    /// Directory containing `user_settings.h` — use as `-I` path.
    pub settings_include_dir: PathBuf,
    /// Parsed `#define` names from `user_settings.h`.
    pub defines: HashSet<String>,
}

/// Builder for compiling wolfSSL from source.
pub struct Build {
    /// Path to the wolfSSL source tree.
    source_dir: Option<PathBuf>,
    /// Enable FIPS build.
    fips: bool,
}

impl Build {
    pub fn new() -> Self {
        Build {
            source_dir: None,
            fips: false,
        }
    }

    /// Set the path to the wolfSSL source tree.
    /// If not set, defaults to `WOLFSSL_SRC` env var or `../../wolfssl`.
    pub fn source_dir(&mut self, dir: PathBuf) -> &mut Self {
        self.source_dir = Some(dir);
        self
    }

    /// Enable FIPS 140-3 build.
    pub fn fips(&mut self, enable: bool) -> &mut Self {
        self.fips = enable;
        self
    }

    /// Compile wolfSSL and return artifact paths.
    pub fn build(&self) -> Artifacts {
        let wolfssl_dir = self.resolve_source_dir();
        let settings_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // Parse user_settings.h for conditional source selection
        let user_settings_path = settings_dir.join("user_settings.h");
        let mut defines = parse_defines(&user_settings_path);
        if self.fips {
            let fips_path = settings_dir.join("user_settings_fips.h");
            if !fips_path.exists() {
                panic!(
                    "FIPS build requested but {} does not exist. \
                     Create it with the required FIPS #defines.",
                    fips_path.display()
                );
            }
            defines.extend(parse_defines(&fips_path));
        }

        // Collect source files
        let wolfcrypt_src = wolfssl_dir.join("wolfcrypt").join("src");
        let ssl_src = wolfssl_dir.join("src");

        let mut wolfcrypt_sources: Vec<&str> = CORE_WOLFCRYPT_SOURCES.to_vec();
        if self.fips {
            wolfcrypt_sources.extend_from_slice(FIPS_WOLFCRYPT_SOURCES);
        }
        append_conditional_wolfcrypt_sources(&defines, &mut wolfcrypt_sources);
        let ssl_srcs = ssl_sources(&defines);

        // Compile
        let mut build = cc::Build::new();
        build.include(&wolfssl_dir);
        build.include(&settings_dir);
        build.define("WOLFSSL_USER_SETTINGS", None);
        if self.fips {
            build.define("HAVE_FIPS", None);
        }

        for src in &wolfcrypt_sources {
            let path = wolfcrypt_src.join(src);
            if !path.exists() {
                panic!("required wolfcrypt source not found: {}", path.display());
            }
            build.file(&path);
            println!("cargo:rerun-if-changed={}", path.display());
        }
        for src in ssl_srcs {
            let path = ssl_src.join(src);
            if !path.exists() {
                panic!("required wolfssl source not found: {}", path.display());
            }
            build.file(&path);
            println!("cargo:rerun-if-changed={}", path.display());
        }

        build.warnings(false);
        build.opt_level(2);
        build.compile("wolfssl");

        println!("cargo:rerun-if-changed={}", user_settings_path.display());
        if self.fips {
            println!("cargo:rerun-if-changed={}", settings_dir.join("user_settings_fips.h").display());
        }

        Artifacts {
            lib_dir: PathBuf::from(env::var("OUT_DIR").unwrap()),
            include_dir: wolfssl_dir,
            settings_include_dir: settings_dir,
            defines,
        }
    }

    fn resolve_source_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.source_dir {
            if !dir.exists() {
                panic!("wolfssl source dir does not exist: {}", dir.display());
            }
            return dir.clone();
        }

        if let Ok(dir) = env::var("WOLFSSL_SRC") {
            let path = PathBuf::from(&dir);
            if !path.exists() {
                panic!("WOLFSSL_SRC={dir} does not exist");
            }
            return path;
        }

        // Look for wolfssl adjacent to the workspace root.
        // CARGO_MANIFEST_DIR is wolfssl-src/; one level up is the workspace root.
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let candidate = workspace_root.join("..").join("wolfssl");
        if candidate.exists() {
            return candidate;
        }

        panic!(
            "wolfSSL source not found. Set WOLFSSL_SRC to the path of your wolfssl checkout, \
             or clone it adjacent to this workspace:\n  \
             git clone https://github.com/wolfSSL/wolfssl.git"
        );
    }
}

impl Default for Build {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================
// Settings parser
// ================================================================

/// Parse a C header and return all `#define`d macro names.
///
/// Flat scan — does not evaluate `#if`/`#ifdef` guards.
pub fn parse_defines(path: &Path) -> HashSet<String> {
    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let reader = std::io::BufReader::new(file);
    let mut defines = HashSet::new();
    for line in reader.lines() {
        let line = line.expect("read error");
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let name = rest
            .trim_start()
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        if !name.is_empty() {
            defines.insert(name.to_string());
        }
    }
    defines
}

// ================================================================
// Source file lists
// ================================================================

const CORE_WOLFCRYPT_SOURCES: &[&str] = &[
    "aes.c",
    "arc4.c",
    "asn.c",
    "blake2b.c",
    "blake2s.c",
    "camellia.c",
    "cmac.c",
    "coding.c",
    "cpuid.c",
    "cryptocb.c",
    "dsa.c",
    "error.c",
    "hash.c",
    "logging.c",
    "md4.c",
    "md5.c",
    "memory.c",
    "pkcs7.c",
    "pkcs12.c",
    "random.c",
    "sha.c",
    "sha256.c",
    "signature.c",
    "sp_int.c",
    "sp_c32.c",
    "sp_c64.c",
    "srp.c",
    "wc_encrypt.c",
    "wc_port.c",
    "wolfmath.c",
];

const FIPS_WOLFCRYPT_SOURCES: &[&str] = &[
    "fips.c",
    "fips_test.c",
    "wolfcrypt_first.c",
    "wolfcrypt_last.c",
];

fn append_conditional_wolfcrypt_sources(defines: &HashSet<String>, sources: &mut Vec<&'static str>) {
    if defines.contains("HAVE_CHACHA") {
        sources.push("chacha.c");
    }
    if defines.contains("HAVE_CHACHA") && defines.contains("HAVE_POLY1305") {
        sources.push("chacha20_poly1305.c");
    }
    if defines.contains("HAVE_POLY1305") {
        sources.push("poly1305.c");
    }
    if defines.contains("HAVE_ECC") {
        sources.push("ecc.c");
    }
    if defines.contains("HAVE_ED25519") || defines.contains("HAVE_CURVE25519") {
        sources.push("curve25519.c");
        sources.push("fe_operations.c");
        sources.push("ge_operations.c");
    }
    if defines.contains("HAVE_ED25519") {
        sources.push("ed25519.c");
    }
    if defines.contains("HAVE_ED448") || defines.contains("HAVE_CURVE448") {
        sources.push("curve448.c");
        sources.push("fe_448.c");
        sources.push("ge_448.c");
    }
    if defines.contains("HAVE_ED448") {
        sources.push("ed448.c");
    }
    if !defines.contains("NO_DH") {
        sources.push("dh.c");
    }
    if !defines.contains("NO_RSA") {
        sources.push("rsa.c");
    }
    if !defines.contains("NO_HMAC") {
        sources.push("hmac.c");
    }
    if !defines.contains("NO_DES3") {
        sources.push("des3.c");
    }
    if defines.contains("WOLFSSL_SHA3") {
        sources.push("sha3.c");
    }
    if defines.contains("WOLFSSL_SHA512") || defines.contains("WOLFSSL_SHA384") {
        sources.push("sha512.c");
    }
    if defines.contains("HAVE_DILITHIUM") {
        sources.push("dilithium.c");
    }
    if defines.contains("WOLFSSL_HAVE_MLKEM") {
        sources.push("wc_mlkem.c");
        sources.push("wc_mlkem_poly.c");
    }
    if defines.contains("HAVE_HKDF") {
        sources.push("kdf.c");
    }
    if defines.contains("HAVE_PBKDF2") {
        sources.push("pwdbased.c");
    }
    if defines.contains("OPENSSL_EXTRA") || defines.contains("OPENSSL_ALL") {
        sources.push("evp.c");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_defines_basic() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "#define HAVE_ECC").unwrap();
        writeln!(f, "#define HAVE_AES").unwrap();
        writeln!(f, "#define WOLFSSL_SHA256").unwrap();
        writeln!(f, "// not a define").unwrap();
        writeln!(f, "int x = 5;").unwrap();
        let defs = parse_defines(f.path());
        assert!(defs.contains("HAVE_ECC"), "missing HAVE_ECC: {:?}", defs);
        assert!(defs.contains("HAVE_AES"), "missing HAVE_AES: {:?}", defs);
        assert!(defs.contains("WOLFSSL_SHA256"), "missing WOLFSSL_SHA256: {:?}", defs);
        assert_eq!(defs.len(), 3, "unexpected defines: {:?}", defs);
    }

    #[test]
    fn parse_defines_with_values() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "#define WOLFSSL_MAX_STRENGTH 1").unwrap();
        writeln!(f, "#define HAVE_FIPS_VERSION 5").unwrap();
        let defs = parse_defines(f.path());
        assert!(defs.contains("WOLFSSL_MAX_STRENGTH"));
        assert!(defs.contains("HAVE_FIPS_VERSION"));
    }

    #[test]
    fn parse_defines_ignores_non_defines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "#include <stdio.h>").unwrap();
        writeln!(f, "#ifdef HAVE_ECC").unwrap();
        writeln!(f, "#endif").unwrap();
        writeln!(f, "void foo(void);").unwrap();
        let defs = parse_defines(f.path());
        assert!(defs.is_empty(), "should have no defines: {:?}", defs);
    }

    #[test]
    fn parse_defines_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let defs = parse_defines(f.path());
        assert!(defs.is_empty());
    }
}

fn ssl_sources(defines: &HashSet<String>) -> &'static [&'static str] {
    if defines.contains("OPENSSL_EXTRA") || defines.contains("OPENSSL_ALL") {
        &[
            "pk.c",
            "pk_ec.c",
            "pk_rsa.c",
            "ssl.c",
            "ssl_api_pk.c",
            "ssl_asn1.c",
            "ssl_bn.c",
            "ssl_crypto.c",
            "ssl_load.c",
            "ssl_misc.c",
            "ssl_sk.c",
        ]
    } else {
        &[]
    }
}
