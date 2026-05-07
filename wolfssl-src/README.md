# wolfssl-src

Build-script crate that compiles
[wolfSSL](https://github.com/wolfSSL/wolfssl) from C source as part of a
Cargo build. Used by [`wolfcrypt-sys`](../wolfcrypt-sys) when its
`vendored` feature is enabled, modelled on the
[`openssl-src`](https://crates.io/crates/openssl-src) /
[`openssl-sys`](https://crates.io/crates/openssl-sys) pattern.

## Why

The three-crate split (`wolfssl-src` → `wolfcrypt-sys` →
`wolfcrypt-rs`) separates concerns so each layer can change
independently:

- `wolfssl-src` owns the C build; it can be versioned independently of
  the FFI or the safe Rust API.
- [`wolfcrypt-sys`](../wolfcrypt-sys) owns the FFI boundary and bindgen
  invocation.
- [`wolfcrypt-rs`](../wolfcrypt-rs) owns the safe Rust wrapper and
  re-exports build metadata.

Having the C build in its own crate means multiple crates in the same
workspace (`wolfcrypt-sys`, `wolftpm-sys`, `wolfhsm-sys`) can share the
compiled wolfSSL without recompiling it.

## Usage

This crate is normally consumed transitively through `wolfcrypt-sys`:

```toml
[dependencies]
wolfcrypt-sys = { version = "0.1", features = ["vendored"] }
```

For direct use in your own build pipeline:

```toml
[dependencies]
wolfssl-src = "0.1"
```

```rust,no_run
// Build wolfSSL from source and report where the artefacts landed.
let artifacts = wolfssl_src::Build::new()
    .fips(false)              // pass true for FIPS 140-3 builds (commercial)
    .build();

println!("lib dir:      {}", artifacts.lib_dir.display());
println!("include dir:  {}", artifacts.include_dir.display());
println!("settings dir: {}", artifacts.settings_include_dir.display());
```

`Artifacts` exposes the static-archive directory, the wolfSSL header
include path, the directory containing the active `user_settings.h`,
and the parsed set of `#define` names from that settings file.

When using `wolfssl-src` from another crate's `build.rs`, declare it as
a regular `[dependency]` (not a `[build-dependency]`) so Cargo
propagates the `DEP_WOLFSSL_SRC_*` metadata to your build script.

### Source resolution

`Build::build()` discovers the wolfSSL source tree in this priority
order:

1. `Build::source_dir(...)` — explicit programmatic override.
2. `WOLFSSL_SRC` environment variable.
3. Bundled submodule at `wolfssl-src/wolfssl/` (after
   `git submodule update --init`).
4. `pkg-config` — looks for a `wolfssl` package whose prefix contains
   source files.

### FIPS 140-3

wolfCrypt is FIPS 140-3 validated. FIPS builds require:

- The specific wolfSSL source tree submitted for validation (not an
  arbitrary checkout) — supplied by wolfSSL Inc. under commercial
  license.
- A `user_settings_fips.h` configuration header in this crate's
  manifest directory.

Set `Build::fips(true)` to enable the FIPS code path.
[Contact wolfSSL](https://www.wolfssl.com/license/) for a commercial
FIPS license and the validated source tree.

## How it works

`build.rs` selects one of several pre-configured `user_settings.h`
files based on Cargo features, then uses the [`cc`](https://crates.io/crates/cc)
crate to compile the wolfSSL source tree against that settings file.
Feature precedence is `cryptocb-pure` > `cryptocb-only` >
`riscv-bare-metal` > default (verified in `src/lib.rs`).

| Feature | `user_settings.h` used | Purpose |
|---|---|---|
| *(default)* | `user_settings.h` | OpenSSL compat, all algorithms, `WOLF_CRYPTO_CB` |
| `cryptocb-only` | `user_settings_cryptocb_only.h` | All crypto routed to CryptoCb callbacks; SP math excluded |
| `cryptocb-pure` | `user_settings_cryptocb_pure.h` | Minimum: CryptoCb routing + type defs only; no OpenSSL EVP, no HKDF, no ASN template |
| `riscv-bare-metal` | `user_settings_riscv.h` | No stdio/pthread; for `riscv32imc-unknown-none-elf` (Caliptra firmware) |

The compiled static library and include directory are exposed via
Cargo metadata (`DEP_WOLFSSL_SRC_*`) so that downstream sys crates can
link against them without re-running the C build.

## References

- [wolfcrypt-sys](../wolfcrypt-sys) — primary consumer; the FFI binding
  layer
- [wolfcrypt-rs](../wolfcrypt-rs) — typed Rust wrapper above
  `wolfcrypt-sys`
- [wolfhsm-src](../wolfhsm-src) — sibling source-build crate for wolfHSM
- [wolftpm-src](../wolftpm-src) — sibling source-build crate for wolfTPM
- [wolfSSL repository](https://github.com/wolfSSL/wolfssl)
- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [`cc` crate](https://crates.io/crates/cc) — C build dependency
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
