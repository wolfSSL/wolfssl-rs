# wolfssl-src

Build-script crate that compiles [wolfSSL](https://github.com/wolfSSL/wolfssl)
from C source as part of a Cargo build.  Used by `wolfcrypt-sys` when the
`vendored` feature is enabled.

## What

`wolfssl-src` is a build-infrastructure crate.  It has no public Rust API.
Its only job is to compile the wolfSSL/wolfCrypt C library and make the
resulting static archive and headers available to `wolfcrypt-sys`.

## Why

The three-crate split (`wolfssl-src` → `wolfcrypt-sys` → `wolfcrypt-rs`)
separates concerns cleanly:

- `wolfssl-src` owns the C build; it can be versioned independently of the FFI
  or the safe Rust API.
- `wolfcrypt-sys` owns the FFI boundary and bindgen invocation.
- `wolfcrypt-rs` owns the safe Rust wrapper and re-exports build metadata.

Having the C build in its own crate means that multiple crates in the same
workspace (e.g. `wolfcrypt-sys` and `wolftpm-sys`) can share the compiled
wolfSSL without recompiling it.

## How it works

`build.rs` selects one of several pre-configured `user_settings.h` files based
on Cargo features, then uses the `cc` crate to compile the wolfSSL source tree
against that settings file.  The compiled static library and include directory
are exposed via Cargo metadata so `wolfcrypt-sys` can link against them.

Feature-to-config mapping:

| Feature | user_settings.h used | Purpose |
|---|---|---|
| *(default)* | full-featured | OpenSSL compat, all algorithms, `WOLF_CRYPTO_CB` |
| `cryptocb-only` | crypto-callback only | All calls dispatched to CryptoCb callbacks |
| `cryptocb-pure` | minimal | CryptoCb + type defs only; no software math |
| `riscv-bare-metal` | bare-metal | No stdio/pthread; for RISC-V firmware |

## How to use

This crate is not intended to be used directly.  Enable it through
`wolfcrypt-sys`:

```toml
wolfcrypt-sys = { version = "0.1", features = ["vendored"] }
```

To use `wolfssl-src` directly (e.g. to link wolfSSL into your own build),
declare it as a `[dependency]` (not `[build-dependency]`) so Cargo propagates
its metadata to your build script.

## Configuration

| Environment variable | Description |
|---------------------|-------------|
| `WOLFSSL_SRC` | Path to a wolfSSL source tree.  Required when `vendored` is enabled. |

The `riscv-bare-metal` feature selects a minimal configuration for
`riscv32imc-unknown-none-elf` targets (Caliptra firmware).

## Features

| Feature | Description |
|---|---|
| `cryptocb-only` | CryptoCb dispatch only — all crypto routed to callbacks |
| `cryptocb-pure` | Absolute minimum — CryptoCb + type defs, no SP math |
| `riscv-bare-metal` | Bare-metal RISC-V platform stubs (Caliptra) |

## FIPS 140-3

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated.  FIPS builds require the specific wolfSSL source tree submitted for
validation (not an arbitrary checkout) and a commercial license.
[Contact wolfSSL](https://www.wolfssl.com/license/) for a commercial FIPS
license and the validated source tree.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
