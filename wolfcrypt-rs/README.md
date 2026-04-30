# wolfcrypt-rs

Typed FFI layer on top of `wolfcrypt-sys`.  Provides opaque types, size
constants, and the `WOLFSSL_VERSION` string parsed from the linked library
at build time.

This crate is the glue between the raw bindgen output and the higher-level
wolfssl-rs crates.  Most users should depend on `wolfcrypt` or
`wolfcrypt-ring-compat` instead.

## Why

`wolfcrypt-rs` sits between the raw bindgen output and the safe high-level
crates.  It exists as a separate crate because:

- It re-exports the wolfSSL build metadata (`DEP_WOLFSSL_*`) via the `links`
  key so downstream crates receive include paths, cfg flags, and library
  locations without discovering them again.
- It compiles a small C shim (`compat_shim.c`) that stack-allocates wolfCrypt
  structs for operations that cannot be performed from Rust FFI alone.
- It emits the `WOLFSSL_VERSION` constant at compile time.

## Usage

```toml
wolfcrypt-rs = { version = "0.1", features = ["vendored"] }
```

## How it works

```text
wolfcrypt-sys   Raw bindgen output; emits DEP_WOLFCRYPT_SYS_* metadata
      │
wolfcrypt-rs    Compiles compat_shim.c; re-exports metadata as DEP_WOLFSSL_*
                (links = "wolfssl")
      │
wolfcrypt       Safe RustCrypto trait impls
wolfcrypt-ring-compat  ring-compatible API
```

The `links = "wolfssl"` key means Cargo propagates `DEP_WOLFSSL_*` environment
variables (include dirs, cfg flags, library paths) to any crate that has
`wolfcrypt-rs` in its dependency graph, including build scripts.

## Features

| Feature | Description |
|---------|-------------|
| `fips` | Enable the FIPS 140-3 code path |
| `riscv-bare-metal` | Bare-metal RISC-V configuration (Caliptra) |

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated.  [Contact wolfSSL](https://www.wolfssl.com/license/) for a
commercial FIPS license and the validated source tree.

## WOLFSSL_VERSION

```rust
println!("linked wolfSSL {}", wolfcrypt_rs::WOLFSSL_VERSION);
```

Set at compile time from `wolfssl/version.h`.  Returns `"unknown"` if the
header was not found.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

MIT — see [LICENSE](LICENSE).

The [MIT License](https://opensource.org/licenses/MIT) applies to the Rust
source code in this crate.  The underlying wolfSSL/wolfCrypt C library is
licensed under GPL-2.0-or-later with a commercial option available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)
