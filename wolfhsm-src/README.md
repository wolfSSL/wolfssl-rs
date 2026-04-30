# wolfhsm-src

Build-script crate that compiles [wolfHSM](https://github.com/wolfSSL/wolfHSM)
from C source as part of a Cargo build.  Used internally by `wolfhsm-sys`.

## What

`wolfhsm-src` is a build-infrastructure crate.  It has no public Rust API.
Its only job is to compile the wolfHSM C client library into a static archive
(`libwolfhsm.a`) and expose the paths to the compiled library and its headers
via Cargo's `links` metadata mechanism, so that `wolfhsm-sys` can link against
it and run `bindgen` over the headers.

## Why

Cargo cannot compile C libraries on behalf of an arbitrary crate — each crate
that links a C library needs a `build.rs` that drives the C compiler.  The
three-crate split (`wolfhsm-src` → `wolfhsm-sys` → `wolfhsm`) mirrors the
pattern used throughout this workspace (`wolfssl-src`, `wolftpm-src`) and
separates concerns cleanly:

- `wolfhsm-src` owns the C build; it can be versioned and replaced without
  touching the FFI or the safe Rust API.
- `wolfhsm-sys` owns the FFI boundary; bindgen is run here.
- `wolfhsm` owns the safe Rust API.

## How it works

`build.rs` performs five steps:

1. **Locate wolfHSM source** — checks `WOLFHSM_SRC` first, then falls back to
   the bundled git submodule at `wolfhsm-src/wolfhsm/`.
2. **Locate wolfSSL headers** — checks `WOLFSSL_INCLUDE_DIR`, `WOLFSSL_DIR`,
   then `WOLFSSL_SRC` in that priority order (same as the rest of the
   workspace).
3. **Generate `wolfhsm_cfg.h`** in `OUT_DIR` — wolfHSM's `wh_settings.h`
   unconditionally `#include`s `wolfhsm_cfg.h`.  This generated file enables
   the POSIX time hook (`WOLFHSM_CFG_PORT_GETTIME`), client-side functionality
   (`WOLFHSM_CFG_ENABLE_CLIENT`), and CryptoCb support (`WOLF_CRYPTO_CB`).
   When the `she` Cargo feature is enabled it also defines
   `WOLFHSM_CFG_SHE_EXTENSION`.
4. **Compile wolfHSM** — uses the `cc` crate to compile the client-side source
   files (`wh_client.c`, `wh_client_crypto.c`, `wh_comm.c`, message layer
   files, and more) together with the POSIX transport implementations
   (`posix_transport_tcp.c`, `posix_transport_shm.c`, `posix_transport_uds.c`,
   etc.) when present.
5. **Emit Cargo metadata** — `DEP_WOLFHSM_SRC_INCLUDE` (wolfHSM source root)
   and `DEP_WOLFHSM_SRC_LIB` (directory holding `libwolfhsm.a` and
   `wolfhsm_cfg.h`) for consumption by `wolfhsm-sys`.

## How to use

This crate is not intended to be used directly.  Add `wolfhsm-sys` or `wolfhsm`
to your `Cargo.toml` instead.

If you need to use `wolfhsm-src` directly (e.g. to build a different FFI crate
against the same wolfHSM build), declare it as a regular `[dependency]` rather
than a `[build-dependency]` so that Cargo propagates the `DEP_WOLFHSM_SRC_*`
metadata to your build script.

## wolfHSM source

`wolfhsm-src` needs the wolfHSM C source tree.  Two ways to supply it:

### Option 1: Environment variable (recommended for development)

```sh
export WOLFHSM_SRC=/path/to/wolfHSM
cargo build -p wolfhsm-sys
```

### Option 2: Bundled submodule

```sh
git submodule update --init wolfhsm-src/wolfhsm
cargo build -p wolfhsm-sys
```

The submodule tracks the upstream `wolfSSL/wolfHSM` `main` branch.

## wolfSSL dependency

wolfHSM uses wolfSSL/wolfCrypt for all cryptographic operations.  Supply the
wolfSSL headers via any of:

| Variable | Description |
|---|---|
| `WOLFSSL_DIR` | Install prefix — headers at `$WOLFSSL_DIR/include` |
| `WOLFSSL_INCLUDE_DIR` | Direct path to the wolfSSL include directory |
| `WOLFSSL_SRC` | wolfSSL source tree root (vendored build) |

The pre-built wolfSSL must have been compiled with `WOLF_CRYPTO_CB` enabled.

## Features

| Feature | Description |
|---|---|
| `she` | Enable SHE (Secure Hardware Extension) automotive key management — defines `WOLFHSM_CFG_SHE_EXTENSION` in the generated `wolfhsm_cfg.h`.  Requires `WOLFSSL_AES_DIRECT` and `HAVE_AES_ECB` in the linked wolfSSL. |

## References

- [wolfHSM repository](https://github.com/wolfSSL/wolfHSM)
- [wolfHSM documentation](https://www.wolfssl.com/documentation/manuals/wolfhsm/)
- [wolfssl-rs workspace](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfHSM is copyright wolfSSL Inc. and its contributors.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`

This crate (the Rust build-script wrapper) is available under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
For proprietary or commercial use, a commercial license is available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)

wolfHSM itself is also licensed under GPL-2.0-or-later or a commercial
wolfSSL license.
