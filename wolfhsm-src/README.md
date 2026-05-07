# wolfhsm-src

Build-script crate that compiles [wolfHSM](https://github.com/wolfSSL/wolfHSM)
from C source as part of a Cargo build. Used internally by
[`wolfhsm-sys`](../wolfhsm-sys); has no public Rust API.

## Why

Cargo cannot compile C libraries on behalf of an arbitrary crate — each
crate that links a C library needs a `build.rs` that drives the C
compiler. Splitting the C build into its own crate (the same pattern used
by [`wolfssl-src`](../wolfssl-src) and [`wolftpm-src`](../wolftpm-src) in
this workspace) keeps concerns separate:

- **`wolfhsm-src` owns the C build** — it can be versioned and replaced
  without touching the FFI or the safe Rust API.
- **`wolfhsm-sys` owns the FFI boundary** — bindgen runs there, consuming
  the `DEP_WOLFHSM_SRC_*` metadata emitted by this crate.
- **`wolfhsm` owns the safe Rust API**.
- **`links = "wolfhsm_src"`** prevents two copies of the wolfHSM static
  archive being linked into the same binary.

## Usage

This crate is normally pulled in transitively via
[`wolfhsm-sys`](../wolfhsm-sys) or [`wolfhsm`](../wolfhsm). Add one of
those instead of depending on `wolfhsm-src` directly.

If you need to build a different FFI crate against the same wolfHSM
build, declare `wolfhsm-src` as a regular `[dependency]` (not a
`[build-dependency]`) so Cargo propagates the `DEP_WOLFHSM_SRC_*`
metadata to your build script:

```toml
[dependencies]
wolfhsm-src = "0.1"
```

### Supplying the wolfHSM source

Two ways to provide the wolfHSM C source tree:

**Environment variable** (recommended for development):

```sh
export WOLFHSM_SRC=/path/to/wolfHSM
cargo build -p wolfhsm-sys
```

**Bundled submodule**:

```sh
git submodule update --init wolfhsm-src/wolfhsm
cargo build -p wolfhsm-sys
```

The submodule tracks the upstream `wolfSSL/wolfHSM` `main` branch.

### Supplying wolfSSL headers

wolfHSM uses wolfSSL/wolfCrypt for all cryptographic operations. Supply
the headers via any of:

| Variable | Description |
|---|---|
| `WOLFSSL_DIR` | Install prefix — headers at `$WOLFSSL_DIR/include` |
| `WOLFSSL_INCLUDE_DIR` | Direct path to the wolfSSL include directory |
| `WOLFSSL_SRC` | wolfSSL source tree root (vendored build) |

The pre-built wolfSSL must have been compiled with `WOLF_CRYPTO_CB`
enabled.

## How it works

`build.rs` performs five steps:

1. **Locate wolfHSM source** — checks `WOLFHSM_SRC` first, then falls
   back to the bundled git submodule at `wolfhsm-src/wolfhsm/`.
2. **Locate wolfSSL headers** — checks `WOLFSSL_INCLUDE_DIR`,
   `WOLFSSL_DIR`, then `WOLFSSL_SRC` in that priority order (same as the
   rest of the workspace).
3. **Generate `wolfhsm_cfg.h`** in `OUT_DIR` — wolfHSM's `wh_settings.h`
   unconditionally `#include`s `wolfhsm_cfg.h`. The generated file
   enables the POSIX time hook (`WOLFHSM_CFG_PORT_GETTIME`), client-side
   functionality (`WOLFHSM_CFG_ENABLE_CLIENT`), and CryptoCb support
   (`WOLF_CRYPTO_CB`). When the `she` Cargo feature is enabled it also
   defines `WOLFHSM_CFG_SHE_EXTENSION`.
4. **Compile wolfHSM** — uses the `cc` crate to compile the client-side
   sources (`wh_client.c`, `wh_client_crypto.c`, `wh_comm.c`, message
   layer files, and more) together with the POSIX transport
   implementations (`posix_transport_tcp.c`, `posix_transport_shm.c`,
   `posix_transport_uds.c`) when present.
5. **Emit Cargo metadata** — `DEP_WOLFHSM_SRC_INCLUDE` (wolfHSM source
   root) and `DEP_WOLFHSM_SRC_LIB` (directory holding `libwolfhsm.a` and
   `wolfhsm_cfg.h`) for consumption by `wolfhsm-sys`.

### Features

| Feature | Description |
|---|---|
| `she` | Enable SHE (Secure Hardware Extension) AutoSAR automotive key management — defines `WOLFHSM_CFG_SHE_EXTENSION` in the generated `wolfhsm_cfg.h`. Requires `WOLFSSL_AES_DIRECT` and `HAVE_AES_ECB` in the linked wolfSSL. |

## References

- [wolfhsm-sys](../wolfhsm-sys) — bindgen-generated FFI built on top of
  this crate
- [wolfhsm](../wolfhsm) — safe Rust API
- [wolfssl-src](../wolfssl-src) — sibling source-build crate for wolfSSL
- [wolftpm-src](../wolftpm-src) — sibling source-build crate for wolfTPM
- [wolfHSM repository](https://github.com/wolfSSL/wolfHSM)
- [wolfHSM documentation](https://www.wolfssl.com/documentation/manuals/wolfhsm/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfHSM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfHSM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
