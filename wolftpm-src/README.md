# wolftpm-src

Build-script crate that compiles [wolfTPM](https://github.com/wolfSSL/wolfTPM)
from C source as part of a Cargo build.  Used internally by `wolftpm-sys`.

## What

`wolftpm-src` is a build-infrastructure crate.  It has no public Rust API.
Its only job is to compile the wolfTPM C library into a static archive
(`libwolftpm.a`) and expose the paths to the compiled library and its headers
via Cargo's `links` metadata mechanism, so that `wolftpm-sys` can link against
it and run `bindgen` over the headers.

## Why

Cargo cannot compile C libraries on behalf of an arbitrary crate — each crate
that links a C library needs a `build.rs` that drives the C compiler.  The
three-crate split (`wolftpm-src` → `wolftpm-sys` → `wolftpm`) mirrors the
pattern used throughout this workspace (`wolfssl-src`, `wolfhsm-src`) and
separates concerns cleanly:

- `wolftpm-src` owns the C build; it can be versioned and replaced without
  touching the FFI or the safe Rust API.
- `wolftpm-sys` owns the FFI boundary; bindgen is run here.
- `wolftpm` owns the safe Rust API.

## How it works

`build.rs` performs four steps:

1. **Locate wolfTPM source** — checks `WOLFTPM_SRC` first, then falls back to
   the bundled git submodule at `wolftpm-src/wolftpm/`.
2. **Locate wolfSSL headers** — checks `WOLFSSL_INCLUDE_DIR`, `WOLFSSL_DIR`,
   then `WOLFSSL_SRC` in that priority order (same as the rest of the
   workspace).
3. **Generate `wolftpm/options.h`** in `OUT_DIR` — wolfTPM's headers
   unconditionally `#include <wolftpm/options.h>`.  This generated file
   selects the transport backend based on Cargo features and the target OS.
   On Linux with no feature selected it defaults to `WOLFTPM_LINUX_DEV`
   (the `/dev/tpm0` kernel driver) so that `hal/tpm_io.h` maps `TPM2_IoCb`
   to `NULL`, which is what the kernel driver path requires.
4. **Compile wolfTPM** — uses the `cc` crate to compile the core source files
   (`tpm2.c`, `tpm2_wrap.c`, `tpm2_packet.c`, `tpm2_param_enc.c`,
   `tpm2_util.c`, `tpm2_crypto.c`) and optional transport files
   (`tpm2_cryptocb.c`, `tpm2_linux.c`, `tpm2_swtpm.c`, `tpm2_tis.c`)
   when present.

The compiled library path and wolfTPM include directory are emitted as Cargo
metadata (`DEP_WOLFTPM_SRC_LIB`, `DEP_WOLFTPM_SRC_INCLUDE`) for consumption
by `wolftpm-sys`.

## How to use

This crate is not intended to be used directly.  Add `wolftpm-sys` or `wolftpm`
to your `Cargo.toml` instead.

If you need to use `wolftpm-src` directly (e.g. to build a different FFI crate
against the same wolfTPM build), declare it as a regular `[dependency]` rather
than a `[build-dependency]` so that Cargo propagates the `DEP_WOLFTPM_SRC_*`
metadata to your build script.

## wolfTPM source

`wolftpm-src` needs the wolfTPM C source tree.  Two ways to supply it:

### Option 1: Environment variable (recommended for development)

```sh
export WOLFTPM_SRC=/path/to/wolfTPM
cargo build -p wolftpm-sys
```

### Option 2: Bundled submodule

```sh
git submodule update --init wolftpm-src/wolftpm
cargo build -p wolftpm-sys
```

The submodule tracks the upstream `wolfSSL/wolfTPM` `main` branch.

## wolfSSL dependency

wolfTPM uses wolfSSL/wolfCrypt for RSA, ECC, and hash operations internally.
Supply the wolfSSL headers via any of:

| Variable | Description |
|---|---|
| `WOLFSSL_DIR` | Install prefix — headers at `$WOLFSSL_DIR/include` |
| `WOLFSSL_INCLUDE_DIR` | Direct path to the wolfSSL include directory |
| `WOLFSSL_SRC` | wolfSSL source tree root (vendored build) |

The pre-built wolfSSL must have been compiled with `WOLF_CRYPTO_CB` enabled.

## Features

| Feature | Description |
|---|---|
| `linux-dev` | Compile wolfTPM with Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Compile wolfTPM with software TPM socket transport (swtpm, IBM TPM2 simulator) |

If neither feature is selected, the build defaults to `WOLFTPM_LINUX_DEV` on
Linux.  Both features may be enabled simultaneously.

## References

- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [wolfTPM documentation](https://www.wolfssl.com/docs/wolftpm/)
- [wolfTPM manual](https://wolfssl.github.io/wolfTPM/)
- [wolfssl-rs workspace](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`

This crate (the Rust build-script wrapper) is available under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
For proprietary or commercial use, a commercial license is available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)

wolfTPM itself is also licensed under GPL-2.0-or-later or a commercial
wolfSSL license.
