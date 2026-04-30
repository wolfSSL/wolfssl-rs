# wolftpm

Safe Rust bindings to [wolfTPM](https://github.com/wolfSSL/wolfTPM), a portable
TPM 2.0 library from wolfSSL.

> **Status**: build infrastructure stub — the high-level Rust API has not yet
> been implemented.  The `wolftpm-src` and `wolftpm-sys` crates compile wolfTPM
> from source and generate raw FFI bindings; this crate will wrap them safely.

## Crate stack

| Crate | Role |
|---|---|
| `wolftpm-src` | Compiles wolfTPM C source via the `cc` crate |
| `wolftpm-sys` | bindgen-generated raw FFI bindings |
| `wolftpm` | Safe high-level Rust API (this crate) |

## Build requirements

- wolfTPM source (via `WOLFTPM_SRC` env var or bundled submodule)
- wolfSSL headers (via `WOLFSSL_DIR` or `WOLFSSL_INCLUDE_DIR`)

See [`wolftpm-src/README.md`](../wolftpm-src/README.md) for details.

## Features

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport (swtpm / IBM TPM2 simulator) |

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial
