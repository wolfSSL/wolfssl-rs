# wolfhsm-src

Builds [wolfHSM](https://github.com/wolfSSL/wolfHSM) from source as part of a Cargo build. Used by `wolfhsm-sys`.

## Usage

This crate is not intended to be used directly. Depend on `wolfhsm-sys` or `wolfhsm` instead.

## Configuration

| Environment variable | Description |
|---------------------|-------------|
| `WOLFHSM_SRC` | Path to the wolfHSM source tree. Required. |
| `WOLFSSL_DIR` | wolfSSL install prefix (headers at `$WOLFSSL_DIR/include`). |
| `WOLFSSL_INCLUDE_DIR` | Path to wolfSSL headers directly. |
| `WOLFSSL_SRC` | Path to wolfSSL source tree (alternative to install prefix). |
| `WOLFSSL_SETTINGS_INCLUDE` | Directory containing `user_settings.h`. |

If `WOLFHSM_SRC` is not set, the build script falls back to `~/GIT/wolfHSM`.

## Features

| Feature | Description |
|---------|-------------|
| `she` | Enable SHE (Secure Hardware Extension) automotive key management. Requires `WOLFSSL_AES_DIRECT` and `HAVE_AES_ECB` in the linked wolfSSL. |

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`
