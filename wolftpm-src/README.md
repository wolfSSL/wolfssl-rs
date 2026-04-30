# wolftpm-src

Build-script crate that compiles [wolfTPM](https://github.com/wolfSSL/wolfTPM)
from C source for use by `wolftpm-sys`.

## wolfTPM source

`wolftpm-src` requires the wolfTPM C source tree.  Two ways to supply it:

### Option 1: Environment variable (recommended for development)

```sh
export WOLFTPM_SRC=/path/to/wolfTPM
cargo build -p wolftpm-sys
```

### Option 2: Bundled submodule (for building without a local clone)

```sh
git submodule update --init wolftpm-src/wolftpm
cargo build -p wolftpm-sys
```

## wolfSSL dependency

wolfTPM requires wolfSSL headers at compile time.  Supply them via any of:

| Variable | Description |
|---|---|
| `WOLFSSL_DIR` | Install prefix (headers at `$WOLFSSL_DIR/include`) |
| `WOLFSSL_INCLUDE_DIR` | Direct path to the wolfSSL include directory |
| `WOLFSSL_SRC` | wolfSSL source tree (vendored build) |

## Features

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport (swtpm / IBM TPM2 simulator) |

If neither feature is enabled, wolfTPM autodetects the available transport at
runtime on Linux.

## License

`wolftpm-src` is licensed under GPL-2.0-only or a commercial wolfSSL license.
wolfTPM itself is also GPL-2.0-only or commercial.
