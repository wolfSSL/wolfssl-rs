# wolfssl-src

Builds wolfSSL from source as part of a Cargo build. Used by `wolfcrypt-sys` when the `vendored` feature is enabled.

## Usage

This crate is not intended to be used directly. Add it as a dependency through `wolfcrypt-sys`:

```toml
wolfcrypt-sys = { version = "0.1", features = ["vendored"] }
```

## Configuration

| Environment variable | Description |
|---------------------|-------------|
| `WOLFSSL_SRC` | Path to a wolfSSL source tree. Required when using `vendored`. |

The `riscv-bare-metal` feature selects a minimal configuration for `riscv32imc-unknown-none-elf` targets (Caliptra firmware).

## License

MIT
