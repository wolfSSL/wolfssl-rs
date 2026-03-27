# wolfcrypt-rs

Typed FFI layer on top of `wolfcrypt-sys`. Provides opaque types, size constants, and the `WOLFSSL_VERSION` string parsed from the linked library at build time.

This crate is the glue between the raw bindgen output and the higher-level wolfssl-rs crates. Most users should depend on `wolfcrypt` or `wolfcrypt-ring-compat` instead.

## Usage

```toml
wolfcrypt-rs = { version = "0.1", features = ["vendored"] }
```

## Features

| Feature | Description |
|---------|-------------|
| `fips` | Enable the FIPS 140-3 code path |
| `riscv-bare-metal` | Bare-metal RISC-V configuration (Caliptra) |

## WOLFSSL_VERSION

```rust
println!("linked wolfSSL {}", wolfcrypt_rs::WOLFSSL_VERSION);
```

Set at compile time from `wolfssl/version.h`. Returns `"unknown"` if the header was not found.

## License

MIT
