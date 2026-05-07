# wolfcrypt-rs

Typed FFI layer on top of `wolfcrypt-sys`. Provides opaque types, size
constants, and the `WOLFSSL_VERSION` string parsed from the linked library
at build time.

This crate is the glue between the raw bindgen output and the higher-level
wolfssl-rs crates. Most users should depend on
[`wolfcrypt`](../wolfcrypt) or [`wolfcrypt-ring-compat`](../wolfcrypt-ring-compat)
instead.

## Why

`wolfcrypt-rs` sits between the raw bindgen output and the safe high-level
crates. It exists as a separate crate because:

- It re-exports the wolfSSL build metadata (`DEP_WOLFSSL_*`) via the `links`
  key so downstream crates receive include paths, cfg flags, and library
  locations without discovering them again.
- It compiles a small C shim (`compat_shim.c`) that stack-allocates wolfCrypt
  structs whose layouts are opaque to Rust (e.g. `Aes`, `WC_RNG`,
  `wc_ed25519_key`, `dilithium_key`) and verifies their sizes with
  `_Static_assert` at build time.
- It emits the `WOLFSSL_VERSION` constant at compile time so downstream
  crates can identify the linked C library without a runtime call.

## Usage

```toml
[dependencies]
wolfcrypt-rs = { version = "0.1", features = ["vendored"] }
```

Minimal example — print the linked wolfSSL version and generate 32 random
bytes via wolfCrypt's RNG:

```rust
use wolfcrypt_rs::{WC_RNG, wc_InitRng, wc_RNG_GenerateBlock, wc_FreeRng};

println!("linked wolfSSL {}", wolfcrypt_rs::WOLFSSL_VERSION);

let mut rng = WC_RNG::zeroed();
let mut buf = [0u8; 32];

// SAFETY: `rng` is zero-initialised storage with the verified size of
// wolfCrypt's WC_RNG struct; `wc_InitRng` initialises it in place. The
// matching `wc_FreeRng` is required to release wolfCrypt-managed
// resources before `rng` goes out of scope.
unsafe {
    assert_eq!(wc_InitRng(&mut rng), 0);
    assert_eq!(
        wc_RNG_GenerateBlock(&mut rng, buf.as_mut_ptr(), buf.len() as u32),
        0,
    );
    assert_eq!(wc_FreeRng(&mut rng), 0);
}
```

`WOLFSSL_VERSION` is set at compile time from `LIBWOLFSSL_VERSION_STRING` in
`wolfssl/version.h`. It returns `"unknown"` if the header was not found
during the build.

## How it works

```text
wolfcrypt-sys   Raw bindgen output; emits DEP_WOLFCRYPT_SYS_* metadata
      │
wolfcrypt-rs    Compiles compat_shim.c; re-exports metadata as DEP_WOLFSSL_*
                (links = "wolfssl")
      │
wolfcrypt              Safe RustCrypto trait impls
wolfcrypt-ring-compat  ring-compatible API
```

The `links = "wolfssl"` key means Cargo propagates `DEP_WOLFSSL_*`
environment variables (include dirs, cfg flags, library paths) to any crate
that has `wolfcrypt-rs` in its dependency graph, including build scripts.

| Feature | Description |
|---------|-------------|
| `fips` | Enable the wolfSSL FIPS 140-3 code path (commercial license required) |
| `riscv-bare-metal` | Bare-metal RISC-V configuration (Caliptra) |
| `cryptocb-only` | Build wolfSSL with only the CryptoCb callback routing layer |
| `cryptocb-pure` | Minimal CryptoCb-only build (no SSL/EVP/HKDF/ASN-template) |

Need FIPS 140-3 validation in your Rust application? wolfCrypt is FIPS 140-3
validated. [Contact wolfSSL](https://www.wolfssl.com/license/) for a
commercial FIPS license and the validated source tree.

## References

- [wolfcrypt](../wolfcrypt) — RustCrypto trait implementations (preferred
  high-level API)
- [wolfcrypt-ring-compat](../wolfcrypt-ring-compat) — `ring` API parity
  alternative
- [wolfcrypt-sys](../wolfcrypt-sys) — raw bindgen output this crate is
  layered on
- [wolfssl-src](../wolfssl-src) — vendored wolfSSL C source build
- [wolfSSL repository](https://github.com/wolfSSL/wolfssl)
- [wolfSSL / wolfCrypt documentation](https://www.wolfssl.com/documentation/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
