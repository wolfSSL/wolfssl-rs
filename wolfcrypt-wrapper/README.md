# wolfcrypt-wrapper

Idiomatic Rust wrapper for the wolfCrypt cryptographic algorithms portion
of the wolfSSL C library. Stays close to the C API and exposes a broad set
of primitives directly, without the RustCrypto trait layer.

For code written against RustCrypto traits (`digest::Digest`, `aead::Aead`,
`signature::Signer`, etc.) use the [`wolfcrypt`](../wolfcrypt) crate
instead.

## Why

- **FIPS 140-3** — wolfCrypt is FIPS 140-3 validated; this wrapper exposes
  the validated primitives directly. FIPS 140-3 validation requires a
  wolfSSL commercial FIPS license and the specific validated source tree;
  [contact wolfSSL](https://www.wolfssl.com/license/) for details.
- **Broad coverage** — AES (all modes), ECC, RSA, Ed25519, Ed448, Curve25519,
  the SHA family, HMAC, CMAC, HKDF, PBKDF2, ChaCha20-Poly1305, BLAKE2,
  Dilithium, ML-KEM, LMS, and more
- **Thin wrapper** — stays close to the C API; useful when you need an
  algorithm not yet covered by the higher-level [`wolfcrypt`](../wolfcrypt)
  crate, or when porting C code that already uses wolfCrypt
- **`#![no_std]`** — does not require the standard library

## Usage

The `wolfssl` C library must be available before building this crate; the
[`wolfcrypt-sys`](../wolfcrypt-sys) build script handles vendored builds
through [`wolfssl-src`](../wolfssl-src).

```toml
[dependencies]
wolfcrypt-wrapper = "1.1"
```

Minimal example — initialise wolfCrypt, hash a message with the streaming
SHA-256 API, then clean up:

```rust
use wolfcrypt_wrapper::{wolfcrypt_init, wolfcrypt_cleanup};
use wolfcrypt_wrapper::sha::SHA256;

wolfcrypt_init().expect("wolfCrypt_Init failed");

let mut hasher = SHA256::new().expect("SHA256::new failed");
hasher.update(b"hello ").expect("update failed");
hasher.update(b"world").expect("update failed");

let mut digest = [0u8; SHA256::DIGEST_SIZE];
hasher.finalize(&mut digest).expect("finalize failed");

wolfcrypt_cleanup().expect("wolfCrypt_Cleanup failed");
```

`Result<_, i32>` returned by every operation carries the wolfSSL library
error code on failure. Other algorithm modules (`aes`, `ecc`, `rsa`,
`ed25519`, …) follow the same `new` / `update` / `finalize` or
`new` / `sign` / `verify` shape; see each module's rustdoc for details.

## How it works

```text
wolfssl-src        Compiles wolfSSL/wolfCrypt C source via the cc crate
      │
wolfcrypt-sys      bindgen FFI
      │
wolfcrypt-wrapper  Idiomatic Rust types over wolfCrypt primitives (this crate)
```

| Category | Algorithms |
|----------|------------|
| AES | CBC, CCM, CFB, CTR, EAX, ECB, GCM, OFB, XTS |
| Asymmetric | ECC, RSA, Ed25519, Ed448, Curve25519, DH |
| Authenticated encryption | ChaCha20-Poly1305 |
| Hash | SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256 |
| MAC | CMAC, HMAC, BLAKE2 |
| KDF | HKDF, PBKDF2, PKCS#12 PBKDF, PRF, SSH KDF, TLSv1.3 HKDF, SRTP/SRTCP KDF |
| Post-quantum | Dilithium (ML-DSA), ML-KEM, LMS |
| Random | wolfCrypt RNG |

| Feature | Description |
|---------|-------------|
| `std` | Enable `std`-dependent helpers (off by default) |
| `fips` | Enable the wolfSSL FIPS 140-3 code path (commercial license required) |

## References

- [wolfcrypt](../wolfcrypt) — RustCrypto trait implementations over the
  same backend
- [wolfcrypt-sys](../wolfcrypt-sys) — raw bindgen FFI this wrapper is
  layered on
- [wolfssl-src](../wolfssl-src) — vendored wolfSSL C source build
- [wolfSSL repository](https://github.com/wolfSSL/wolfssl)
- [wolfSSL / wolfCrypt documentation](https://www.wolfssl.com/documentation/)
- [FIPS 140-3 certificate information](https://www.wolfssl.com/license/fips/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
