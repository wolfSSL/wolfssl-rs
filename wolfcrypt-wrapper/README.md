# wolfcrypt-wrapper

Rust wrapper for the wolfCrypt cryptographic algorithms portion of the
wolfSSL C library.

## What

`wolfcrypt-wrapper` provides idiomatic Rust types and functions over the
wolfCrypt C API.  It covers a broad set of algorithms with a straightforward
API, making it a good choice when you need direct access to wolfCrypt
primitives without the RustCrypto trait layer.

For code written against RustCrypto traits (`digest::Digest`, `aead::Aead`,
`signature::Signer`, etc.) use the `wolfcrypt` crate instead.

## Why

- **FIPS 140-3** — wolfCrypt is FIPS 140-3 validated; this wrapper gives you
  direct access to the validated primitives
  ([contact wolfSSL](https://www.wolfssl.com/license/) for FIPS licensing)
- **Broad coverage** — AES (all modes), ECC, RSA, Ed25519, Ed448, SHA family,
  HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, Curve25519, and more
- **Thin wrapper** — stays close to the C API; useful when you need an
  algorithm not yet covered by the higher-level `wolfcrypt` crate

## How to use

The `wolfssl` C library must be installed before building this crate.

```toml
[dependencies]
wolfcrypt-wrapper = "1.0"
```

## How it works

```text
wolfssl-src        Compiles wolfSSL/wolfCrypt C source via the cc crate
      │
wolfcrypt-sys      bindgen FFI
      │
wolfcrypt-wrapper  Idiomatic Rust types over wolfCrypt primitives (this crate)
```

## API Coverage

| Category | Algorithms |
|---|---|
| AES | CBC, CCM, CFB, CTR, EAX, ECB, GCM, OFB, XTS |
| Asymmetric | ECC, RSA, Ed25519, Ed448, Curve25519, DH |
| Authenticated encryption | ChaCha20-Poly1305 |
| Hash | SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256 |
| MAC | CMAC, HMAC, BLAKE2 |
| KDF | HKDF, PBKDF2, PKCS#12 PBKDF, PRF, SSH KDF, TLSv1.3 HKDF, SRTP/SRTCP KDF |
| Random | RNG |

## FIPS 140-3

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated — the same library this crate wraps.  [Contact wolfSSL](https://www.wolfssl.com/license/)
for a commercial FIPS license and the validated source tree.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

MIT — see [LICENSE](LICENSE).

The [MIT License](https://opensource.org/licenses/MIT) applies to the Rust
source code in this crate.  The underlying wolfSSL/wolfCrypt C library is
licensed under GPL-2.0-or-later with a commercial option available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)
