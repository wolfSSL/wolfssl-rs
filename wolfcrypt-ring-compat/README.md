# wolfcrypt-ring-compat

API-compatible replacement for the [`ring`](https://crates.io/crates/ring)
crate, backed by [wolfCrypt][wolfCrypt] instead of BoringSSL. Exports
`lib.name = "ring"` so downstream code keeps `use ring::...` unchanged.

## Why

`ring` is widely used by rustls, AWS SDKs, and other foundational Rust
crates, but it is not FIPS 140-3 certifiable.
`wolfcrypt-ring-compat` provides the same API surface with a
FIPS-validatable backend:

- **Drop-in replacement** — exports `lib.name = "ring"`, so downstream
  code keeps `use ring::...` unchanged. Swap the dependency via
  `[patch.crates-io]` and rebuild.
- **FIPS 140-3** — wolfCrypt is FIPS 140-3 validated; this is the
  migration path if your project uses `ring`'s API and needs a
  FIPS-certifiable backend ([contact wolfSSL](https://www.wolfssl.com/license/)
  for the commercial FIPS license and validated source).
- **Broad coverage** — targets API parity with `ring 0.17`: AES-GCM,
  ChaCha20-Poly1305, ECDH (P-256, P-384, X25519), SHA-{1, 256, 384, 512},
  HMAC, HKDF, PBKDF2, ECDSA, Ed25519, RSA PKCS#1 v1.5 and PSS, and
  `SystemRandom`.
- **Single crypto stack** — every algorithm above goes through wolfCrypt
  rather than a mix of pure-Rust and assembly backends.

## Usage

```toml
[dependencies]
wolfcrypt-ring-compat = "1.16"

# Redirect transitive deps that ask for upstream `ring`:
[patch.crates-io]
ring = { package = "wolfcrypt-ring-compat", version = "1.16" }
```

```rust
use ring::aead::{LessSafeKey, UnboundKey, Aad, Nonce, AES_256_GCM};

let key_bytes = [0u8; 32];
let nonce_bytes = [0u8; 12];
let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
let key = LessSafeKey::new(unbound);

let mut in_out = b"plaintext".to_vec();
key.seal_in_place_append_tag(
    Nonce::assume_unique_for_key(nonce_bytes),
    Aad::empty(),
    &mut in_out,
)?;
```

> **Do not pull in both `ring` and `wolfcrypt-ring-compat`** in the same
> dependency tree. They export the same Rust library name (`ring`) and
> will collide at link time. Use the `[patch.crates-io]` snippet above
> to redirect any transitive `ring` dependency to this crate.

## How it works

```text
wolfssl-src              Compiles wolfSSL/wolfCrypt C source via the cc crate
      │
wolfcrypt-sys            bindgen FFI + cargo cfg flags per compiled algorithm
      │
wolfcrypt-rs             Typed Rust FFI wrapper
      │
wolfcrypt-ring-compat    ring-compatible API surface  ← this crate
                         lib.name = "ring"
```

The crate is organised module-for-module against upstream `ring`:
`aead`, `agreement`, `cipher`, `digest`, `ec`, `ed25519`, `hkdf`, `hmac`,
`pbkdf2`, `rand`, `rsa`, `signature`, plus `io` and `error`. Each
module forwards to the corresponding `wolfcrypt-rs` API instead of
BoringSSL.

| Feature           | Default | Description |
|-------------------|---------|-------------|
| `alloc`           | yes     | Allow allocation of arbitrary-sized values. Required by `io::writer`. (Semantics differ from upstream `ring`'s `alloc` feature.) |
| `std`             | yes     | Standard library support; depends on `alloc`. |
| `ring-io`         | yes     | Enable the `io` module. |
| `ring-sig-verify` | yes     | Preserve compatibility with `ring::signature::VerificationAlgorithm::verify`; pulls in `untrusted = "0.7.1"`. |
| `fips`            | no      | Build wolfcrypt-rs against the FIPS 140-3 validated wolfSSL source module. Requires `WOLFSSL_FIPS_SOURCE_DIR` and a wolfSSL commercial FIPS license. |
| `non-fips`        | no      | Compile-time guarantee that the non-FIPS wolfcrypt-rs is used. Mutually exclusive with `fips`. |

`fips` and `non-fips` are mutually exclusive — enabling both produces
a compile-time error. Additional build-time features (`bindgen`,
`prebuilt-nasm`, `asan`, `dev-tests-only`, `unstable`) are documented
in the crate-level rustdoc.

## References

- [`ring`](https://github.com/briansmith/ring) — upstream crate this
  is API-compatible with
- [wolfCrypt][wolfCrypt] — cryptographic backend
- [wolfcrypt-rs](../wolfcrypt-rs) — typed Rust FFI wrapper used by
  every module in this crate
- [wolfcrypt-sys](../wolfcrypt-sys) — bindgen-generated FFI bindings
- [wolfssl-src](../wolfssl-src) — wolfSSL C source build
- [wolfcrypt-ring-testing](../wolfcrypt-ring-testing) — tests and
  benchmarks for this crate
- [RFC 5116] — AEAD interface (AES-GCM, ChaCha20-Poly1305)
- [RFC 8439] — ChaCha20 and Poly1305 for IETF protocols
- [RFC 7748] — X25519 elliptic-curve Diffie-Hellman
- [RFC 8032] — Ed25519 / EdDSA signatures
- [RFC 6979] — Deterministic ECDSA
- [RFC 8017] — RSA PKCS#1 v2.2 (signatures and OAEP)
- [RFC 5869] — HKDF
- [RFC 2104] — HMAC
- [RFC 8018] — PBKDF2
- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

Portions of this crate are derived from
[`ring`](https://github.com/briansmith/ring), copyright Brian Smith and
the ring contributors (ISC license), and from AWS-LibCrypto.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

[wolfCrypt]: https://www.wolfssl.com/products/wolfcrypt/
[RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
[RFC 5116]: https://datatracker.ietf.org/doc/html/rfc5116
[RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869
[RFC 6979]: https://datatracker.ietf.org/doc/html/rfc6979
[RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
[RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017
[RFC 8018]: https://datatracker.ietf.org/doc/html/rfc8018
[RFC 8032]: https://datatracker.ietf.org/doc/html/rfc8032
[RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
