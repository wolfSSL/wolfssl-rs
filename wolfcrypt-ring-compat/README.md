# wolfcrypt-ring-compat

API-compatible replacement for the [`ring`](https://crates.io/crates/ring)
crate, backed by wolfCrypt instead of BoringSSL.

## Why

`ring` is widely used by rustls, AWS SDKs, and other foundational Rust crates,
but it is not FIPS 140-3 certifiable.  `wolfcrypt-ring-compat` gives you the
same API with a FIPS-validatable backend:

- **Drop-in replacement** — no application code changes; swap the Cargo
  dependency and the `ring` API keeps working
- **FIPS 140-3** — wolfCrypt is FIPS 140-3 validated; this is the migration
  path if your project uses `ring`'s API and needs a FIPS-certifiable backend
  ([contact wolfSSL](https://www.wolfssl.com/license/))
- **Broad coverage** — targets API parity with ring 0.17

## Usage

```toml
# Before
ring = "0.17"

# After
wolfcrypt-ring-compat = { version = "1.16", features = ["ring-sig-verify"] }
```

Same API.  No application code changes required.

## Coverage

AES-GCM, ChaCha20-Poly1305, ECDH (P-256, P-384, X25519), SHA-{1,256,384,512},
HMAC, HKDF, PBKDF2, ECDSA, Ed25519, RSA PKCS#1v1.5 and PSS, SystemRandom.
Targets API parity with ring 0.17.

## How it works

```text
wolfssl-src          Compiles wolfSSL/wolfCrypt C source via the cc crate
      │
wolfcrypt-sys        bindgen FFI + cargo cfg flags per compiled algorithm
      │
wolfcrypt-rs         Typed Rust wrapper
      │
wolfcrypt-ring-compat  ring-compatible API surface (this crate)
```

The crate exports `lib.name = "ring"` so that downstream crates that import
`ring` symbols use the wolfCrypt implementation without source changes.  Add a
`[patch.crates-io]` entry in your workspace to redirect the `ring` dependency.

## FIPS 140-3

```toml
wolfcrypt-ring-compat = { version = "1.16", features = ["fips"] }
```

`ring` is not FIPS 140-3 certifiable.  wolfCrypt is.  This is the migration
path if you need ring's API with a FIPS-certifiable backend.

FIPS 140-3 validation requires a wolfSSL commercial FIPS license and the
specific validated source tree.
[Contact wolfSSL](https://www.wolfssl.com/license/) for details.  See the
[workspace README](https://github.com/wolfSSL/wolfssl-rs) for full build
instructions.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
