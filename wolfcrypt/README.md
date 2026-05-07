# wolfcrypt

RustCrypto trait implementations backed by wolfCrypt.  Swap the backend under
your existing RustCrypto code without changing call sites.

## Why

wolfCrypt is a FIPS 140-3 validated cryptographic library used in billions of
devices across aerospace, automotive, and government products.  Choosing
`wolfcrypt` over pure-Rust alternatives gives you:

- **FIPS 140-3** — the same validated implementation used in production
  (commercial license required; [contact wolfSSL](https://www.wolfssl.com/license/))
- **Minimal footprint** — compiles to bare-metal RISC-V for embedded hardware
  security targets (Caliptra, secure elements, automotive MCUs)
- **No API changes** — your existing `digest::Digest`, `aead::Aead`,
  `signature::Signer` code keeps working; only the backend changes

## Usage

```toml
wolfcrypt = { version = "0.1", features = ["digest", "aead", "signature"] }
```

## Algorithms

| Feature | Algorithms |
|---------|-----------|
| `digest` | SHA-1, SHA-224/256/384/512, SHA3-256/384/512 |
| `hmac` | HMAC-SHA-{1,256,384,512} |
| `cmac` | AES-{128,256}-CMAC |
| `aead` | AES-{128,256}-GCM, ChaCha20-Poly1305 |
| `cipher` | AES-{128,256}-{CBC,CTR,CFB}, ChaCha20 |
| `hkdf` | HKDF-SHA-{256,384,512} |
| `pbkdf2` | PBKDF2-HMAC-SHA-{1,256,384,512} |
| `ecdsa` | ECDSA P-256, P-384, P-521 |
| `ed25519` | Ed25519 |
| `ed448` | Ed448 |
| `rsa` | RSA PKCS#1 v1.5 and PSS |
| `mldsa` | ML-DSA (Dilithium) |
| `mlkem` | ML-KEM (Kyber) |
| `keywrap` | AES keywrap |
| `dh` / `ecdh` | DH, ECDH |
| `rand` | CSPRNG (included by default) |

## How it works

```text
wolfssl-src     Compiles wolfSSL/wolfCrypt C source via the cc crate
      │
wolfcrypt-sys   bindgen FFI; emits cargo cfg flags per compiled algorithm
      │         (wolfssl_aes_gcm, wolfssl_ecc_p384, …)
      │
wolfcrypt-rs    Typed Rust wrapper + C shim for struct field access
      │
wolfcrypt       RustCrypto trait impls (this crate)
```

Each algorithm is gated behind a Cargo feature and a corresponding cfg flag
emitted by `wolfcrypt-sys`, so unused algorithms are dead-stripped.

## FIPS 140-3

```toml
wolfcrypt = { version = "0.1", features = ["aead", "fips"] }
```

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated — the same library, the same code path.  Enabling the `fips` feature
alone is not sufficient: FIPS 140-3 validation requires the specific wolfSSL
source tree submitted for validation and a commercial license.
[Contact wolfSSL](https://www.wolfssl.com/license/) for a commercial FIPS
license and the validated source tree.  See the
[workspace README](https://github.com/wolfSSL/wolfssl-rs) for full details.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
