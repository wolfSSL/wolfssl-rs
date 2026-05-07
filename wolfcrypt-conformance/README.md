# wolfcrypt-conformance

Cross-validation and trait conformance tests for the
[`wolfcrypt`](../wolfcrypt) backend.
Not published (`publish = false`); test crate only.

## Why

wolfCrypt is a C library reached through bindgen FFI. "It compiles" and
"it links" are not enough — bytes can be mis-laid out, lengths can be
swapped, and a subtly wrong implementation can still pass tests it
wrote against itself. This crate provides the independent oracles:

- **Wycheproof vectors** — Google's adversarial test corpus for AEAD,
  ECDSA, EdDSA, ECDH, HKDF, HMAC, CMAC, RSA (PKCS#1 v1.5, OAEP, PSS),
  and AES keywrap.
- **NIST CAVP / SHAVS vectors** — official Cryptographic Algorithm
  Validation Program vectors for SHA-1, SHA-2, SHA-3, and CMAC.
- **RustCrypto cross-validation** — each wolfCrypt output is compared
  bit-for-bit against the corresponding pure-Rust RustCrypto crate
  (`sha2`, `aes-gcm`, `chacha20poly1305`, `hmac`, `hkdf`, `pbkdf2`,
  `ed25519-dalek`, `p256` / `p384` / `p521`, `x25519-dalek`, …).
- **RFC test vectors** — RFC 7748 (X25519/X448), RFC 8032 (Ed25519/Ed448),
  RFC 8439 (ChaCha20-Poly1305), and similar published vectors.
- **Optional Caliptra hardware path** — the `caliptra-hw` feature gates
  a separate binary that re-runs a representative algorithm subset
  through the Caliptra hardware dispatch path and asserts the
  per-algorithm dispatch counters increment.

## Usage

Vector files are not bundled with the crate. Point the test harness at
them with environment variables:

```sh
WYCHEPROOF_DIR=/path/to/wycheproof \
CONFORMANCE_VECTORS_DIR=/path/to/vectors \
cargo test -p wolfcrypt-conformance
```

From a workspace checkout, vectors are found automatically in
`third_party/wycheproof/` and `vectors/` if those directories are
populated.

To run the Caliptra hardware conformance binary (non-`riscv32` host
only):

```sh
cargo run -p wolfcrypt-conformance \
    --features caliptra-hw \
    --bin caliptra_hw_conformance
```

## How it works

```text
                  ┌──────────────────────────┐
                  │   Wycheproof / CAVP /    │
                  │   RFC / NIST vectors     │
                  └────────────┬─────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
        ┌─────▼─────┐                    ┌──────▼──────┐
        │ wolfcrypt │                    │ RustCrypto  │
        │ (FFI to C │                    │ pure-Rust   │
        │ wolfSSL)  │                    │ crates      │
        └─────┬─────┘                    └──────┬──────┘
              │                                 │
              └────────────► compare ◄──────────┘
                          bit-exact outputs
                          and error classes

  Optional caliptra-hw bin: routes a subset of operations through
  wolfcrypt-dpe-hw + caliptra-emu-periph and asserts hardware
  dispatch counters per suite.
```

`src/lib.rs` is intentionally near-empty; the crate exists only as a
host for `tests/` and the `caliptra_hw_conformance` binary. Each
integration test file under `tests/` covers one algorithm or one
vector source (`wycheproof_aead.rs`, `cavp_digest.rs`, `rfc_ed25519.rs`,
`rsa_pkcs1v15_baseline.rs`, …). Test helpers live under
`tests/helpers/`.

| Feature       | Description |
|---------------|-------------|
| `caliptra-hw` | Build the `caliptra_hw_conformance` binary against `wolfcrypt-dpe-hw` (with the `caliptra-2x` backend) and `caliptra-emu-periph`. Routes SHA-256/384/512, HMAC-384, AES-256-GCM, and ECDSA P-384 through the Caliptra hardware dispatch path and asserts per-algorithm dispatch counters. |

## References

- [wolfcrypt](../wolfcrypt) — safe Rust API under test
- [wolfcrypt-rs](../wolfcrypt-rs) — typed FFI wrapper
- [wolfcrypt-dpe-hw](../wolfcrypt-dpe-hw) — hardware backend used by
  the optional `caliptra-hw` binary
- [Wycheproof](https://github.com/google/wycheproof) — Google's
  adversarial test vector corpus
- [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) —
  official validation vectors
- [RustCrypto](https://github.com/RustCrypto) — pure-Rust crates used
  as cross-validation oracles
- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
