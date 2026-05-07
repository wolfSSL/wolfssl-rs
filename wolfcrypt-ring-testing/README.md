# wolfcrypt-ring-testing

Integration tests and Criterion benchmarks for
[`wolfcrypt-ring-compat`](../wolfcrypt-ring-compat). Not a library
crate; exists only to keep test data, vectors, and benchmark harnesses
out of the published `wolfcrypt-ring-compat` crate.

## Why

`wolfcrypt-ring-compat` claims API parity with upstream `ring`. That
claim is only meaningful if the same inputs produce the same outputs
on both backends.

- **Cross-backend equivalence** — tests import both
  `wolfcrypt_ring_compat::*` (the wolfCrypt backend) and `ring::*`
  (upstream BoringSSL backend) and assert byte-for-byte equality on
  AEAD seal/open, agreement (X25519 / P-256 / P-384), HKDF, RSA
  PKCS#1 v1.5 / PSS / OAEP, and QUIC header protection.
- **Direct throughput comparison** — Criterion benchmarks measure the
  wolfCrypt path by default and can be enabled to also benchmark
  upstream `ring` and OpenSSL on the same inputs, in the same harness.
- **No test pollution in the published crate** — keeping vector files,
  bench data, and `dev-dependencies` (`criterion`, `ring`, `openssl`)
  out of `wolfcrypt-ring-compat` shrinks its dep tree and
  `cargo publish` payload.
- **Optional FIPS path** — the `fips` feature forwards to
  `wolfcrypt-ring-compat/fips`, so the same test and benchmark suite
  can be re-run against the FIPS 140-3 validated wolfSSL source module.

## Usage

```sh
# Run the integration tests
WOLFSSL_SRC=/path/to/wolfssl \
cargo test -p wolfcrypt-ring-testing

# Run the Criterion benchmarks
WOLFSSL_SRC=/path/to/wolfssl \
cargo bench -p wolfcrypt-ring-testing

# Compare against upstream ring and OpenSSL
cargo bench -p wolfcrypt-ring-testing \
    --features ring-benchmarks,openssl-benchmarks

# Run the suite against the FIPS 140-3 validated source
WOLFSSL_FIPS_SOURCE_DIR=/path/to/wolfssl-fips \
cargo test -p wolfcrypt-ring-testing --features fips
```

## How it works

```text
                tests/  +  benches/
                     │
          ┌──────────┼──────────────────────────┐
          │          │                          │
   ┌──────▼──────┐   │                   ┌──────▼──────┐
   │ wolfcrypt-  │   │                   │ ring        │
   │ ring-compat │   │                   │ (upstream,  │
   │ (lib.name = │   │                   │ dev-dep)    │
   │  "ring")    │   │                   └──────┬──────┘
   └──────┬──────┘   │                          │
          │          │                   ┌──────▼──────┐
          │          │                   │ openssl     │
          │          │                   │ (dev-dep,   │
          │          │                   │ vendored)   │
          │          │                   └──────┬──────┘
          │          │                          │
          └──────────► compare ◄────────────────┘
                  outputs / errors / throughput
```

`tests/` contains five integration test files (`aead_test`,
`agreement_tests`, `hkdf_test`, `quic_test`, `rsa_test`). `benches/`
contains twelve Criterion harnesses (`aead_benchmark`,
`agreement_benchmark`, `cipher_benchmark`, `digest_benchmark`,
`ecdsa_benchmark`, `ed25519_benchmark`, `hkdf_benchmark`,
`hmac_benchmark`, `kem_benchmark`, `pbkdf2_benchmark`, `quic_benchmark`,
`rsa_benchmark`).

Tests refer to the wolfCrypt backend by its Cargo crate name
(`wolfcrypt_ring_compat::aead`, etc.) and to upstream as
`ring::aead`. Both names resolve unambiguously inside this crate
because upstream `ring` is pulled in as a `dev-dependency`; the
`lib.name = "ring"` collision is avoided by not declaring
`wolfcrypt-ring-compat` as a runtime dependency in any consumer that
also depends on real `ring`.

| Feature              | Description |
|----------------------|-------------|
| `ring-benchmarks`    | Include upstream `ring` in the Criterion benchmark groups for side-by-side throughput comparison. |
| `openssl-benchmarks` | Include OpenSSL (vendored) in the Criterion benchmark groups. |
| `ring-sig-verify`    | Forwards to `wolfcrypt-ring-compat/ring-sig-verify`; required for tests that exercise `signature::VerificationAlgorithm::verify`. |
| `fips`               | Forwards to `wolfcrypt-ring-compat/fips`; runs the test and benchmark suite against the FIPS 140-3 validated wolfSSL source module. Requires `WOLFSSL_FIPS_SOURCE_DIR` and a wolfSSL commercial FIPS license. |

## References

- [wolfcrypt-ring-compat](../wolfcrypt-ring-compat) — backend under test
- [`ring`](https://github.com/briansmith/ring) — upstream crate used as
  the cross-validation oracle
- [Criterion.rs](https://github.com/bheisler/criterion.rs) — benchmark
  harness
- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
