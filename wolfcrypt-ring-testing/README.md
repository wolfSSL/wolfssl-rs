# wolfcrypt-ring-testing

Test suite and benchmarks for `wolfcrypt-ring-compat`.

## What

`wolfcrypt-ring-testing` runs `ring`'s own test vectors against the wolfCrypt
backend to verify API parity.  It is not a library crate; it exists purely to
hold integration tests and benchmarks that would otherwise pollute the
`wolfcrypt-ring-compat` crate itself.

## Why

`wolfcrypt-ring-compat` exports the same symbols as `ring`.  These tests
confirm that the wolfCrypt implementation produces bit-exact results on ring's
published test vectors — not merely that the code compiles.  Benchmarks allow
direct throughput comparison against `ring` (with `--features ring-benchmarks`)
and OpenSSL (with `--features openssl-benchmarks`).

## How to run

```sh
WOLFSSL_SRC=/path/to/wolfssl \
cargo test -p wolfcrypt-ring-testing
```

## Benchmarks

```sh
WOLFSSL_SRC=/path/to/wolfssl \
cargo bench -p wolfcrypt-ring-testing
```

Compare against ring with `--features ring-benchmarks` and against OpenSSL
with `--features openssl-benchmarks`.

## How it works

Each test module imports from `ring` (which Cargo resolves to
`wolfcrypt-ring-compat` via the `lib.name = "ring"` setting) and runs the same
test logic that ring's own test suite uses, so any divergence in output or
behaviour is immediately visible.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated.  [Contact wolfSSL](https://www.wolfssl.com/license/) for a
commercial FIPS license and the validated source tree.
