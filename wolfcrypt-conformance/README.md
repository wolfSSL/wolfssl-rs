# wolfcrypt-conformance

Cross-validation test suite for the wolfssl-rs crates.

## What

`wolfcrypt-conformance` is the primary test crate for the workspace.  It cross-
validates the wolfCrypt backend against external test vector sets and independent
pure-Rust implementations:

- **Wycheproof** — Google's adversarial test vectors for AEAD, ECDSA, EdDSA,
  HKDF, HMAC, CMAC, RSA, and AES keywrap
- **CAVP/SHAVS** — NIST Cryptographic Algorithm Validation Program vectors for
  SHA-{1,2,3}
- **RustCrypto cross-validation** — each wolfCrypt algorithm output is compared
  against the corresponding pure-Rust RustCrypto implementation to confirm
  bit-exact agreement

## Why

wolfCrypt is a C library.  These tests confirm that the Rust bindings pass
bytes correctly and that the algorithm outputs match published test vectors and
independent implementations — not just that the code compiles and links.

## How to run

Vectors are not bundled with the crate.  Point to them with environment
variables:

```sh
WYCHEPROOF_DIR=/path/to/wycheproof \
CONFORMANCE_VECTORS_DIR=/path/to/vectors \
cargo test -p wolfcrypt-conformance
```

From a workspace checkout, vectors are found automatically in `third_party/`
and `vectors/` if present.

## How it works

Each test module:

1. Loads test vectors from the external directory (Wycheproof JSON or CAVP
   `.rsp` files).
2. Runs the operation through the wolfCrypt backend via the `wolfcrypt` crate.
3. Compares the result against the expected output from the vector set.

For cross-validation tests, the same input is also passed through the
corresponding RustCrypto pure-Rust implementation and the outputs are compared.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

MIT — see [LICENSE](LICENSE).

The [MIT License](https://opensource.org/licenses/MIT) applies to the Rust
source code in this crate.  The underlying wolfSSL/wolfCrypt C library is
licensed under GPL-2.0-or-later with a commercial option available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)

Need FIPS 140-3 validation in your Rust application?  wolfCrypt is FIPS 140-3
validated.  [Contact wolfSSL](https://www.wolfssl.com/license/) for a
commercial FIPS license and the validated source tree.
