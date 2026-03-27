# wolfcrypt-conformance

Cross-validation tests for the wolfssl-rs crates against external test vector sets:

- **Wycheproof** — Google's adversarial test vectors for AEAD, ECDSA, EdDSA, HKDF, HMAC, CMAC, RSA, AES keywrap
- **CAVP/SHAVS** — NIST Cryptographic Algorithm Validation Program vectors for SHA-{1,2,3}

## Running

Vectors are not bundled with the crate. Point to them with environment variables:

```
WYCHEPROOF_DIR=/path/to/wycheproof \
CONFORMANCE_VECTORS_DIR=/path/to/vectors \
cargo test -p wolfcrypt-conformance
```

From a workspace checkout, vectors are found automatically in `third_party/` and `vectors/` if present.

## License

MIT
