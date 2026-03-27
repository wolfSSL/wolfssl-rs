# wolfcrypt-ring-compat

API-compatible replacement for the [`ring`](https://crates.io/crates/ring) crate, backed by wolfCrypt instead of BoringSSL.

## Usage

```toml
# Before
ring = "0.17"

# After
wolfcrypt-ring-compat = { version = "1.16", features = ["ring-sig-verify"] }
```

Same API. No application code changes required.

## Coverage

AES-GCM, ChaCha20-Poly1305, ECDH (P-256, P-384, X25519), SHA-{1,256,384,512}, HMAC, HKDF, PBKDF2, ECDSA, Ed25519, RSA PKCS#1v1.5 and PSS, SystemRandom. Targets API parity with ring 0.17.

## FIPS

```toml
wolfcrypt-ring-compat = { version = "1.16", features = ["fips"] }
```

ring is not FIPS 140-3 certifiable. wolfCrypt is. This is the migration path if you need ring's API with a FIPS-certifiable backend.

Requires a wolfSSL commercial FIPS license and the validated source tree. See the [workspace README](https://github.com/wolfSSL/wolfssl-rs).

## License

MIT
