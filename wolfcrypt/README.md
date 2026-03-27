# wolfcrypt

RustCrypto trait implementations backed by wolfCrypt. Swap the backend under your existing RustCrypto code without changing call sites.

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

## FIPS

```toml
wolfcrypt = { version = "0.1", features = ["aead", "fips"] }
```

Threads through to `wolfcrypt-sys`. Requires a wolfSSL commercial FIPS license and the validated source tree. See the [workspace README](https://github.com/wolfSSL/wolfssl-rs) for details.

## License

MIT
