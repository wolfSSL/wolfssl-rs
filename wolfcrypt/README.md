# wolfcrypt

RustCrypto trait implementations backed by wolfCrypt. Swap the backend
under your existing RustCrypto code without changing call sites.

## Why

wolfCrypt is a FIPS 140-3 validated cryptographic library used in billions
of devices across aerospace, automotive, and government products. Choosing
`wolfcrypt` over pure-Rust alternatives gives you:

- **FIPS 140-3** — the same validated implementation used in production.
  Enabling the `fips` feature alone is not sufficient; FIPS 140-3 validation
  requires the specific wolfSSL source tree submitted for validation and a
  commercial license. [Contact wolfSSL](https://www.wolfssl.com/license/)
  for a commercial FIPS license and the validated source tree.
- **Minimal footprint** — `#![no_std]` (with `alloc`); compiles to bare-metal
  RISC-V for embedded hardware security targets (Caliptra, secure elements,
  automotive MCUs)
- **No API changes** — your existing `digest::Digest`, `aead::Aead`,
  `signature::Signer` code keeps working; only the backend changes

## Usage

```toml
[dependencies]
wolfcrypt = { version = "0.1", features = ["digest", "aead", "signature"] }
```

### SHA-256 via the RustCrypto `Digest` trait

```rust
use wolfcrypt::Sha256;
use digest_trait::Digest;

let mut hasher = Sha256::new();
hasher.update(b"hello ");
hasher.update(b"world");
let digest = hasher.finalize();
// digest: GenericArray<u8, U32>
```

### AES-256-GCM via the RustCrypto `Aead` trait

```rust
use wolfcrypt::Aes256Gcm;
use aead_trait::{Aead, KeyInit};

let key = [0u8; 32];
let nonce = [0u8; 12];
let cipher = Aes256Gcm::new(&key.into());
let ciphertext = cipher.encrypt(&nonce.into(), b"plaintext".as_ref())?;
let plaintext  = cipher.decrypt(&nonce.into(), ciphertext.as_ref())?;
```

### Ed25519 via the RustCrypto `Signer`/`Verifier` traits

```rust
use wolfcrypt::{Ed25519SigningKey, Ed25519VerifyingKey};
use signature_trait::{Signer, Verifier};

let signing_key = Ed25519SigningKey::generate()?;
let verifying_key: Ed25519VerifyingKey = signing_key.verifying_key();
let signature = signing_key.sign(b"message");
verifying_key.verify(b"message", &signature)?;
```

The trait crates are renamed in `Cargo.toml` (`digest_trait`, `aead_trait`,
`signature_trait`) to avoid colliding with the `digest`/`aead`/`signature`
modules of this crate; downstream code typically imports the upstream names
directly.

For algorithms with no RustCrypto trait (HKDF, PBKDF2, AES Key Wrap, classic
DH, ECDH, ML-KEM), see the per-module documentation; each provides a bespoke
API with method names matching the closest RustCrypto sibling.

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

| Feature | Algorithms / role |
|---------|-------------------|
| `digest` | SHA-1, SHA-224/256/384/512, SHA3-256/384/512, SHA-512/256 |
| `hmac` | HMAC-SHA-{1,256,384,512} |
| `cmac` | AES-{128,256}-CMAC |
| `aead` | AES-{128,192,256}-GCM, ChaCha20-Poly1305, AES-{128,256}-CCM |
| `cipher` | AES-{128,192,256}-{CBC,CTR,CFB,ECB}, ChaCha20 |
| `des3` | DES-EDE3-CBC (legacy) |
| `poly1305` | Poly1305 MAC |
| `hkdf` | HKDF-SHA-{256,384,512} |
| `pbkdf2` | PBKDF2-HMAC-SHA-{256,384,512} |
| `ecdsa` | ECDSA P-256, P-384, P-521 |
| `ed25519` | Ed25519 |
| `ed448` | Ed448 |
| `rsa` | RSA PKCS#1 v1.5 and PSS |
| `rsa-direct` | Raw RSA primitives (`rsa` + `rand`) |
| `mldsa` | ML-DSA (Dilithium) — FIPS 204 |
| `mlkem` | ML-KEM (Kyber) — FIPS 203 |
| `keywrap` | AES Key Wrap (RFC 3394) |
| `dh` / `ecdh` | Classic DH and ECDH (X25519, X448, NIST P-256/P-384/P-521) |
| `rand` | CSPRNG (`WolfRng`); enabled by default |
| `blake2` / `shake` / `kdf` / `ecc` / `lms` | Additional algorithm modules |
| `hpke` | RFC 9180 HPKE (`rsa` plumbing + `rand`) |
| `cryptocb` | CryptoCb hardware-callback offload hooks |
| `fips` | Activates the wolfSSL FIPS 140-3 code path (commercial license required) |
| `riscv-bare-metal` | Bare-metal RISC-V configuration (Caliptra) |
| `cryptocb-only` | Build wolfSSL with only the CryptoCb routing layer |
| `cryptocb-pure` | Minimal CryptoCb-only build (no SSL/EVP/HKDF/ASN-template) |
| `require-dev-id` | Compile-error if any caller still uses the software DRBG path |

## References

- [wolfcrypt-rs](../wolfcrypt-rs) — typed FFI layer this crate is built on
- [wolfcrypt-ring-compat](../wolfcrypt-ring-compat) — `ring` API parity
  alternative for the same backend
- [wolfcrypt-tls](../wolfcrypt-tls) — TLS client/server using the same backend
- [wolfcrypt-conformance](../wolfcrypt-conformance) — cross-validation suite
  (NIST CAVP, Wycheproof, RFC vectors); always run after modifying this crate
- [RustCrypto traits](https://github.com/RustCrypto/traits) — upstream
  trait definitions
- [wolfSSL repository](https://github.com/wolfSSL/wolfssl)
- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [FIPS 140-3 certificate information](https://www.wolfssl.com/license/fips/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
