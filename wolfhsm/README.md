# wolfhsm

Safe Rust client for [wolfHSM](https://github.com/wolfSSL/wolfHSM) hardware security modules.

wolfHSM is an open-source HSM firmware library from wolfSSL. This crate wraps the wolfHSM C client library with an idiomatic Rust API: type-safe key handles, RAII-style cache slot management, and RustCrypto trait implementations.

## Quick start

```toml
wolfhsm = { version = "0.1" }
```

```rust
use wolfhsm::{Client, Transport};

let mut client = Client::connect(
    Transport::Tcp { ip: "127.0.0.1".into(), port: 8080 },
    1,
)?;

// Generate a P-256 key, sign, then evict — guaranteed even on error.
let digest = sha2::Sha256::digest(b"hello world");
let sig = client.with_ecc_p256_key(|key, client| {
    key.sign_digest(client, &digest)
})?;
```

## Crypto operations

| Operation | API |
|-----------|-----|
| ECC P-256 keygen, sign, verify, ECDH | `Client::with_ecc_p256_key` |
| RSA keygen, raw op, public key export | `Client::with_rsa_key` |
| Ed25519 keygen, sign, verify | `Client::with_ed25519_key` |
| AES-GCM encrypt/decrypt | `Client::with_aes_key` |
| CMAC | `Client::with_cmac_key` |
| CryptoCb device registration | `CryptoCbGuard` |

`EccP256Key` also implements `signature::Signer<p256::ecdsa::DerSignature>` via `EccP256Key::signer()`.

## Key management

Key handles hold a cache slot on the HSM server. The closure-based API ensures slots are always released:

```rust
client.with_ecc_p256_key(|key, client| {
    let pub_der = key.public_key_der(client)?;
    let sig = key.sign_digest(client, &digest)?;
    Ok((pub_der, sig))
})?;
// Cache slot is evicted here, whether the closure succeeded or failed.
```

## NVM

Persistent key and object storage on the HSM:

```rust
client.nvm_add(id, 0, 0, b"my-key", &key_bytes)?;
let data = client.nvm_read(id)?;
client.nvm_erase(id)?;
```

## Feature flags

| Feature | What it enables |
|---------|----------------|
| `cert`  | Certificate management (`wh_Client_Cert*`) — store, read, and verify DER certificates against trusted roots in NVM |
| `auth`  | Authentication and user management (`wh_Client_Auth*`) |
| `she`   | SHE (Secure Hardware Extension) automotive key management |
| `mldsa` | ML-DSA (Dilithium) key support; requires `HAVE_DILITHIUM` in the linked wolfSSL |

## Transport

| Variant | Description |
|---------|-------------|
| `Transport::Tcp` | TCP/IP socket |
| `Transport::Uds` | Unix domain socket |
| `Transport::Shm` | POSIX shared memory (same host, zero-copy) |

## Building

Requires a wolfHSM source tree and a compiled wolfSSL:

```sh
export WOLFHSM_SRC=/path/to/wolfHSM
export WOLFSSL_DIR=/path/to/wolfssl-install
cargo build
```

wolfSSL must be built with `WOLF_CRYPTO_CB` enabled. See the [workspace README](https://github.com/wolfSSL/wolfssl-rs) for full build instructions.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`
