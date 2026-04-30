# wolfhsm

Safe Rust client for [wolfHSM](https://github.com/wolfSSL/wolfHSM) hardware security modules.

## What

[wolfHSM](https://github.com/wolfSSL/wolfHSM) is an open-source C firmware library from wolfSSL that implements the server side of a hardware security module (HSM). It runs on secure microcontrollers — Infineon TC3xx, Microchip PIC32CZ, Renesas RH850, and others — and exposes cryptographic services to a host processor over a transport layer (TCP, Unix socket, or shared memory).

This crate wraps the wolfHSM C **client** library with an idiomatic Rust API. Your application links this crate; the wolfHSM server runs separately (on secure hardware or a POSIX simulator). The crate provides:

- **Hardware-isolated keys** — ECC P-256, Ed25519, Curve25519, RSA, ML-DSA — generated and stored inside the secure enclave; private key material never leaves
- **Symmetric crypto** — AES-GCM encryption/decryption, CMAC, HKDF key derivation
- **NV storage** — tamper-resistant object store for keys, certificates, counters, and arbitrary data
- **CryptoCb integration** — register the HSM as a wolfcrypt CryptoCb device so existing wolfcrypt code routes operations to the HSM transparently
- **RustCrypto traits** — `EccP256Key` and `Ed25519Key` implement `signature::Signer`

## Why

### Why wolfHSM?

wolfHSM is self-contained (depends only on wolfSSL/wolfCrypt), compiles to a small footprint, and is designed from the ground up for embedded and automotive HSM targets. The client library is portable C that is straightforward to wrap.

### Why this crate?

`wolfhsm` adds the Rust guarantees the C API cannot express:

- **RAII key management** — cache slots are always released on drop, even if the closure returns `Err`
- **Typed key handles** — `EccP256Key`, `RsaKey`, `AesKey` prevent mixing key types at compile time
- **`Result` everywhere** — no raw C return code checking in application code
- **RustCrypto interop** — use HSM keys anywhere a `signature::Signer` is accepted

## How it works

### Crate stack

```text
wolfhsm-src     Compiles the wolfHSM C client library from source via the
│               cc crate; emits DEP_WOLFHSM_SRC_{INCLUDE,LIB} for downstream
│
wolfhsm-sys     bindgen-generated FFI bindings to wh_client.h and friends;
│               also compiles C shims for key operations (wolfcrypt structs
│               are zero-sized in the Rust FFI and must be stack-allocated
│               on the C side)
│
wolfhsm         Safe Rust API — Client, typed key handles, NVM, counters,
                CryptoCb, RustCrypto trait impls (this crate)
```

### Communication model

```text
Your app (Rust) → wolfhsm → wolfHSM C client lib → TCP/UDS/SHM → wolfHSM server
```

The server is a separate process (or secure element firmware). This crate handles the client side only. The server must be started independently before calling `Client::connect`.

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

## References

- [wolfHSM repository](https://github.com/wolfSSL/wolfHSM)
- [wolfHSM documentation](https://www.wolfssl.com/documentation/manuals/wolfhsm/)
- [wolfssl-rs workspace](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfHSM is copyright wolfSSL Inc. and its contributors.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`

This crate is available under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
For proprietary or commercial use where the GPL is not acceptable, a commercial
license is available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

wolfHSM itself is licensed under GPL-2.0-or-later or a commercial wolfSSL license.
