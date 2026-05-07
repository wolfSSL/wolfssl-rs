# wolfhsm

Safe Rust client for [wolfHSM](https://github.com/wolfSSL/wolfHSM) hardware
security modules. Wraps the wolfHSM C client library with an idiomatic Rust
API; the wolfHSM server runs separately on secure hardware (Infineon TC3xx,
Microchip PIC32CZ, Renesas RH850, etc.) or a POSIX simulator.

## Why

The wolfHSM C client is portable and small, but it is a raw C API. This
crate adds the Rust guarantees the C API cannot express:

- **Hardware-isolated keys** — ECC P-256, Ed25519, Curve25519, RSA, ML-DSA,
  AES, CMAC keys are generated and stored inside the secure enclave;
  private key material never crosses the transport.
- **RAII cache-slot management** — closure-based key APIs guarantee server
  cache slots are evicted on every path, including when the closure
  returns `Err`.
- **Typed key handles** — `EccP256Key`, `RsaKey`, `Ed25519Key`, `AesKey`,
  `Curve25519Key`, `MlDsaKey`, `CmacKey` prevent mixing key types at
  compile time.
- **`Result` everywhere** — no raw C return-code checking in application
  code.
- **RustCrypto interop** — `EccP256Key::signer` and `Ed25519Key::signer`
  return `signature::Signer` adapters, so HSM keys plug into any code
  expecting a `signature::Signer`.
- **`&mut Client` enforces protocol** — the wolfHSM transport allows only
  one in-flight request; requiring `&mut Client` on every method makes
  the borrow checker enforce that invariant.

## Usage

```toml
[dependencies]
wolfhsm = "0.1"
```

### Connect and sign

```rust
use wolfhsm::{Client, Transport};

let mut client = Client::connect(
    Transport::Tcp { ip: "127.0.0.1".into(), port: 8080 },
    1, // client id
)?;

let digest = [0u8; 32]; // SHA-256 of the data to sign
let sig = client.with_ecc_p256_key(|key, client| {
    key.sign_digest(client, &digest)
})?;
```

`with_ecc_p256_key` generates the key, runs the closure, and always evicts
the cache slot — even if the closure returns `Err`.

### Multiple operations on the same key

```rust
let (pub_der, sig) = client.with_ecc_p256_key(|key, client| {
    let pub_der = key.public_key_der(client)?;
    let sig = key.sign_digest(client, &digest)?;
    Ok((pub_der, sig))
})?;
// Cache slot evicted here, regardless of outcome.
```

### NVM (persistent object store)

```rust
use wolfhsm::NvmId;

let id: NvmId = /* … */;
client.nvm_add(id, /* access */ 0, /* flags */ 0, b"my-key", &key_bytes)?;
let data = client.nvm_read(id, /* offset */ 0)?;
client.nvm_delete(id)?;
```

### CryptoCb integration

Register the HSM as a wolfCrypt CryptoCb device so existing wolfCrypt code
routes operations to the HSM transparently:

```rust
use wolfhsm::CryptoCbGuard;

let _guard = CryptoCbGuard::register(&mut client)?;
// While `_guard` is alive, wolfCrypt operations using DEV_ID are
// dispatched to the HSM. Dropped on scope exit.
```

### RustCrypto `Signer`

```rust
use signature::Signer;

client.with_ecc_p256_key(|key, client| {
    let signer = key.signer(client);
    let sig: p256::ecdsa::DerSignature = signer.sign(b"message");
    Ok(sig)
})?;
```

## How it works

```text
wolfhsm-src     Compiles the wolfHSM C client library from source via the
│               cc crate; emits DEP_WOLFHSM_SRC_{INCLUDE,LIB}.
│
wolfhsm-sys     bindgen-generated FFI to wh_client.h plus C shims that
│               stack-allocate wolfCrypt key/context structs on the
│               C side (those types are opaque from Rust).
│
wolfhsm         Safe Rust API — Client, typed key handles, NVM,
                counters, CryptoCb, RustCrypto adapters (this crate).
```

The communication model is request/response over a transport:

```text
Your app (Rust) → wolfhsm → wolfHSM C client → TCP/UDS/SHM → wolfHSM server
```

The server is a separate process or secure-element firmware. It must be
running before `Client::connect` is called.

### Transport variants

| Variant | Mechanism |
|---------|-----------|
| `Transport::Tcp` | TCP/IP socket |
| `Transport::Uds` | Unix domain socket |
| `Transport::Shm` | POSIX shared memory (same host, zero-copy) |

### Feature flags

| Feature | What it enables |
|---------|----------------|
| `cert`  | Certificate management (`wh_Client_Cert*`) — store, read, and verify DER certificates against trusted roots in NVM |
| `auth`  | Authentication and user management (`wh_Client_Auth*`) |
| `she`   | SHE (Secure Hardware Extension) AutoSAR automotive key management; requires `WOLFSSL_AES_DIRECT` and `HAVE_AES_ECB` in the linked wolfSSL |
| `mldsa` | ML-DSA (Dilithium) key support; requires `HAVE_DILITHIUM` in the linked wolfSSL |

### Build prerequisites

A wolfHSM source tree and a compiled wolfSSL with `WOLF_CRYPTO_CB` enabled
are required at build time. Configuration is handled by
[`wolfhsm-src`](../wolfhsm-src) and [`wolfhsm-sys`](../wolfhsm-sys); see
those crates for the full set of supported environment variables
(`WOLFHSM_SRC`, `WOLFSSL_DIR`, `WOLFSSL_INCLUDE_DIR`, `WOLFSSL_SRC`).

## References

- [wolfhsm-sys](../wolfhsm-sys) — raw FFI bindings; use this only if you
  need a wolfHSM C symbol that is not yet wrapped here
- [wolfhsm-src](../wolfhsm-src) — vendored wolfHSM C source build
- [wolfcrypt-tls](../wolfcrypt-tls) — safe Rust TLS using wolfSSL (the
  `wolfssl` crate name)
- [wolfHSM repository](https://github.com/wolfSSL/wolfHSM)
- [wolfHSM documentation](https://www.wolfssl.com/documentation/manuals/wolfhsm/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfHSM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfHSM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
