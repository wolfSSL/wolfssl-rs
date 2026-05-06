# Plan: wolfHSM Rust crate family

Add three new workspace crates: `wolfhsm-src`, `wolfhsm-sys`, `wolfhsm`.
Mirror the `wolfssl-src` / `wolfcrypt-sys` / `wolfcrypt-rs` pattern.

**Reference source**: `~/GIT/wolfHSM/` — full wolfHSM C source tree, already cloned.
**Consumers**: `secretx-wolfhsm` in `~/PROJECT/crate-secretsx/secretx-wolfhsm/` will wrap
the `wolfhsm` crate to implement `SecretStore` and `SigningBackend`. Do not touch that repo
during this work.

## Design goals

- **Complete**: cover the full wolfHSM client API
- **Idiomatic**: typed key handles, `Result` everywhere, RAII, RustCrypto trait impls
- **Composable**: CryptoCb integration lets wolfcrypt transparently route to HSM
- **Feature-gated**: optional subsystems (cert, auth, she, mldsa) behind Cargo features

---

## Implementation status (as of 2026-04-29)

All three crates exist in the workspace and build. The core API is complete.

**Remaining gaps:**

| Item | Notes |
|------|-------|
| `crypto/hkdf.rs` | Not implemented — `make_cache_key` / `make_export_key` missing |
| `Transport::Tls` | Not implemented — C layer exists (`posix_transport_tls.c`) but not exposed in Rust |
| `AesKey::cbc_encrypt/cbc_decrypt/ctr` | Not implemented — GCM only |
| `AeadInPlace` impl for `AesKey` | Not implemented |
| Integration tests #5, #6, #10, #19, #20 | `nvm_not_found`, `nvm_label_too_long`, `ecc_export_der`, `signer_trait_ecc`, `signer_trait_ed25519` |

**Design divergence from plan:** `Client` uses `&mut self` + closure pattern for key ops
instead of `RefCell<Box<whClientContext>>` + `&self`. See `client.rs` design section below.

---

## Crate 1: `wolfhsm-src`

Mirrors `wolfssl-src`. Compiles wolfHSM C source files into a static library and exports
metadata so downstream build scripts can find headers and the compiled lib.

### `wolfhsm-src/Cargo.toml`

```toml
[package]
name = "wolfhsm-src"
version = "0.1.0"
edition = "2021"
description = "Compile wolfHSM from source for use by wolfhsm-sys"
license = "GPL-3.0-only OR LicenseRef-wolfSSL-commercial"
repository = "https://github.com/wolfSSL/wolfssl-rs"

[build-dependencies]
cc = "1"
```

### `wolfhsm-src/src/lib.rs`

```rust
// Empty — this crate is build-script only.
```

### `wolfhsm-src/build.rs`

The build script must:

1. Locate wolfHSM source tree:
   - `WOLFHSM_SRC` env var
   - Fallback: `~/GIT/wolfHSM`
   - Panic with a clear message if not found.

2. Accept `WOLFSSL_INCLUDE_DIR` and `WOLFSSL_SETTINGS_INCLUDE` env vars for wolfSSL headers.
   These are required — wolfHSM headers include wolfSSL headers.
   In practice, wolfhsm-sys/build.rs sets these via `std::env::set_var` before this
   build-dep runs, sourcing them from `DEP_WOLFCRYPT_SYS_INCLUDE` and
   `DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE`. For standalone use, the caller sets them manually.

3. Compile all source files unconditionally. Feature flags only gate the Rust API surface;
   unused C code is stripped by the linker.

   Under `src/`:
   - `wh_comm.c`
   - `wh_message_comm.c`
   - `wh_message_crypto.c`
   - `wh_message_keystore.c`
   - `wh_message_nvm.c`
   - `wh_message_counter.c`
   - `wh_message_auth.c`
   - `wh_message_she.c`
   - `wh_client.c`
   - `wh_client_crypto.c`
   - `wh_client_nvm.c`
   - `wh_client_cryptocb.c`
   - `wh_client_keywrap.c`
   - `wh_client_auth.c`
   - `wh_client_cert.c`
   - `wh_client_she.c`
   - `wh_keyid.c`
   - `wh_lock.c`
   - `wh_log.c`
   - `wh_utils.c`

   Under `port/posix/`:
   - `posix_transport_tcp.c`
   - `posix_transport_shm.c`
   - `posix_transport_uds.c`
   - `posix_transport_tls.c`
   - `posix_lock.c`
   - `posix_timeout.c`
   - `posix_time.c`

4. Include paths:
   - `{wolfhsm_src}/` (wolfHSM root, for `wolfhsm/` headers)
   - `{wolfhsm_src}/port/posix` (POSIX transport headers)
   - `{wolfssl_include}` (wolfSSL headers, from env var)
   - `{wolfssl_settings_include}` (user_settings.h location)

   Compile flags: `-DWOLFHSM_CFG_NO_WOLFCRYPT=0` (enable wolfCrypt integration).

5. Export:
   ```
   cargo:INCLUDE={wolfhsm_src}
   cargo:LIB={out_dir}
   ```

6. Emit `cargo:rerun-if-env-changed` for `WOLFHSM_SRC`, `WOLFSSL_INCLUDE_DIR`,
   `WOLFSSL_SETTINGS_INCLUDE`.

---

## Crate 2: `wolfhsm-sys`

Raw FFI bindings + C shims. Mirrors `wolfcrypt-sys`. Depends on both `wolfcrypt-sys`
(for wolfSSL) and `wolfhsm-src` (for the compiled library).

### `wolfhsm-sys/Cargo.toml`

```toml
[package]
name = "wolfhsm-sys"
version = "0.1.0"
edition = "2021"
description = "Auto-generated Rust FFI bindings to wolfHSM"
license = "GPL-3.0-only OR LicenseRef-wolfSSL-commercial"
repository = "https://github.com/wolfSSL/wolfssl-rs"
links = "wolfhsm"

[dependencies]
wolfcrypt-sys = { version = "0.1.2", path = "../wolfcrypt-sys", features = ["vendored"] }

[build-dependencies]
bindgen = "0.72"
wolfhsm-src = { version = "0.1.0", path = "../wolfhsm-src" }
```

### `wolfhsm-sys/src/lib.rs`

```rust
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

Plus `extern "C"` declarations for the shim functions (see below).

### `wolfhsm-sys/build.rs`

1. Get wolfSSL include paths from wolfcrypt-sys metadata:
   ```rust
   let wolfssl_include = env::var("DEP_WOLFCRYPT_SYS_INCLUDE").unwrap();
   let wolfssl_settings = env::var("DEP_WOLFCRYPT_SYS_SETTINGS_INCLUDE").unwrap();
   ```

2. Propagate wolfSSL paths to wolfhsm-src via env (must happen before wolfhsm-src's
   build script consumes them):
   ```rust
   // SAFETY: build scripts are single-threaded; no other threads read these vars.
   unsafe {
       env::set_var("WOLFSSL_INCLUDE_DIR", &wolfssl_include);
       env::set_var("WOLFSSL_SETTINGS_INCLUDE", &wolfssl_settings);
   }
   ```

3. Get wolfHSM paths from wolfhsm-src metadata:
   ```rust
   let wolfhsm_include = env::var("DEP_WOLFHSM_SRC_INCLUDE").unwrap();
   let wolfhsm_lib     = env::var("DEP_WOLFHSM_SRC_LIB").unwrap();
   ```

4. Link the static libraries:
   ```rust
   println!("cargo:rustc-link-search=native={wolfhsm_lib}");
   println!("cargo:rustc-link-lib=static=wolfhsm");
   println!("cargo:rustc-link-lib=static=wolfhsm_shims");
   ```

5. Run bindgen over `wolfhsm-sys/wrapper.h`:
   ```c
   #include "wolfhsm/wh_common.h"
   #include "wolfhsm/wh_error.h"
   #include "wolfhsm/wh_comm.h"
   #include "wolfhsm/wh_client.h"
   #include "wolfhsm/wh_client_crypto.h"
   #include "wolfhsm/wh_client_cryptocb.h"
   #include "wolfhsm/wh_client_she.h"
   #include "wolfhsm/wh_auth.h"
   #include "port/posix/posix_transport_tcp.h"
   #include "port/posix/posix_transport_shm.h"
   #include "port/posix/posix_transport_uds.h"
   #include "port/posix/posix_transport_tls.h"
   ```

   Clang args: `-I{wolfhsm_include}`, `-I{wolfhsm_include}/port/posix`,
   `-I{wolfssl_include}`, `-I{wolfssl_settings}`.

   Use prefix allowlisting to capture wolfHSM symbols without pulling in wolfSSL internals:
   - `allowlist_type("wh.*")` and `allowlist_type("WH.*")`
   - `allowlist_type("posix_transport_.*")`  ← transport config structs
   - `allowlist_function("wh_Client_.*")`
   - `allowlist_item("WH_.*")`  ← constants and enums

6. Compile `wolfhsm-sys/src/shims.c` as a separate `cc::Build` into `libwolfhsm_shims.a`.
   Include paths are the same as wolfhsm-src.

### C shims (`wolfhsm-sys/src/shims.c`)

wolfcrypt key structs that are zero-sized (opaque) in Rust FFI require C shims to
stack-allocate them on the C side. Each shim: init key struct → set key ID → perform
operation → free key struct → return.

Write shims for every algorithm whose key struct is zero-sized in the generated bindings.
At minimum:

```c
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include <stdint.h>

/* ECC P-256 */
int wolfhsm_ecc_sign(whClientContext* ctx, uint16_t keyId,
                     const uint8_t* hash, uint16_t hash_len,
                     uint8_t* sig, uint16_t* sig_len);

int wolfhsm_ecc_verify(whClientContext* ctx, uint16_t keyId,
                       const uint8_t* hash, uint16_t hash_len,
                       const uint8_t* sig, uint16_t sig_len, int* result);

int wolfhsm_ecc_export_public_der(whClientContext* ctx, uint16_t keyId,
                                  uint8_t* out, uint32_t* out_len);

int wolfhsm_ecc_shared_secret(whClientContext* ctx, uint16_t priv_key_id,
                              const uint8_t* peer_der, uint32_t peer_der_len,
                              uint8_t* out, uint32_t* out_len);

int wolfhsm_ecc_make_key(whClientContext* ctx, int curve_id,
                         uint16_t* out_key_id);

/* Curve25519 */
int wolfhsm_curve25519_make_key(whClientContext* ctx, uint16_t* out_key_id);

int wolfhsm_curve25519_shared_secret(whClientContext* ctx, uint16_t priv_key_id,
                                     const uint8_t* peer_pub, uint32_t peer_len,
                                     uint8_t* out, uint32_t* out_len);

/* RSA */
int wolfhsm_rsa_sign(whClientContext* ctx, uint16_t keyId, int rsa_type,
                     const uint8_t* in, uint32_t in_len,
                     uint8_t* out, uint32_t* out_len);

int wolfhsm_rsa_verify(whClientContext* ctx, uint16_t keyId, int rsa_type,
                       const uint8_t* sig, uint32_t sig_len,
                       const uint8_t* msg, uint32_t msg_len, int* result);

int wolfhsm_rsa_make_key(whClientContext* ctx, int bits, long e,
                         uint16_t* out_key_id);

/* ML-DSA */
int wolfhsm_mldsa_sign(whClientContext* ctx, uint16_t keyId, int level,
                       const uint8_t* msg, uint32_t msg_len,
                       uint8_t* sig, uint32_t* sig_len);

int wolfhsm_mldsa_verify(whClientContext* ctx, uint16_t keyId, int level,
                         const uint8_t* sig, uint32_t sig_len,
                         const uint8_t* msg, uint32_t msg_len, int* result);

int wolfhsm_mldsa_make_key(whClientContext* ctx, int level,
                           uint16_t* out_key_id);

/* AES-GCM */
int wolfhsm_aes_gcm_encrypt(whClientContext* ctx, uint16_t keyId,
                             const uint8_t* iv, uint32_t iv_len,
                             const uint8_t* aad, uint32_t aad_len,
                             const uint8_t* in, uint32_t in_len,
                             uint8_t* out, uint8_t* tag, uint32_t tag_len);

int wolfhsm_aes_gcm_decrypt(whClientContext* ctx, uint16_t keyId,
                             const uint8_t* iv, uint32_t iv_len,
                             const uint8_t* aad, uint32_t aad_len,
                             const uint8_t* in, uint32_t in_len,
                             uint8_t* out,
                             const uint8_t* tag, uint32_t tag_len);

/* SHA-256 (one-shot) */
int wolfhsm_sha256(whClientContext* ctx,
                   const uint8_t* in, uint32_t in_len, uint8_t* out);

/* CMAC */
int wolfhsm_cmac(whClientContext* ctx, uint16_t keyId,
                 const uint8_t* in, uint32_t in_len,
                 uint8_t* out, uint32_t* out_len);
```

Note: `ed25519_key` IS sized in wolfcrypt-rs (`[u8; 256]` with static assert), so
Ed25519 operations do not need a shim — init and set key ID in Rust directly.
Current `wh_Client_Ed25519Sign` signature (post 2026-04 merge):
```c
int wh_Client_Ed25519Sign(whClientContext* ctx, ed25519_key* key,
                          const uint8_t* msg, uint32_t msgLen, uint8_t type,
                          const uint8_t* context, uint32_t contextLen,
                          uint8_t* sig, uint32_t* inout_sig_len);
```
Pass `type=0, context=NULL, contextLen=0` for standard Ed25519.

---

## Crate 3: `wolfhsm`

Safe Rust API. This is what consumers depend on.

### `wolfhsm/Cargo.toml`

```toml
[package]
name = "wolfhsm"
version = "0.1.0"
edition = "2021"
description = "Safe Rust API for wolfHSM secure element client"
license = "GPL-3.0-only OR LicenseRef-wolfSSL-commercial"
repository = "https://github.com/wolfSSL/wolfssl-rs"

[features]
cert  = []
auth  = []
she   = []
mldsa = []

[dependencies]
wolfhsm-sys  = { version = "0.1.0", path = "../wolfhsm-sys" }
wolfcrypt-rs = { version = "0.1.2", path = "../wolfcrypt-rs", features = ["vendored"] }
thiserror    = "1"
# RustCrypto traits
signature = "2"
digest    = "0.10"
aead      = "0.5"
# Concrete types for trait impls
p256   = { version = "0.13", features = ["ecdsa"] }
ed25519 = "2"
```

### Module structure

```
wolfhsm/src/
  lib.rs
  error.rs         WolfHsmError enum + check() helper
  client.rs        Client struct, connect, lifecycle
  transport.rs     Transport enum (Tcp, Shm, Uds, Tls)
  key.rs           KeyId newtype; raw key lifecycle (cache/evict/commit/erase/revoke/wrap)
  nvm.rs           NvmId, NvmObject, NvmMetadata; list/read/write/delete/find_by_label
  counter.rs       Counter handle; init/increment/read/reset/destroy
  crypto/
    mod.rs
    ecc.rs         EccP256Key + EccP256Signer; sign, verify, ecdh, make/load/export  ✓
    ed25519.rs     Ed25519Key + Ed25519Signer; sign, verify, make/load/export         ✓
    curve25519.rs  Curve25519Key; ecdh, make/load/export                              ✓
    rsa.rs         RsaKey; sign, verify, make/load/export                             ✓
    mldsa.rs       MlDsaKey (feature = "mldsa"); sign, verify, make/load/export       ✓
    aes.rs         AesKey; gcm_encrypt/gcm_decrypt only (cbc/ctr/AeadInPlace: TODO)  PARTIAL
    sha.rs         HsmSha256/384/512 + Digest impl                                    ✓
    cmac.rs        CmacKey; compute                                                   ✓
    hkdf.rs        hkdf_make_key, hkdf_make_export_key                               NOT IMPLEMENTED
    rng.rs         generate                                                            ✓
  cryptocb.rs      register_crypto_cb → CryptoCbGuard (RAII unregister on drop)
  cert.rs          (feature = "cert")
  auth.rs          (feature = "auth")
  she.rs           (feature = "she")
```

### `error.rs`

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("wolfHSM: not found")]                         NotFound,
    #[error("wolfHSM: no space")]                          NoSpace,
    #[error("wolfHSM: access denied")]                     Access,
    #[error("wolfHSM: bad arguments")]                     BadArgs,
    #[error("wolfHSM: aborted")]                           Aborted,
    #[error("wolfHSM: timeout")]                           Timeout,
    #[error("wolfHSM: not ready")]                         NotReady,
    #[error("wolfHSM: buffer size mismatch")]              BufferSize,
    #[error("wolfHSM: label too long (max {max} bytes)")]  LabelTooLong { max: usize },
    #[error("wolfHSM: error {0}")]                         Other(i32),
}

pub(crate) fn check(rc: i32) -> Result<(), Error> { ... }
```

Map `WH_ERROR_*` constants from wh_error.h to the enum variants.

### `transport.rs`

```rust
pub enum Transport {
    Tcp { host: String, port: u16 },
    Shm { name: String },
    Uds { path: String },
    // NOT IMPLEMENTED: Tls { host: String, port: u16 /* + TLS cert/key config */ },
    // The C layer has posix_transport_tls.c but it is not yet exposed in Rust.
}
```

### `client.rs`

> **Design divergence from original plan:** The plan proposed `RefCell<Box<whClientContext>>`
> + `&self` so that `Signer` impls could avoid `&mut`. The implementation instead uses
> `&mut self` throughout and exposes `Signer` adapters (`EccP256Signer`, `Ed25519Signer`)
> that borrow `&mut Client` for their lifetime. This enforces the single-in-flight-request
> invariant at compile time rather than at runtime via `RefCell::borrow_mut`. The `Signer`
> impls use interior `UnsafeCell` to satisfy the `&self` requirement of
> `signature::Signer::try_sign`. See `lib.rs` for the full rationale.
>
> `connect` also takes a `client_id: u8` argument (not in the original plan).
> `echo` writes into a caller-supplied `&mut [u8]` buffer and returns `usize` rather than
> returning `Vec<u8>`.

```rust
pub struct Client { /* &mut self required for all operations */ }

impl Client {
    pub fn connect(transport: Transport, client_id: u8) -> Result<Self, Error>;
    pub fn echo(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, Error>;
    pub fn info(&mut self) -> Result<ServerInfo, Error>;
}

impl Drop for Client {
    fn drop(&mut self) { /* wh_Client_CommClose then wh_Client_Cleanup */ }
}
```

### `key.rs`

```rust
/// Opaque key identifier. Wraps the C `whKeyId` (u16).
pub struct KeyId(pub(crate) whKeyId);

// Internal helpers used by crypto/ modules.
pub(crate) fn key_evict(client: &Client, id: &KeyId) -> Result<(), Error>;
pub(crate) fn key_commit(client: &Client, id: &KeyId) -> Result<(), Error>;
pub(crate) fn key_erase(client: &Client, id: &KeyId) -> Result<(), Error>;
pub(crate) fn key_revoke(client: &Client, id: &KeyId) -> Result<(), Error>;
pub(crate) fn key_wrap(client: &Client, cipher_type: u32,
                       wrap_key_id: &KeyId, key_id: &KeyId) -> Result<Vec<u8>, Error>;
pub(crate) fn key_unwrap_and_cache(client: &Client, cipher_type: u32,
                                   wrap_key_id: &KeyId,
                                   wrapped: &[u8]) -> Result<KeyId, Error>;
```

### `nvm.rs`

```rust
pub type NvmId = whNvmId;  // u16

pub struct NvmObject {
    pub id:     NvmId,
    pub label:  String,
    pub size:   u16,
    pub access: u16,
    pub flags:  u16,
}

pub struct NvmAvailable { pub objects: u32, pub bytes: u32 }

/// Returns NvmAvailable { free object slots, free bytes }.
pub fn available(client: &Client) -> Result<NvmAvailable, Error>;

/// List all NVM objects. Returns WH_ERROR_NOTFOUND from wh_Client_NvmList
/// as a normal loop-termination condition, not an error.
pub fn list(client: &Client) -> Result<Vec<NvmObject>, Error>;

/// Read a data object's contents by NVM ID.
pub fn read(client: &Client, id: NvmId) -> Result<Vec<u8>, Error>;

/// Write (create or overwrite) a data object by label. Destroys any existing
/// object with the same label first, then calls NvmAddObject.
/// Returns Error::LabelTooLong if label exceeds WH_NVM_LABEL_LEN (24) bytes.
pub fn write(client: &Client, label: &str, data: &[u8]) -> Result<NvmId, Error>;

/// Delete a data object by NVM ID.
pub fn delete(client: &Client, id: NvmId) -> Result<(), Error>;

/// Find the first NVM object matching label. O(n) round-trips; cache result.
pub fn find_by_label(client: &Client, label: &str) -> Result<NvmObject, Error>;
```

### `counter.rs`

```rust
pub struct Counter { id: NvmId }

impl Counter {
    pub fn init(client: &Client, id: NvmId, initial: u32) -> Result<Self, Error>;
    pub fn increment(&self, client: &Client) -> Result<u32, Error>;
    pub fn read(&self, client: &Client) -> Result<u32, Error>;
    pub fn reset(&self, client: &Client, value: u32) -> Result<u32, Error>;
    pub fn destroy(self, client: &Client) -> Result<(), Error>;
}
```

### `crypto/ecc.rs`

```rust
pub struct EccP256Key { id: KeyId }

impl EccP256Key {
    /// Generate an ephemeral P-256 key on the HSM (cached, not committed to NVM).
    pub fn generate(client: &Client) -> Result<Self, Error>;
    /// Load a committed P-256 key from NVM by label.
    pub fn load(client: &Client, label: &str) -> Result<Self, Error>;
    /// Commit a cached key to NVM under the given label.
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    /// Evict from the HSM key cache.
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    /// Export the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self, client: &Client) -> Result<Vec<u8>, Error>;
    /// Sign a pre-hashed digest (SHA-256). Returns DER-encoded ECDSA signature.
    pub fn sign_digest(&self, client: &Client, digest: &[u8]) -> Result<Vec<u8>, Error>;
    /// Verify a DER-encoded ECDSA signature against a pre-hashed digest.
    pub fn verify_digest(&self, client: &Client,
                         digest: &[u8], sig: &[u8]) -> Result<(), Error>;
    /// ECDH: compute shared secret with a peer DER-encoded SubjectPublicKeyInfo.
    pub fn ecdh(&self, client: &Client,
                peer_public_der: &[u8]) -> Result<Vec<u8>, Error>;
    /// Return a signing context implementing `signature::Signer`.
    /// SHA-256 hash is computed in Rust; only the signing operation hits the HSM.
    pub fn signer<'a>(&'a self, client: &'a Client) -> EccP256Signer<'a>;
}

/// Implements `signature::Signer<p256::ecdsa::DerSignature>`.
pub struct EccP256Signer<'a> { key: &'a EccP256Key, client: &'a Client }

impl<'a> signature::Signer<p256::ecdsa::DerSignature> for EccP256Signer<'a> {
    fn try_sign(&self, msg: &[u8]) -> Result<p256::ecdsa::DerSignature, signature::Error>;
}
```

### `crypto/ed25519.rs`

```rust
pub struct Ed25519Key { id: KeyId }

impl Ed25519Key {
    pub fn generate(client: &Client) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str) -> Result<Self, Error>;
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    pub fn public_key_bytes(&self, client: &Client) -> Result<[u8; 32], Error>;
    /// Sign a message. Uses wh_Client_Ed25519Sign with type=0, context=NULL, contextLen=0.
    /// No shim needed: ed25519_key is 256 bytes and can be heap-allocated in Rust.
    pub fn sign(&self, client: &Client, msg: &[u8]) -> Result<[u8; 64], Error>;
    pub fn verify(&self, client: &Client,
                  msg: &[u8], sig: &[u8; 64]) -> Result<(), Error>;
    pub fn signer<'a>(&'a self, client: &'a Client) -> Ed25519Signer<'a>;
}

pub struct Ed25519Signer<'a> { key: &'a Ed25519Key, client: &'a Client }

impl<'a> signature::Signer<ed25519::Signature> for Ed25519Signer<'a> {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, signature::Error>;
}
```

### `crypto/curve25519.rs`

```rust
pub struct Curve25519Key { id: KeyId }

impl Curve25519Key {
    pub fn generate(client: &Client) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str) -> Result<Self, Error>;
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    pub fn public_key_bytes(&self, client: &Client) -> Result<[u8; 32], Error>;
    /// X25519 DH. peer_public is a 32-byte little-endian public key.
    pub fn diffie_hellman(&self, client: &Client,
                          peer_public: &[u8; 32]) -> Result<[u8; 32], Error>;
}
```

### `crypto/rsa.rs`

```rust
pub struct RsaKey { id: KeyId, bits: u32 }

impl RsaKey {
    pub fn generate(client: &Client, bits: u32, e: u64) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str, bits: u32) -> Result<Self, Error>;
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    pub fn public_key_der(&self, client: &Client) -> Result<Vec<u8>, Error>;
    /// Raw RSA operation via wh_Client_RsaFunction (caller selects padding type).
    pub fn function(&self, client: &Client,
                    rsa_type: i32, in_buf: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn get_size(&self, client: &Client) -> Result<u32, Error>;
}
```

### `crypto/mldsa.rs` (feature = "mldsa")

```rust
pub struct MlDsaKey { id: KeyId, level: u8 }  // level: 44, 65, or 87

impl MlDsaKey {
    pub fn generate(client: &Client, level: u8) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str, level: u8) -> Result<Self, Error>;
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    pub fn sign(&self, client: &Client, msg: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn verify(&self, client: &Client,
                  msg: &[u8], sig: &[u8]) -> Result<(), Error>;
    pub fn check_private_key(&self, client: &Client) -> Result<(), Error>;
}
```

### `crypto/aes.rs`

```rust
pub struct AesKey { id: KeyId, bits: u32 }

impl AesKey {
    pub fn generate(client: &Client, bits: u32) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str, bits: u32) -> Result<Self, Error>;
    pub fn commit(&self, client: &Client, label: &str) -> Result<(), Error>;
    pub fn evict(&self, client: &Client) -> Result<(), Error>;
    /// Returns (ciphertext, 16-byte GCM tag).
    pub fn gcm_encrypt(&self, client: &Client, iv: &[u8],
                       aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16]), Error>;
    pub fn gcm_decrypt(&self, client: &Client, iv: &[u8], aad: &[u8],
                       ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, Error>;
    // NOT IMPLEMENTED:
    pub fn cbc_encrypt(&self, client: &Client,
                       iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn cbc_decrypt(&self, client: &Client,
                       iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    pub fn ctr(&self, client: &Client,
               iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, Error>;
}

// NOT IMPLEMENTED: AeadInPlace impl for AesKey
// impl aead::AeadInPlace for AesKey { ... }
```

### `crypto/sha.rs`

Implement `digest::Digest` + `digest::Update` + `digest::FixedOutput` for each variant.
For streaming, use `wh_Client_Sha256UpdateRequest` / `wh_Client_Sha256FinalRequest`.
For one-shot, use the single-call `wh_Client_Sha256` shim.

```rust
pub struct HsmSha256<'a> { client: &'a Client, /* internal wc_Sha256 state */ }
pub struct HsmSha384<'a> { client: &'a Client, /* internal wc_Sha384 state */ }
pub struct HsmSha512<'a> { client: &'a Client, /* internal wc_Sha512 state */ }

impl<'a> digest::Update for HsmSha256<'a> { ... }
impl<'a> digest::FixedOutput for HsmSha256<'a> { ... }
// etc. for 384, 512
```

### `crypto/cmac.rs`

```rust
pub struct CmacKey { id: KeyId }

impl CmacKey {
    pub fn generate(client: &Client, bits: u32) -> Result<Self, Error>;
    pub fn load(client: &Client, label: &str) -> Result<Self, Error>;
    pub fn compute(&self, client: &Client, data: &[u8]) -> Result<[u8; 16], Error>;
}
```

### `crypto/hkdf.rs`

```rust
/// Derive a new cached key via HKDF on the HSM.
pub fn make_cache_key(client: &Client, hash_type: i32,
                      salt_key_id: Option<KeyId>,
                      ikm_key_id: KeyId,
                      info: &[u8],
                      target_key_len: u16) -> Result<KeyId, Error>;

/// Derive and export a key via HKDF.
pub fn make_export_key(client: &Client, hash_type: i32,
                       salt_key_id: Option<KeyId>,
                       ikm_key_id: KeyId,
                       info: &[u8],
                       target_key_len: u16) -> Result<Vec<u8>, Error>;
```

### `crypto/rng.rs`

```rust
pub fn generate(client: &Client, size: usize) -> Result<Vec<u8>, Error>;
```

### `cryptocb.rs`

wolfcrypt has a global device registry. Register wolfHSM as `WH_DEV_ID` so all wolfcrypt
calls using that device ID are routed to the HSM. The guard unregisters on drop.

```rust
/// Device ID assigned to wolfHSM by wolfcrypt's CryptoCb system.
pub const DEV_ID: i32 = 0x5748_534D;  // "WHSM"

/// Register the wolfHSM client as a wolfcrypt CryptoCb device.
/// Returns a guard; the device is unregistered when the guard is dropped.
/// Only one guard should exist at a time — enforce with an AtomicBool.
pub fn register(client: &Client) -> Result<CryptoCbGuard<'_>, Error>;

pub struct CryptoCbGuard<'a> { _client: &'a Client }

impl Drop for CryptoCbGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: single-threaded; guard lifetime ensures client is still alive.
        unsafe { wolfcrypt_sys::wc_CryptoCb_UnRegisterDevice(DEV_ID); }
        REGISTERED.store(false, Ordering::Release);
    }
}
```

After registration, existing wolfcrypt types (ECC, AES, etc.) initialized with `WH_DEV_ID`
offload operations to the HSM transparently, without going through wolfhsm key handles.

### `cert.rs` (feature = "cert")

Wraps `wh_Client_Cert*` functions.

```rust
pub fn init(client: &Client) -> Result<(), Error>;
pub fn add_trusted(client: &Client, id: NvmId,
                   access: u16, cert: &[u8]) -> Result<(), Error>;
pub fn read_trusted(client: &Client, id: NvmId) -> Result<Vec<u8>, Error>;
pub fn erase_trusted(client: &Client, id: NvmId) -> Result<(), Error>;
pub fn verify(client: &Client, cert: &[u8]) -> Result<(), Error>;
/// Verify a certificate chain and cache the leaf public key. Returns cached KeyId.
pub fn verify_and_cache_leaf_pubkey(client: &Client,
                                    cert: &[u8]) -> Result<KeyId, Error>;
pub fn verify_acert(client: &Client, cert: &[u8]) -> Result<(), Error>;
```

### `auth.rs` (feature = "auth")

Wraps `wh_Client_Auth*` functions (added in wolfHSM post-1.4.0).

```rust
pub fn set_credentials(client: &Client,
                       user_id: u16, token: &[u8]) -> Result<(), Error>;
```

### `she.rs` (feature = "she")

Wraps `wh_Client_She*` functions for the Secure Hardware Extension automotive key
management protocol. See wolfHSM docs for the SHE protocol specification.

---

## Workspace integration

Add to `wolfssl-rs/Cargo.toml` workspace members:
```toml
"wolfhsm-src",
"wolfhsm-sys",
"wolfhsm",
```

---

## Testing

All integration tests require a wolfHSM simulator or device. Gate on `WOLFHSM_SERVER` env var:

```rust
fn server_addr() -> Option<String> {
    std::env::var("WOLFHSM_SERVER").ok()
}
```

Skip the test body if `server_addr()` returns `None`.

### Test cases

All verification must use an **independent oracle** — never verify wolfHSM output with
wolfHSM itself.

| # | Test | Actual test name | Oracle | Status |
|---|------|-----------------|--------|--------|
| 1 | `connect_disconnect` | `connect_echo` | — | ✓ |
| 2 | `echo` | `connect_echo` | byte-exact comparison | ✓ |
| 3 | `nvm_write_read` | `nvm_overwrite_read_delete` | byte-exact comparison | ✓ |
| 4 | `nvm_overwrite` | `nvm_overwrite_read_delete` | second value wins | ✓ |
| 5 | `nvm_not_found` | — | `Error::NotFound` | **MISSING** |
| 6 | `nvm_label_too_long` | — | `Error::LabelTooLong`, no round-trip | **MISSING** |
| 7 | `counter_lifecycle` | `counter_lifecycle` | init/increment/read/destroy | ✓ |
| 8 | `ecc_keygen_sign_verify` | `ecc_p256_sign_verify_cross` | `p256` crate verifies signature | ✓ |
| 9 | `ecc_ecdh` | `ecc_p256_ecdh_cross` | two keys → same shared secret | ✓ |
| 10 | `ecc_export_der` | — | `spki` crate parses SubjectPublicKeyInfo | **MISSING** |
| 11 | `ed25519_sign_verify` | `ed25519_sign_verify_cross` | `ed25519-dalek` verifies signature | ✓ |
| 12 | `curve25519_dh` | `curve25519_x25519_ecdh_cross` | two keys → same shared secret | ✓ |
| 13 | `rsa_sign_verify` | `rsa_round_trip` | `rsa` crate verifies signature | ✓ |
| 14 | `mldsa_sign_verify` (feat) | `mldsa_round_trip` | independent ML-DSA ref impl verifies | ✓ |
| 15 | `aes_gcm_roundtrip` | `aes_gcm_nist_empty_plaintext` | NIST vector + decrypt matches | ✓ |
| 16 | `sha256_known_vector` | `sha256_nist_abc` | NIST SHA-256 vector | ✓ |
| 17 | `cmac_known_vector` | `cmac_nist_empty_message` | NIST CMAC test vector | ✓ |
| 18 | `cryptocb_routes_to_hsm` | `cryptocb_register_lifecycle` | register guard, wolfcrypt call with WH_DEV_ID succeeds; drop guard, same call fails | ✓ |
| 19 | `signer_trait_ecc` | — | `EccP256Key::signer()` satisfies `signature::Signer` bound | **MISSING** |
| 20 | `signer_trait_ed25519` | — | `Ed25519Key::signer()` satisfies `signature::Signer` bound | **MISSING** |

### Simulator setup

```bash
cd ~/GIT/wolfHSM
make wh_server_sim
./wh_server_sim &
export WOLFHSM_SERVER="127.0.0.1:8080"
cargo test -p wolfhsm
```

---

## Key constraints and gotchas

1. **`Client` is `!Send + !Sync`** — `RefCell<Box<whClientContext>>` is `!Sync`. Users
   wrap in `Mutex<Client>` + `spawn_blocking` for async contexts.

2. **`RefCell` enables `&self` in `Signer` impls** — `signature::Signer::try_sign` takes
   `&self`. Since `Client` uses `RefCell` internally, all HSM calls go through a runtime
   borrow that panics on reentrance rather than causing UB.

3. **`WH_NVM_LABEL_LEN = 24`** — enforce before any round-trip. Return
   `Error::LabelTooLong { max: 24 }` immediately.

4. **NVM overwrite semantics** — `NvmAddObject` does not replace existing objects; it
   adds a new version. `nvm::write` must call `NvmDestroyObjects` on the old ID first.

5. **NVM scan termination** — `wh_Client_NvmList` returns `WH_ERROR_NOTFOUND` when no
   more objects exist. This is a normal loop-termination condition, not an error.

6. **Transport struct lifetimes** — C transport config structs must outlive
   `whClientContext`. Both are stored in `Client` via `_transport: Box<dyn Any>`.

7. **Ed25519Sign extra args** — `wh_Client_Ed25519Sign` takes `type`, `context`,
   `contextLen`. Pass `0, ptr::null(), 0` for standard Ed25519 (no pre-hashing, no
   context). The Rust FFI declaration must include all five arguments.

8. **wolfSSL feature requirements** — the linked wolfSSL must have at minimum:
   `HAVE_ECC`, `HAVE_ED25519`, `HAVE_CURVE25519`, `NO_RSA=0`, `WOLF_CRYPTO_CB`.
   Verify against `wolfssl-src/user_settings.h`.

9. **CryptoCb is global state** — `wc_CryptoCb_RegisterDevice` writes to a global
   wolfcrypt table. Use an `AtomicBool` in `cryptocb.rs` to reject double-registration
   at runtime and return `Error::BadArgs`.

10. **`std::env::set_var` is unsafe in Rust 2024+** — wolfhsm-sys/build.rs uses
    `unsafe { env::set_var(...) }` to propagate wolfSSL paths to wolfhsm-src. This is
    safe in build scripts (single-threaded), but must be wrapped in `unsafe {}` explicitly.

11. **Source file `wh_message.c` does not exist** — source files are individually named
    (`wh_message_comm.c`, `wh_message_crypto.c`, etc.). Do not add a `wh_message.c` entry.
