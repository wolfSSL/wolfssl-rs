# wolfssl-rs

Rust bindings and cryptographic trait implementations for
[wolfSSL](https://www.wolfssl.com/)/wolfCrypt.

This workspace provides two API surfaces over the same wolfCrypt C library,
plus supporting crates for SSH key handling, DPE integration, and testing.

## Crate map

### Crypto backends (pick one per ecosystem)

| Crate | Exports as | Target ecosystem | API style |
|-------|-----------|-----------------|-----------|
| `wolfcrypt-ring-compat` | `ring` | rustls, anything that depends on `ring` | Drop-in ring v0.16 replacement via `[patch]` |
| `wolfcrypt` | `wolfcrypt` | RustCrypto trait ecosystem (`digest`, `signature`, `aead`, etc.) | Native RustCrypto trait impls |

Both are needed: `wolfcrypt-ring-compat` serves rustls and the ring ecosystem,
`wolfcrypt` serves crates that program against RustCrypto traits.

### FFI / build chain

```
wolfSSL C source
    │
    ▼
wolfssl-src          Compiles wolfSSL from source via cc
    │
    ▼
wolfcrypt-sys        Runs bindgen, emits cargo:rustc-cfg flags
    │                (links = "wolfcrypt_sys")
    ▼
wolfcrypt-rs         Low-level Rust wrapper + C shim for struct accessors
    │                (links = "wolfssl")
    ▼
wolfcrypt            Safe RustCrypto trait impls (digest, aead, signature, ...)
wolfcrypt-ring-compat  Ring-compatible API surface
```

Metadata flows through Cargo's `links` system:
`wolfcrypt-sys` emits `DEP_WOLFCRYPT_SYS_*` env vars (include paths, cfg flags,
library locations), which `wolfcrypt-rs` reads and re-exports as `DEP_WOLFSSL_*`
for downstream consumers.

### Application crates

| Crate | Purpose |
|-------|---------|
| `ssh-key-wolfcrypt` | Fork of RustCrypto `ssh-key` with wolfCrypt backend. Drop-in replacement (exports as `ssh_key`). |
| `wolfcrypt-dpe` | Caliptra DPE `Crypto` trait impl backed by wolfCrypt. For hardware root-of-trust. |
| `wolfcrypt-wrapper` | Simplified wolfCrypt wrapper (alternative to `wolfcrypt-ring-compat`). |

### Upstream git dependencies

`ssh-key-wolfcrypt` depends on pre-release RustCrypto SSH crates (`ssh-encoding`
and `ssh-cipher` 0.3.0-rc.8) that are not yet on crates.io. These are pulled
via git tags from `https://github.com/RustCrypto/SSH` and patched in the
workspace `Cargo.toml`. Switch to crates.io deps once upstream publishes
stable 0.3 releases.

### Test crates

| Crate | What it tests |
|-------|--------------|
| `wolfcrypt-conformance` | Cross-validates wolfcrypt against pure-Rust RustCrypto, NIST CAVP vectors, and Wycheproof. |
| `wolfcrypt-ring-testing` | Integration tests for the ring-compatible API. |
| `wolfcrypt-dpe-conformance` | Cross-validates wolfcrypt-dpe against the caliptra-dpe reference implementation. |
| `links-testing` | Validates the cargo metadata propagation chain. |
| `builder-test` | Tests build script modules as a library. |

## Building

```sh
# Default: compiles wolfSSL from vendored source
cargo build

# Run the conformance test suite (most wolfcrypt tests live here)
cargo test -p wolfcrypt-conformance

# Run all tests
cargo test --workspace
```

wolfSSL source discovery (in priority order):
1. `WOLFSSL_LIB_DIR` + `WOLFSSL_INCLUDE_DIR` env vars (pre-built)
2. `WOLFSSL_DIR` env var (install prefix)
3. `vendored` feature on `wolfcrypt-sys` (default: compile from source)
4. `pkg-config`

## FIPS 140-3

These crates expose a `fips` feature flag that enables the wolfSSL FIPS 140-3
code path. **Enabling this feature alone does not give you a FIPS 140-3
validated build.** FIPS 140-3 validation requires:

1. A wolfSSL commercial FIPS license (contact wolfssl.com/license).
2. The specific wolfSSL source tree that was submitted for validation — not an
   arbitrary checkout. The validated source is provided by wolfSSL under the
   commercial license.
3. No modifications to the FIPS cryptographic boundary code.
4. The FIPS self-test (`wc_RunAllCast()`) must pass at startup.

Without a commercial license and the validated source, enabling `fips` builds
against unvalidated code. The MIT license on these Rust crates does not grant
any FIPS compliance rights; those come from wolfSSL Inc. exclusively.

## License

All wolfcrypt crates are licensed under MIT. See individual crate directories
for license files.

`ssh-key-wolfcrypt`, `ssh-encoding`, and `ssh-cipher` are licensed under
Apache-2.0 OR MIT (inherited from upstream RustCrypto).

The underlying wolfSSL C library has its own license terms (GPLv2+ with
commercial licensing available).
