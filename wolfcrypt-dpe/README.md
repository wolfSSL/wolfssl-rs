# wolfcrypt-dpe

[Caliptra DPE](https://github.com/chipsalliance/caliptra-dpe) Crypto trait
implementation backed by wolfCrypt. No FFI — all crypto goes through the
safe Rust API of the [`wolfcrypt`](../wolfcrypt) crate.

> Not currently published to crates.io. The upstream
> `caliptra-dpe-crypto` trait crate is git-only as of caliptra-dpe
> fw-2.1.0; crates.io rejects published crates with git dependencies.
> Once chipsalliance publishes that crate, this one will follow.

## Why

DPE (DICE Protection Environment) is the
[CHIPS Alliance standard](https://github.com/chipsalliance/caliptra-dpe)
for layered cryptographic device identity. The reference implementation
ships with a RustCrypto-backed `Crypto` trait. `wolfcrypt-dpe` provides
the same trait backed by wolfSSL/wolfCrypt:

- **FIPS 140-3 path** — wolfCrypt is FIPS 140-3 validated; the RustCrypto
  reference backend is not. Required for Caliptra deployments that need a
  FIPS-validatable trust root ([contact wolfSSL](https://www.wolfssl.com/license/)).
- **Hardware dispatch** — the constructor `new_with_rng_dev_id` routes
  every `wc_RNG_GenerateBlock` call through a registered CryptoCb device
  (e.g. `wolfcrypt-dpe-hw`'s ITRNG), enforcing hardware entropy.
- **`no_std`** — runs on bare-metal RISC-V (Caliptra silicon target).
- **One crypto dependency** — only `wolfcrypt`; no parallel RustCrypto
  crate graph for SHA / HKDF / ECDSA / RNG.

## Usage

```toml
[dependencies]
wolfcrypt-dpe = { path = "../wolfcrypt-dpe" }
caliptra-dpe-crypto = { git = "https://github.com/chipsalliance/caliptra-dpe", rev = "<pinned>", package = "crypto", default-features = false }
```

Default (P-384 / SHA-384, software DRBG):

```rust
use wolfcrypt_dpe::WolfCryptDpe;
use caliptra_dpe_crypto::Crypto;

let mut dpe = WolfCryptDpe::new();
let mut nonce = [0u8; 32];
dpe.rand_bytes(&mut nonce)?;
```

P-256 / SHA-256 variant:

```rust
use wolfcrypt_dpe::WolfCryptDpe256;
let mut dpe = WolfCryptDpe256::new();
```

Hardware ITRNG (CryptoCb device registered by `wolfcrypt-dpe-hw`):

```rust
use wolfcrypt_dpe::WolfCryptDpe;
use wolfcrypt_dpe_hw::HW_DEVICE_ID;
let mut dpe = WolfCryptDpe::new_with_rng_dev_id(HW_DEVICE_ID);
```

When the `require-dev-id` feature is enabled, `WolfCryptDpe::new()` and
the software-DRBG path are removed entirely; only `new_with_rng_dev_id`
compiles. Use this on production firmware where software entropy is not
acceptable.

## How it works

```text
wolfcrypt-dpe                        ← this crate
   │
   ├─ impl caliptra_dpe_crypto::Crypto for WolfCryptDpeImpl<S, D>
   │     where S: SignatureType, D: DigestType
   │
   └─ wolfcrypt (safe Rust API only)
         ├─ digest, hkdf, ecdsa, rand
         └─ wolfcrypt-rs / wolfcrypt-sys / wolfssl-src
```

The implementation is parameterized by signature curve (`Curve256`,
`Curve384`) and digest (`Sha256`, `Sha384`). Type aliases
`WolfCryptDpe384` (default) and `WolfCryptDpe256` cover the two valid
combinations.

Trade-offs encoded in the implementation:

- **Cached alias signing key** — `set_alias_key` imports the EC key once
  and caches the wolfCrypt handle. Subsequent `sign_with_alias` calls
  skip EC point multiplication.
- **Lazy RNG** — `wc_InitRng_ex` (DRBG init + entropy reseed) runs on
  first random byte request, not at construction.
- **Constant-time CDI handle lookup** — `derive_key_pair_exported`
  iterates all slots without short-circuiting (`ct_eq`) so the access
  pattern does not leak which slot matched.
- **Zeroize on drop** — private key bytes are wiped via `Zeroize`; CDI
  bytes are wrapped in `Zeroizing<Vec<u8>>`.

| Feature | Description |
|---|---|
| `riscv-bare-metal` | Target the riscv32imc Caliptra firmware build (propagates to `wolfcrypt`) |
| `cryptocb-only` | Build wolfSSL with only CryptoCb callback infrastructure |
| `cryptocb-pure` | Minimal wolfSSL build for CryptoCb routing only (no OPENSSL_EXTRA / HKDF / ASN template) |
| `require-dev-id` | Remove the software DRBG path; only `new_with_rng_dev_id` compiles |

## References

- [caliptra-dpe](https://github.com/chipsalliance/caliptra-dpe) — DPE
  reference implementation and trait crate
- [DICE Protection Environment specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Protection-Environment-Specification_14february2023-1.pdf)
- [wolfcrypt](../wolfcrypt) — safe Rust API used for all crypto
- [wolfcrypt-dpe-hw](../wolfcrypt-dpe-hw) — Caliptra hardware backend that
  registers a CryptoCb device for hardware ITRNG / hash / AES / ECC dispatch
- [wolfcrypt-dpe-conformance](../wolfcrypt-dpe-conformance) — cross-validation
  tests against the RustCrypto reference backend
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
