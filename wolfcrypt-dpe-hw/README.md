# wolfcrypt-dpe-hw

Caliptra 2.x hardware backend for [`wolfcrypt-dpe`](../wolfcrypt-dpe).
Wires Caliptra silicon accelerators into wolfCrypt via the CryptoCb
callback mechanism. Not published (`publish = false`).

## Why

`wolfcrypt-dpe` provides the Caliptra DPE Crypto trait in pure software.
On Caliptra silicon, the actual cryptographic work should be performed by
the dedicated hash, AES, ECC-384, and ITRNG hardware accelerators.
`wolfcrypt-dpe-hw` is the bridge:

- **Hardware acceleration on silicon** — SHA-256/384/512, HMAC-384,
  AES-256-GCM/CBC, ECDSA/ECDH P-384, and ITRNG dispatch through the
  Caliptra hardware engines via [`caliptra-drivers`](https://github.com/chipsalliance/caliptra).
- **FIPS 140-3 boundary** — on `riscv32` Caliptra silicon, this crate
  establishes the boundary that connects the wolfCrypt software boundary
  to the Caliptra hardware boundary via `wc_CryptoCb_RegisterDevice`. See
  [`FIPS_BOUNDARY.md`](FIPS_BOUNDARY.md) for the full algorithm table and
  testing-gap disclosure.
- **Host cross-validation** — on non-RISC-V targets, dispatch goes
  through RustCrypto crates (`sha2`, `hmac`, `aes`, `ghash`, `cbc`,
  `p384`) instead of the Caliptra emulator. This path is for integration
  testing and conformance vectors only; **the host build is NOT a FIPS
  boundary**.

## Usage

```toml
[dependencies]
wolfcrypt-dpe-hw = { path = "../wolfcrypt-dpe-hw", features = ["caliptra-2x"] }
wolfcrypt-dpe = { path = "../wolfcrypt-dpe" }
```

```rust
use wolfcrypt_dpe::WolfCryptDpe;
use wolfcrypt_dpe_hw::{init, HW_DEVICE_ID};

// Register the CryptoCb device (idempotent; triggers wolfCrypt FIPS POST).
init().expect("hw backend init failed");

// All RNG calls now route through the Caliptra ITRNG.
let mut dpe = WolfCryptDpe::new_with_rng_dev_id(HW_DEVICE_ID);
```

Without the `caliptra-2x` feature, `init()` is a no-op and every dispatch
counter stays at zero. The `has_caliptra_hw_backend()` const-fn lets
tests check this without touching wolfSSL internals.

## How it works

```text
wolfcrypt-dpe                 (caliptra_dpe::Crypto trait impl)
        │
        │   wc_*_ex(..., devId = HW_DEVICE_ID)
        ▼
wolfCrypt CryptoCb dispatch table
        │
        │   hw_callback(info)  ← registered by init()
        ▼
wolfcrypt-dpe-hw              ← this crate
   │
   ├─ riscv32 Caliptra silicon target
   │      └─ caliptra-drivers (hash / AES / ECC-384 / ITRNG hardware regs)
   │
   └─ non-riscv32 host target
          └─ RustCrypto (sha2 / hmac / aes / ghash / cbc / p384)
             — NOT a FIPS boundary; cross-validation only
```

`init()` calls `wolfCrypt_Init` (idempotent; runs the FIPS power-on
self-test in FIPS builds) then `wc_CryptoCb_RegisterDevice(HW_DEVICE_ID,
hw_callback, NULL)`. The callback dispatches:

- `WC_ALGO_TYPE_HASH` → `hw_hash::dispatch_hash`
- `WC_ALGO_TYPE_HMAC` → `hw_hash::dispatch_hmac`
- `WC_ALGO_TYPE_CIPHER` → `hw_aes::dispatch_cipher`
- `WC_ALGO_TYPE_PK` → `hw_pk::dispatch_pk`
- `WC_ALGO_TYPE_RNG` → `hw_rng::dispatch_rng`
- everything else → `CRYPTOCB_UNAVAILABLE` (-271), causing wolfCrypt to
  fall through to its software path

Per-algorithm dispatch counters (`hw_dispatch_count`,
`aes_dispatch_count`, `ecc_dispatch_count`, `mldsa_dispatch_count`,
`trng_dispatch_count`) are exposed for FIPS dispatch evidence and are
used by the integration tests in `tests/`.

| Feature | Description |
|---|---|
| `caliptra-2x` | Master gate — enables all hardware paths and pulls in `caliptra-drivers` (riscv32) or RustCrypto host implementations (non-riscv32) |
| `cryptocb-only` | (Documentation flag) Enable on `wolfcrypt-dpe` instead — propagates a wolfSSL build with only CryptoCb infrastructure |
| `cryptocb-pure` | Minimum-footprint wolfSSL build for CryptoCb routing only; use when `wolfcrypt-dpe-hw` is the sole consumer of `wolfcrypt-sys` |
| `mldsa87-hw` | ML-DSA-87 hardware dispatch via Adams Bridge — off by default, gated until wire-format compatibility is verified |
| `testing-hooks` | **FIPS-DISQUALIFYING.** Exposes `INJECT_TRNG_ERROR`, which disables the entropy source. Production builds must NOT enable this feature. Used only by integration tests for fault injection. |

### FIPS-relevant constraints (excerpt)

The full disclosure is in [`FIPS_BOUNDARY.md`](FIPS_BOUNDARY.md). Two
constraints worth flagging here:

- **ITRNG opt-in is explicit.** `wc_InitRng(&rng)` (no devId) bypasses
  the boundary and uses wolfSSL's software DRBG. ITRNG dispatch requires
  `wc_InitRng_ex(&rng, NULL, HW_DEVICE_ID)` or, from `wolfcrypt-dpe`,
  `WolfCryptDpe::new_with_rng_dev_id(HW_DEVICE_ID)`.
- **Single in-flight SHA context.** `hw_hash` discards prior partial
  state if two SHA contexts are interleaved on the same `HW_DEVICE_ID`.
  Caliptra firmware is single-threaded and wolfSSL does not interleave,
  so this is safe in the firmware usage pattern but must be disclosed
  for any other deployment.

## References

- [wolfcrypt-dpe](../wolfcrypt-dpe) — DPE Crypto trait implementation
  consumed by this hardware backend
- [wolfcrypt-dpe-conformance](../wolfcrypt-dpe-conformance) —
  cross-validation tests against the RustCrypto reference backend
- [Caliptra](https://github.com/chipsalliance/caliptra) — Caliptra 2.x
  driver and silicon project
- [`FIPS_BOUNDARY.md`](FIPS_BOUNDARY.md) — full FIPS module-boundary
  statement, algorithm coverage table, testing gaps, and open issues
- [`audit/`](audit/) — security review and audit artefacts for this crate
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
