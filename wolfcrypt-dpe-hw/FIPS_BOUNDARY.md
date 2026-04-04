# FIPS Module Boundary — wolfcrypt-dpe-hw

## 1. Module Boundary Statement

**This document describes two distinct compilation targets. They have different
module boundaries. Do not conflate them.**

### Host / non-riscv32 build (`--features caliptra-2x`, `target_arch != riscv32`)

On this target, the cryptographic algorithms execute entirely in **RustCrypto
software crates** (`sha2`, `hmac`, `aes`, `ghash`, `cbc`, `p384`). No
caliptra-drivers hardware registers are accessed during algorithm dispatch.
The `CaliptraRootBus` sw-emulator is instantiated in integration tests for
infrastructure testing only; it is not invoked by any of the dispatch
functions (`hw_hash.rs`, `hw_aes.rs`, `hw_pk.rs`).

**This build is NOT a FIPS boundary.** It is used for host-side integration
testing and conformance vector verification only.

### RISC-V / Caliptra silicon build (`--features caliptra-2x`, `target_arch = riscv32`)

On this target, the intended FIPS boundary extends to include the Caliptra 2.x
hardware accelerators accessible via caliptra-drivers.  The software boundary
(wolfCrypt) and hardware boundary (Caliptra silicon) are connected through the
wc_CryptoCb mechanism.

The boundary is established at registration time by `wolfcrypt_dpe_hw::init()`,
which calls `wc_CryptoCb_RegisterDevice(HW_DEVICE_ID, hw_callback, NULL)`.
All wolfCrypt operations initiated with `devId = HW_DEVICE_ID` pass through
`hw_callback` and are dispatched to the Caliptra hardware.

**Note:** any operation initiated with `INVALID_DEVID` (for example, via
`wc_InitRng` without an explicit devId) bypasses the boundary entirely and
uses wolfSSL's internal software DRBG. Callers must use
`wc_InitRng_ex(&rng, NULL, HW_DEVICE_ID)` for ITRNG dispatch to be active.

This riscv32/Caliptra silicon build is the build subject to FIPS 140-3
evaluation. The host build is not.

---

## 2. Algorithm Table

The table below covers both compilation paths.  The "Non-riscv32 host
implementation" column shows what actually executes today (for testing).
The "riscv32 Caliptra implementation" column shows the intended production
implementation (pending silicon certification).

| Algorithm   | Non-riscv32 host implementation | riscv32 Caliptra implementation | FIPS 140-3 approved? | Notes |
|-------------|--------------------------------|---------------------------------|----------------------|-------|
| SHA-256     | RustCrypto `sha2` crate        | caliptra-drivers hash engine    | Yes (FIPS 180-4) | Dispatch via `dispatch_hash` |
| SHA-384     | RustCrypto `sha2` crate        | caliptra-drivers hash engine    | Yes (FIPS 180-4) | Dispatch via `dispatch_hash` |
| SHA-512     | RustCrypto `sha2` crate        | caliptra-drivers hash engine    | Yes (FIPS 180-4) | Dispatch via `dispatch_hash` |
| HMAC-384    | RustCrypto `hmac` + `sha2`     | caliptra-drivers hash engine    | Yes (FIPS 198-1) | Dispatch via `dispatch_hmac`; KAT uses RFC 4231 TC1 hardcoded vector |
| AES-256-GCM | RustCrypto `aes` + `ghash`     | caliptra-drivers AES engine     | Yes (FIPS 197, SP 800-38D) | Dispatch via `dispatch_cipher` |
| AES-256-CBC | RustCrypto `cbc` crate         | caliptra-drivers AES engine     | Yes (FIPS 197, SP 800-38A) | Dispatch via `dispatch_cipher` |
| ECDSA P-384 | RustCrypto `p384` crate        | caliptra-drivers Ecc384         | Yes (FIPS 186-4) | Dispatch via `dispatch_pk` |
| ECDH P-384  | RustCrypto `p384` crate        | caliptra-drivers Ecc384         | Yes (SP 800-56A) | Dispatch via `dispatch_pk`; riscv32 path deferred |
| ITRNG/RNG   | OS entropy via `wc_GenerateSeed` (non-riscv32: `/dev/urandom`) | caliptra-drivers ITRNG via `caliptra_hw_generate_seed` | Yes (SP 800-90B, SP 800-90A CTR-DRBG seeding) | Dispatch via `dispatch_rng` (non-riscv32) or `caliptra_seed.c` shim (riscv32) |
| ML-DSA-87   | Stub — returns `CRYPTOCB_UNAVAILABLE` | Stub — not yet implemented | Conditional (FIPS 204) | Wire-format compatibility with Adams Bridge not yet verified; see Section 5 |

---

## 3. Testing Gaps

### What the sw-emulator does NOT test

The Caliptra sw-emulator (`caliptra-emu-periph` / `CaliptraRootBus`) exercises
the hardware register interface at the Rust API level.  It does NOT test:

- **Side-channel resistance**: timing attacks, power analysis, electromagnetic
  emanations are hardware properties not observable in simulation.
- **Power analysis**: simple/differential power analysis (SPA/DPA) requires
  silicon-level measurements.
- **Silicon timing**: the emulator runs on host-CPU clocks; real silicon latency
  and timing jitter are not modelled.
- **Physical tamper response**: Caliptra's tamper-detection and key-zeroization
  circuitry are silicon-only features.
- **True entropy quality**: the sw-emulator's ITRNG returns pseudo-random bytes,
  not entropy from a physical noise source.

**Requires real silicon or FPGA for full FIPS 140-3 testing**:
- Entropy source quality testing (NIST SP 800-90B)
- Conditional algorithm self-tests (CAST) on actual hardware
- Physical security testing (Levels 3–4)

### ITRNG bypass in TLS simulation test

`test_full_tls_handshake_simulation` (`phase5_integration.rs`) calls
`wc_InitRng(&mut rng)` without a `devId` argument.  This uses `INVALID_DEVID`
internally and routes RNG calls through wolfSSL's internal software DRBG.
`TRNG_DISPATCH_COUNT` does not increment during this test.  The ITRNG dispatch
path is exercised separately in `phase2_rng.rs` tests 1–5.  A FIPS submission
must document this: the TLS simulation test does not exercise the approved
entropy source.

### Single hash context limitation

`hw_hash.rs` supports exactly one in-flight SHA context at a time.  If two SHA
contexts are interleaved on the same `HW_DEVICE_ID` (one context Update, then
another context Update before the first context Final), the first context's
partial state is silently discarded.  The Caliptra firmware is single-threaded
and wolfSSL does not interleave SHA contexts in the firmware usage pattern.
This constraint is documented in `hw_hash.rs` and must be disclosed in any
FIPS submission for deployments where concurrent SHA operations are possible.

### ML-DSA-87 wire-format status

Wire-format compatibility between wolfCrypt ML-DSA-87 and the Caliptra Adams
Bridge has not been confirmed.  ML-DSA-87 hardware dispatch remains a stub.
See Section 5 open issue 1.

---

## 4. Key Material Handling

- **Ephemeral keys only**: all ECC-384 key pairs generated by `hw_pk.rs` are
  ephemeral; key bytes are in process memory only and are not persisted.
- **No key vault integration**: Caliptra's hardware key vault (KV) is not yet
  wired into this layer.  Future phases will add `wc_ecc_import_key_from_kv()`
  or equivalent.
- **Key zeroization**: `test_key_material_zeroized` in `phase3_aes.rs` uses a
  stack scan heuristic to check that AES key bytes are cleared after use.
  This test provides heuristic evidence only; register allocation may prevent
  the key from appearing on the scanned stack region.  ECC key zeroization
  is handled by wolfCrypt's `wc_ecc_free()` and explicit `zeroize::Zeroize`
  calls on intermediate buffers in `hw_pk.rs`.
- **ITRNG seeding**: `hw_rng.rs` seeds wolfCrypt's DRBG from the ITRNG callback.
  The DRBG itself runs in software (CTR-DRBG per SP 800-90A) seeded from
  hardware entropy.  Callers must use `wc_InitRng_ex` with `HW_DEVICE_ID` for
  ITRNG dispatch to be active (see Section 1, ITRNG bypass note).

---

## 5. Open Issues

### TODO / FIXME / HACK scan — wolfcrypt-dpe-hw/src/

No TODO, FIXME, or HACK comments found in `wolfcrypt-dpe-hw/src/` at time of
this writing.

### Escalated issues — audit/

No `*_escalated.md` files exist in `audit/` at time of this writing.

### Known future work and open items

1. **ML-DSA-87 wire format** — `hw_pk.rs`: stub returns `CRYPTOCB_UNAVAILABLE`
   until cross-validation with Adams Bridge is performed.  The build flag
   `HAVE_DILITHIUM` is already enabled in the local wolfSSL build (see
   `.cargo/config.toml`, `WOLFSSL_DIR`).  The actual blocker is wire-format
   compatibility: the signature format used by caliptra-drivers Adams Bridge
   must be confirmed compatible with wolfCrypt ML-DSA-87 before hardware
   dispatch can be enabled.

2. **ECC riscv32 path** — `hw_pk.rs`: all ECC operations (ECDSA sign/verify and
   ECDH) on riscv32 bare-metal use caliptra-drivers Ecc384 hardware primitives.
   Integration with caliptra-drivers 2.x is deferred to a future phase.  None
   of the ECC dispatch functions are currently implemented for riscv32.

3. **Key vault integration** — `hw_pk.rs`: ephemeral key material is not stored
   in the Caliptra hardware key vault.  KV integration is required before
   long-term identity keys can be protected at FIPS Level 3.

4. **True RNG on riscv32** — `hw_rng.rs`: the ITRNG path on riscv32 calls
   `caliptra_drivers::Trng::generate()`.  Entropy quality certification per
   SP 800-90B requires hardware characterisation beyond what the sw-emulator
   provides.

5. **ECC invalid-curve attack mitigation** — `hw_pk.rs` (riscv32 path, future):
   when the riscv32 hardware ECC path is implemented, all public key inputs must
   be validated on-curve before being passed to `caliptra_drivers::Ecc384`. Off-
   curve public keys can be used to extract private key scalars via Pohlig-Hellman
   variants.  This check is required before any riscv32 ECC dispatch is enabled.

6. **HMAC-384 KAT source** — confirmed: `test_hmac384_nist_vector` uses a
   hardcoded RFC 4231 Test Case 1 vector (`const HMAC384_RFC4231_TC1: [u8; 48]`)
   as the expected value. The expected MAC is not computed at runtime from the
   implementation under test.  The FIPS CAVP/ACVTS KAT requirement (independent
   known-answer source) is satisfied.

7. **`ECC_DISPATCH_COUNT` semantics** — the counter increments on successful
   sign, successful verify, and successful ECDH.  It does NOT increment on
   `VERIFY_SIGN_ERROR` (verify failure).  Counter-based dispatch evidence will
   count fewer dispatches than total invocations when reject paths are exercised.
   This must be disclosed when using counters as FIPS dispatch proof.
