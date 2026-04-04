# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Rust workspace providing bindings to wolfSSL/wolfCrypt. There are two API surfaces:
- **wolfcrypt**: RustCrypto trait implementations (digest, aead, cipher, signature, etc.) backed by wolfCrypt
- **wolfcrypt-ring-compat**: Drop-in `ring` v0.16 replacement via `[patch]`

The workspace also contains Caliptra hardware integration crates for RISC-V firmware.

## Tech Stack

- Language: Rust (edition 2021; `wolfcrypt-wrapper` uses 2024)
- MSRV: 1.71.0 (core crates: `wolfcrypt-rs`, `wolfcrypt`)
- C layer: wolfSSL/wolfCrypt (compiled via `cc` crate or linked as pre-built)
- `no_std + alloc`: `wolfcrypt`, `wolfcrypt-dpe`, `wolfcrypt-dpe-hw`

## Build & Library Discovery

wolfSSL discovery order (controlled by `wolfcrypt-sys/build.rs`):
1. `WOLFSSL_LIB_DIR` + `WOLFSSL_INCLUDE_DIR` (pre-built, split paths)
2. `WOLFSSL_DIR` (install prefix, default from `.cargo/config.toml`: `~/wolfssl-install`)
3. `vendored` feature / `WOLFSSL_SRC` env — compiles wolfSSL from source via `wolfssl-src`
4. pkg-config

The pre-built install at `~/wolfssl-install` must have `HAVE_DILITHIUM` and `WOLF_CRYPTO_CB` enabled. The source tree at `~/wolfssl` is used for vendored/bare-metal builds.

## Commands

```bash
# Build (workspace)
cargo build

# Test a single crate
cargo test -p wolfcrypt --all-targets
cargo test -p wolfcrypt-conformance

# Test with both debug and release (as done in CI)
cargo test --all-targets
cargo test --release --all-targets

# Lint
cargo +nightly clippy --all-targets -- -W clippy::all -W clippy::pedantic

# Caliptra hardware tests (requires caliptra sw-emulator)
cargo test-caliptra                  # alias: test -p wolfcrypt-dpe-hw --features caliptra-2x,testing-hooks
cargo test-caliptra-mldsa            # includes mldsa87-hw feature

# RISC-V firmware build (bare-metal, cross-compiled via zig cc)
cargo build-caliptra-fw              # alias: build -p wolfcrypt-dpe --features cryptocb-only --target riscv32imc-unknown-none-elf
cargo build-caliptra-hw-pure         # alias: build -p wolfcrypt-dpe-hw --features caliptra-2x,cryptocb-pure

# Hardware conformance binary
cargo conformance-caliptra           # alias: run -p wolfcrypt-conformance --bin caliptra_hw_conformance --features wolfcrypt-conformance/caliptra-hw
```

## Crate Architecture

```
wolfssl-src         Compiles wolfSSL C source (cc crate); selects user_settings.h per feature
      ↓
wolfcrypt-sys       FFI bindings (bindgen); emits 60+ cfg flags (wolfssl_aes_gcm, wolfssl_ecc_p384, …)
      ↓
wolfcrypt-rs        Low-level Rust wrapper + compat_shim.c; re-exports metadata via `links = "wolfssl"`
      ↓
├── wolfcrypt           RustCrypto trait impls (no_std + alloc)
├── wolfcrypt-ring-compat  Drop-in ring replacement (published as `ring` via [patch])
├── wolfcrypt-dpe       Caliptra DPE crypto trait impl (no_std + alloc)
└── wolfcrypt-dpe-hw    Caliptra hardware backend; CryptoCb dispatch to caliptra-drivers
```

`wolfcrypt-conformance` is the primary test crate: NIST CAVP vectors, Wycheproof, and cross-validation against pure-Rust RustCrypto implementations.

## Feature Flag System

`wolfssl-src` features select which `user_settings.h` is compiled:
- *(default)*: full-featured build (OpenSSL compat, all algorithms, WOLF_CRYPTO_CB)
- `cryptocb-only`: CryptoCb dispatch only; software stubs compiled but all calls dispatched to callbacks; excludes SP math
- `cryptocb-pure`: absolute minimum — CryptoCb + type defs, no OPENSSL_EXTRA/HKDF/ASN; intended for pure HW routing
- `riscv-bare-metal`: bare-metal platform stubs, no stdio/pthread

`wolfcrypt-sys` parses the compiled wolfSSL defines and emits corresponding `rustc-cfg` flags (e.g. `wolfssl_aes_gcm`, `wolfssl_dilithium`). Downstream crates gate code on these cfg flags.

`wolfcrypt` exposes 60+ Cargo features, one per algorithm/trait group. `require-dev-id` removes the software `WolfRng::new()` path, forcing CryptoCb hardware device ID usage.

## Metadata Propagation

Cargo's `links` mechanism carries build metadata across crate boundaries:
- `wolfcrypt-sys` (links = `wolfcrypt_sys`) → emits `DEP_WOLFCRYPT_SYS_{CFGS,INCLUDE,ROOT,VERSION,…}`
- `wolfcrypt-rs` (links = `wolfssl`) → re-exports as `DEP_WOLFSSL_*` for `wolfcrypt-ring-compat` and others
- Downstream build scripts read these via `env!("DEP_…")` to avoid redundant discovery

## Conventions

- Cargo features are additive and map 1:1 to algorithm groups; never enable an algorithm unconditionally in `Cargo.toml` — gate it behind a feature.
- `wolfcrypt-sys` cfg flags (`wolfssl_*`) are the source of truth for what the linked wolfSSL supports; use them to `#[cfg]`-gate code rather than duplicating Cargo feature checks.
- All `unsafe` blocks must be in `wolfcrypt-rs` or `wolfcrypt-sys`; higher-level crates (`wolfcrypt`, `wolfcrypt-dpe`) must be safe Rust.
- Workspace resolver v2 is required; do not change to v1.

## Test Design Constraint

Tests must use an independent oracle: known test vectors from an external source (NIST CAVP, Wycheproof) or cross-validation between wolfcrypt and a pure-Rust RustCrypto implementation. Do not write tests that encrypt with wolfcrypt and decrypt with wolfcrypt — that proves nothing.

## Key External Dependencies

- `~/wolfssl` — wolfSSL C source tree (must be checked out separately)
- `~/wolfssl-install` — pre-built wolfSSL with `HAVE_DILITHIUM` + `WOLF_CRYPTO_CB`
- `../../caliptra/` — caliptra repo (sibling) for `caliptra-drivers` and sw-emulator
- RISC-V cross-compiler: `.cargo/riscv32-cc` (zig cc wrapper, committed)

## Version Constraints

RustCrypto trait versions are pinned: `digest 0.10`, `cipher 0.4`, `aead 0.5`, `signature 2.2`. Upgrades are blocked on the upstream `generic-array → hybrid-array` migration (digest 0.11, cipher 0.5). Do not bump these without checking the full trait migration chain.

Several git dependencies (caliptra-dpe, ssh-encoding/ssh-cipher) are pinned to exact commits because they are not yet published to crates.io.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
