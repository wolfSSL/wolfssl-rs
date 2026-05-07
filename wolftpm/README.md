# wolftpm

Safe Rust bindings to [wolfTPM](https://github.com/wolfSSL/wolfTPM), a portable
TPM 2.0 library from wolfSSL.

## What

`wolftpm` provides an idiomatic, safe Rust API for TPM 2.0 operations via
wolfTPM.  A Trusted Platform Module (TPM 2.0) is a hardware security chip
present in most modern PCs, servers, and embedded systems.  It provides:

- **Hardware-bound keys** — RSA and ECC keys that never leave the chip
- **Attestation** — cryptographic proof of platform state via PCR quotes
- **Sealing** — encrypting data to a specific measured boot state
- **Random number generation** — hardware entropy source
- **NV storage** — small amounts of tamper-evident persistent storage
- **Platform authentication** — policy-gated access to keys and objects

wolfTPM is a compact, portable C implementation of the TPM 2.0 client stack
that works with hardware TPMs (via Linux kernel driver or SPI), the
[swtpm](https://github.com/stefanberger/swtpm) software TPM, the
[IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/), and
bare-metal microcontrollers.

## Why

### Why wolfTPM over tss2-sys/tpm2-tss?

The [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) stack is the
reference Linux userspace implementation but is large, has many dependencies
(DBUS, JSON, OpenSSL), and is difficult to build for embedded or bare-metal
targets.

wolfTPM is self-contained, depends only on wolfSSL for crypto, compiles to a
small footprint (suitable for microcontrollers), and is designed for
portability.  The wolfTPM C API is straightforward to wrap in Rust.

### Why this crate over writing raw `unsafe` bindings yourself?

`wolftpm`:

- Ensure `WOLFTPM2_DEV` is properly initialised and cleaned up via RAII
- Express TPM object lifetimes in the Rust type system
- Translate TPM return codes to typed `Error` variants
- Provide `Send`/`Sync` analysis for multi-threaded use

## How it works

### Crate stack

```
wolftpm-src     Compiles wolfTPM C source via the cc crate; generates
│               wolftpm/options.h; emits DEP_WOLFTPM_SRC_{INCLUDE,LIB}
│
wolftpm-sys     bindgen-generated FFI bindings; links libwolftpm.a and
│               libwolfssl; excludes wolfSSL key-import helpers for now
│               (WOLFTPM2_NO_WOLFCRYPT)
│
wolftpm         Safe high-level Rust API (this crate)
```

### Transport selection

wolfTPM supports several transport backends, selected at compile time:

| Transport | Define | Description |
|---|---|---|
| Linux kernel driver | `WOLFTPM_LINUX_DEV` | `/dev/tpm0` or `/dev/tpmrm0` |
| Software TPM | `WOLFTPM_SWTPM` | TCP socket to swtpm/IBM simulator |
| SPI TIS | *(chip-specific)* | Direct SPI bus (embedded) |
| Windows | `WOLFTPM_WINAPI` | Windows TBS API |

The default on Linux (when no feature is selected) is `WOLFTPM_LINUX_DEV`.
Select `swtpm` for testing against a software TPM.

### wolfSSL integration

wolfTPM uses wolfSSL/wolfCrypt for RSA, ECC, and hash operations when it needs
to perform key operations locally (e.g. parameter encryption, key wrapping).
The current bindings use `-DWOLFTPM2_NO_WOLFCRYPT` to keep the generated FFI
self-contained.  Full wolfSSL integration (key import/export between wolfSSL
and TPM objects) will be added in a future version.

## How to use

```toml
[dependencies]
wolftpm = "0.1"
```

### Build requirements

wolfTPM source and wolfSSL headers must be available at build time.  The
simplest setup:

```sh
# Option 1: point to a local wolfTPM clone
export WOLFTPM_SRC=/path/to/wolfTPM
export WOLFSSL_DIR=/path/to/wolfssl-install
cargo build

# Option 2: use the bundled submodule
git submodule update --init wolftpm-src/wolftpm
export WOLFSSL_DIR=/path/to/wolfssl-install
cargo build
```

See [`wolftpm-src`](https://crates.io/crates/wolftpm-src) for the full set of
environment variables.

### Features

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport |

## API

```rust
use wolftpm::{Device, Error};

// Open a connection to the TPM
let mut dev = Device::open()?;                    // /dev/tpm0 or swtpm socket

// Hardware random bytes
let random = dev.get_random(32)?;

// Read a PCR (SHA-256 bank, index 0)
let pcr: [u8; 32] = dev.pcr_read(0)?;

// ECC P-256 signing key (transient, flushed on drop)
dev.with_ecc_key(|key| {
    let sig = key.sign(&message_hash)?;           // sha-256 digest
    key.verify(&message_hash, &sig)?;             // Err(SignatureInvalid) if it doesn't match
    Ok(())
})?;
```

## References

- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [wolfTPM documentation](https://www.wolfssl.com/docs/wolftpm/)
- [wolfTPM API reference](https://wolfssl.github.io/wolfTPM/)
- [TCG TPM2 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm — software TPM for testing](https://github.com/stefanberger/swtpm)
- [IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/)
- [wolfssl-rs workspace](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfTPM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
