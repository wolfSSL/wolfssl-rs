# wolftpm

Safe Rust bindings to [wolfTPM](https://github.com/wolfSSL/wolfTPM), a
portable TPM 2.0 library from wolfSSL.

## Why

A Trusted Platform Module (TPM 2.0) is a hardware security chip present in
most modern PCs, servers, and embedded systems. wolfTPM is a compact,
portable C implementation of the TPM 2.0 client stack that works with
hardware TPMs (Linux kernel driver or SPI), the
[swtpm](https://github.com/stefanberger/swtpm) software TPM, the
[IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2/), and
bare-metal microcontrollers.

- **Hardware-bound keys** — RSA and ECC keys that never leave the chip
- **Attestation** — cryptographic proof of platform state via PCR quotes
- **Sealing** — encrypting data to a specific measured boot state
- **Random number generation** — hardware entropy source
- **NV storage** — small amounts of tamper-evident persistent storage
- **Small footprint** — wolfTPM depends only on wolfSSL for crypto and is
  much lighter than the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)
  reference stack (no DBUS, JSON, or OpenSSL dependencies); suitable for
  embedded and bare-metal targets
- **Idiomatic Rust** — RAII cleanup of `WOLFTPM2_DEV`, transient-key
  lifetimes expressed in the type system, typed `Error` variants for TPM
  return codes, and explicit `Send` analysis

## Usage

```toml
[dependencies]
wolftpm = "0.2"
```

```rust
use wolftpm::Device;

let mut dev = Device::open()?;                // /dev/tpm0 or /dev/tpmrm0

// Hardware random bytes
let random = dev.get_random(32)?;

// Read a PCR (SHA-256 bank, index 0)
let pcr: [u8; 32] = dev.pcr_read(0)?;

// Transient ECC P-256 signing key — flushed when the closure returns
dev.with_ecc_key(|key| {
    let sig = key.sign(&message_hash)?;       // SHA-256 digest in
    key.verify(&message_hash, &sig)?;
    Ok(())
})?;
```

`Device::open()` is always available. `Device::open_swtpm(host, port)`
requires the `swtpm` feature. Build prerequisites (wolfTPM source and
wolfSSL headers) are documented in [wolftpm-src](../wolftpm-src).

## How it works

```text
wolftpm-src     Compiles wolfTPM C source via the cc crate; generates
│               wolftpm/options.h; emits DEP_WOLFTPM_SRC_{INCLUDE,LIB}
│
wolftpm-sys     bindgen-generated FFI bindings; links libwolftpm.a and
│               libwolfssl
│
wolftpm         Safe high-level Rust API  ← this crate
```

`Device` wraps a heap-allocated `WOLFTPM2_DEV` and runs `wolfTPM2_Cleanup`
on drop. `EccKey<'dev>` borrows the device for the lifetime of a transient
P-256 signing key and unloads both the signing key and its storage root
key when dropped — even on panic. TPM return codes are mapped to typed
[`Error`] variants; `TpmRc` decodes the standard TPM2 result-code layers.

Transport selection happens in `wolftpm-src` at compile time. On Linux
with no feature selected, `WOLFTPM_LINUX_DEV` is the default so that
`Device::open()` works out of the box.

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport (swtpm / IBM TPM2 simulator); enables `Device::open_swtpm` |

The wolfSSL key-import/export helpers (`wolfTPM2_RsaKey_To_Device` etc.)
are compiled out for now (`-DWOLFTPM2_NO_WOLFCRYPT`). Advanced wolfTPM
features (NV storage, attestation, HMAC sessions) are not yet wrapped;
the [wolftpm-sys](../wolftpm-sys) raw bindings cover the full C API.

## References

- [wolftpm-sys](../wolftpm-sys) — raw FFI bindings (use these for APIs not yet wrapped here)
- [wolftpm-src](../wolftpm-src) — vendored wolfTPM source build
- [wolftpm-tss](../wolftpm-tss) — wolfTPM as a backend for the tpm-rs TSS ecosystem
- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [wolfTPM documentation](https://www.wolfssl.com/docs/wolftpm/)
- [wolfTPM API reference](https://wolfssl.github.io/wolfTPM/)
- [TCG TPM2 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfTPM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
