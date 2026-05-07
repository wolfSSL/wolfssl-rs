# wolftpm-tss

wolfTPM backend for the [tpm-rs](https://github.com/tpm-rs/tpm-rs) TSS
(Trusted Software Stack) Rust ecosystem. Implements
`tpm2_rs_client::connection::Connection` so that any Rust code built
against the tpm-rs client stack can use a hardware TPM or software TPM
simulator via wolfTPM.

## Why

This repository provides two complementary ways to program against
wolfTPM from Rust, mirroring how `wolfcrypt` offers both its own API
and RustCrypto traits:

- **Standalone wolfTPM API** — the [`wolftpm`](../wolftpm) crate
  exposes the full wolfTPM2_* feature set as an idiomatic Rust API.
- **tpm-rs `Connection` trait** — this crate plugs wolfTPM into the
  tpm-rs ecosystem so libraries written against tpm-rs can use a
  wolfTPM transport without code changes.

[tpm-rs](https://github.com/tpm-rs/tpm-rs) is a TCG-chartered project
maintained by engineers from Microsoft, Google, and Huawei. Its
`Connection` trait is the closest thing to a standard Rust TPM
interface; implementing it makes wolfTPM usable as a transport backend
for any library in the tpm-rs ecosystem.

| Type | Transport |
|---|---|
| `WolfTpmLinuxDev` | Linux kernel TPM driver (`/dev/tpm0` or `/dev/tpmrm0`) |
| `WolfTpmSwtpm` | Software TPM TCP socket (swtpm, IBM simulator) — requires the `swtpm` feature |

Both types implement `tpm2_rs_client::connection::Connection` when the
`tss` feature is enabled.

## Usage

```toml
[dependencies]
wolftpm-tss = { version = "0.2", features = ["tss", "linux-dev"] }
tpm2-rs-client = { git = "https://github.com/tpm-rs/tpm-rs", rev = "a7bf0e9126bab6c607a27a30e2f3df65f7e95371" }
tpm2-rs-base   = { git = "https://github.com/tpm-rs/tpm-rs", rev = "a7bf0e9126bab6c607a27a30e2f3df65f7e95371" }
```

The `tss` feature is required for the `Connection` trait
implementations; without it the transport types can be constructed but
cannot be passed to tpm-rs functions. `tpm2-rs-client` and
`tpm2-rs-base` are not yet published on crates.io, so a git revision
that matches the one pinned in this crate's `Cargo.toml` must be used.

```rust
use wolftpm_tss::connection::WolfTpmLinuxDev;
use tpm2_rs_client::run_command;
use tpm2_rs_base::commands::GetRandomCmd;

let mut transport = WolfTpmLinuxDev::open()?;
let resp = run_command(&GetRandomCmd { bytes_requested: 32 }, &mut transport)?;
```

Build prerequisites (wolfTPM source and wolfSSL headers) are documented
in [`wolftpm-src`](../wolftpm-src).

## How it works

```text
cmd: &[u8]
   │
   │ Connection::transact
   ▼
do_transact ──► wolftpm_rs_transact (C shim in wolftpm-sys)
                  │
                  │ XMEMCPY into dev->ctx.cmdBuf
                  ▼
                RS_SEND_COMMAND
                  (TPM2_LINUX_SendCommand or TPM2_SWTPM_SendCommand,
                   selected by wolfTPM transport #ifdef chain)
                  │
                  │ parse big-endian u32 totalSize at cmdBuf[2..6]
                  │ XMEMCPY response bytes back into rsp
                  ▼
                rsp_sz_out
   │
   ▼
Ok(&mut rsp[..n])
```

`Connection::transact` delegates to `do_transact`, which calls
`wolftpm_rs_transact` — a small C shim compiled into
[`wolftpm-sys`](../wolftpm-sys). The shim copies the tpm-rs command
bytes into wolfTPM's internal `cmdBuf`, dispatches via the
`RS_SEND_COMMAND` macro (resolved to the configured transport at link
time, mirroring wolfTPM's own `tpm2.c` `#ifdef` chain), reads the
response length from the big-endian `u32` at bytes 2–5 of the TPM2
response header, and copies that many bytes into the caller's `rsp`
buffer. `TPM_RC_SIZE` from the shim is mapped to
`Error::ResponseBufferTooSmall`.

The shim accesses `dev->ctx.cmdBuf` directly (a wolfTPM internal field)
because `wolfTPM2_Init` with the Linux device or swtpm transport sets
`ioCb = NULL` — wolfTPM manages the I/O itself without exposing a
callback. Going through the shim bypasses the high-level session and
parameter-encryption processing in `TPM2_SendCommand`; the tpm-rs
client stack handles its own command marshalling and sessions.
Compile-time `_Static_assert`s in the shim guard against unexpected
layout changes in `WOLFTPM2_DEV` / `TPM2_CTX`.

`WolfTpmSwtpm::connect` delegates to the shared `init_swtpm` helper in
[`wolftpm-sys`](../wolftpm-sys), the same helper used by
`wolftpm::Device::open_swtpm`. A process-wide mutex serialises
concurrent calls so that two threads do not corrupt each other's
`SWTPM_SERVER_NAME` / `SWTPM_SERVER_PORT` environment variables; this
mutex does not protect against unrelated threads that read or write
those variables outside this API.

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport; enables `WolfTpmSwtpm` |
| `tss` | Enable `Connection` trait impls (pulls in `tpm2-rs-client` / `tpm2-rs-base` git deps) |

## References

- [wolftpm](../wolftpm) — standalone wolfTPM Rust API
- [wolftpm-sys](../wolftpm-sys) — raw FFI bindings (hosts the `wolftpm_rs_transact` shim)
- [wolftpm-src](../wolftpm-src) — vendored wolfTPM source build
- [tpm-rs repository](https://github.com/tpm-rs/tpm-rs)
- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [wolfTPM API documentation](https://wolfssl.github.io/wolfTPM/)
- [TCG TPM2 Library Specification Part 3: Commands](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm](https://github.com/stefanberger/swtpm)
- [workspace README](../README.md)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfTPM C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
