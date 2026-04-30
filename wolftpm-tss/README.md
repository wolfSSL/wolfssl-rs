# wolftpm-tss

wolfTPM backend for the [tpm-rs](https://github.com/tpm-rs/tpm-rs) TSS
(Trusted Software Stack) Rust ecosystem.

## What

`wolftpm-tss` implements [`tpm2_rs_client::connection::Connection`] using
wolfTPM as the underlying transport.  This makes wolfTPM a drop-in backend
for any Rust code built against the tpm-rs client stack: call
`tpm2_rs_client::run_command` with a `WolfTpmLinuxDev` or `WolfTpmSwtpm`
transport and it works with a real TPM chip or a software simulator.

## Why

### Two complementary API surfaces

This repository provides two ways to program against wolfTPM from Rust,
mirroring how `wolfcrypt` offers both its own API and RustCrypto traits:

| Crate | Surface | Who it's for |
|---|---|---|
| [`wolftpm`](../wolftpm/) | Standalone wolfTPM API (wolfTPM2_* wrappers) | Code that wants the full wolfTPM feature set |
| `wolftpm-tss` *(this crate)* | tpm-rs `Connection` trait | Code written against the tpm-rs/TCG stack |

### Why tpm-rs?

[tpm-rs](https://github.com/tpm-rs/tpm-rs) is a TCG-chartered project
maintained by engineers from Microsoft, Google, and Huawei.  Its
`Connection` trait is the closest thing to a standard Rust TPM interface.
By implementing `Connection`, wolfTPM becomes usable as a transport backend
for any library in the tpm-rs ecosystem.

## How it works

### Connection::transact bridge

`Connection::transact` delegates to `wolftpm_rs_transact`, a thin C shim
compiled into `wolftpm-sys` that calls the wolfTPM transport layer directly.

The shim:
1. Copies the tpm-rs command bytes into wolfTPM's internal `cmdBuf`.
2. Dispatches to the configured transport (`RS_SEND_COMMAND` — either the
   Linux kernel TPM driver or the swtpm TCP socket path).
3. Reads the response length from bytes 2–5 of the TPM2 response header
   (big-endian `u32`, per TCG TPM2 Part 3).
4. Copies exactly that many bytes back into the caller's `rsp` buffer.

```text
cmd: &[u8]  ──copy──►  wolftpm cmdBuf
                                │
                         RS_SEND_COMMAND (kernel/swtpm transport)
                                │
                         cmdBuf[2..6] → response_len (big-endian u32)
                                │
                         cmdBuf[..response_len] ──copy──► rsp
                                │
                         Ok(&rsp[..response_len])
```

### Why use a C shim rather than calling ioCb directly?

`wolfTPM2_Init` with the Linux device or swtpm transport sets `ioCb = NULL`
internally — wolfTPM manages the I/O itself without exposing a callback.
The shim accesses `dev->ctx.cmdBuf` directly (documented internal field)
to pass bytes through the transport layer without the high-level session and
parameter-encryption processing in `TPM2_SendCommand`.  The tpm-rs client
stack handles its own command marshaling and sessions.

## Provided types

| Type | Transport |
|---|---|
| `WolfTpmLinuxDev` | Linux kernel TPM driver (`/dev/tpm0`) |
| `WolfTpmSwtpm` | Software TPM TCP socket (swtpm, IBM simulator) |

Both implement `tpm2_rs_client::connection::Connection`.

## Usage

```toml
[dependencies]
wolftpm-tss = { path = "../wolftpm-tss" }
tpm2-rs-client = { git = "https://github.com/tpm-rs/tpm-rs", rev = "a7bf0e9" }
tpm2-rs-base   = { git = "https://github.com/tpm-rs/tpm-rs", rev = "a7bf0e9" }
```

```rust
use wolftpm_tss::connection::WolfTpmLinuxDev;
use tpm2_rs_client::run_command;
use tpm2_rs_base::commands::GetRandom;

let mut transport = WolfTpmLinuxDev::open()?;
let (resp, _) = run_command(&GetRandom { bytes_requested: 32 }, &mut transport)?;
```

## Build requirements

wolfTPM source and wolfSSL headers — see
[`wolftpm-src/README.md`](../wolftpm-src/README.md).

## Features

| Feature | Description |
|---|---|
| `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
| `swtpm` | Software TPM socket transport |
| `tss` | Enable `Connection` trait impls (requires tpm2-rs-client / tpm2-rs-base git deps) |

## References

- [tpm-rs repository](https://github.com/tpm-rs/tpm-rs)
- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [TCG TPM2 Library Specification Part 3: Commands](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm](https://github.com/stefanberger/swtpm)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

wolfTPM is copyright wolfSSL Inc. and its contributors.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`

This crate is available under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
For proprietary or commercial use where the GPL is not acceptable, a commercial
license is available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

wolfTPM itself is licensed under GPL-2.0-or-later or a commercial wolfSSL license.
