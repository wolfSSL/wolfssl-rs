# wolftpm-tss

wolfTPM backend for the [tpm-rs](https://github.com/tpm-rs/tpm-rs) TSS
(Trusted Software Stack) Rust ecosystem.

> **Status**: stub — `open()` / `connect()` constructors and `transact()`
> bodies are not yet implemented.  The crate structure, trait impls, and error
> types are declared so that downstream code can be written and type-checked.

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

wolfTPM stores a raw I/O callback (`TPM2HalIoCb`) inside `TPM2_CTX::ioCb`.
On Linux this callback writes command bytes to `/dev/tpm0` and reads the
response back.  For swtpm it does the same over a TCP socket.

`Connection::transact` bridges to this callback:

1. Copy the tpm-rs command bytes into the response buffer (wolfTPM's
   transport is in-place — the same buffer holds command then response).
2. Call `ctx.ioCb` directly to perform the transport.
3. Read the response length from bytes 2–5 of the TPM2 response header
   (big-endian `u32`, per the TCG TPM2 Part 3 specification).
4. Return a slice of the response buffer of exactly that length.

```text
cmd: &[u8]  ──copy──►  rsp[..cmd.len()]
                                │
                         ioCb(ctx, rsp, rsp, cmd_len, userCtx)
                                │
                         rsp[2..6] → response_len (big-endian u32)
                                │
                         Ok(&rsp[..response_len])
```

### Why call ioCb directly?

`TPM2_SendCommand` in wolfTPM adds session HMAC processing and parameter
encryption on top of the raw transport.  The tpm-rs client stack handles
its own command marshaling and sessions, so calling the transport callback
directly avoids double-processing.

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

## References

- [tpm-rs repository](https://github.com/tpm-rs/tpm-rs)
- [wolfTPM repository](https://github.com/wolfSSL/wolfTPM)
- [TCG TPM2 Library Specification Part 3: Commands](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [swtpm](https://github.com/stefanberger/swtpm)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

`GPL-3.0-only OR LicenseRef-wolfSSL-commercial`
