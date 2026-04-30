//! wolfTPM backend for the [tpm-rs](https://github.com/tpm-rs/tpm-rs) TSS ecosystem.
//!
//! This crate implements [`tpm2_rs_client::connection::Connection`] using
//! wolfTPM as the underlying transport, allowing any code built against the
//! tpm-rs client stack to use a hardware TPM or software TPM simulator via
//! wolfTPM.
//!
//! # Status
//!
//! Stub — the [`Connection`] implementations are not yet wired to wolfTPM.
//! See [`connection`] for the planned types.
//!
//! # Quick start (planned API)
//!
//! ```no_run
//! use wolftpm_tss::connection::WolfTpmLinuxDev;
//! use tpm2_rs_client::run_command;
//! use tpm2_rs_base::commands::GetRandom;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut transport = WolfTpmLinuxDev::open()?;
//! let (resp, _) = run_command(&GetRandom { bytes_requested: 32 }, &mut transport)?;
//! println!("random bytes: {:?}", resp.random_bytes.buffer());
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
//! | `swtpm` | Software TPM socket transport (swtpm / IBM TPM2 simulator) |

pub mod connection;
pub mod error;
