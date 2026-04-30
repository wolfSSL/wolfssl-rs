//! wolfTPM backend for the [tpm-rs](https://github.com/tpm-rs/tpm-rs) TSS ecosystem.
//!
//! This crate implements [`tpm2_rs_client::connection::Connection`] using
//! wolfTPM as the underlying transport, allowing any code built against the
//! tpm-rs client stack to use a hardware TPM or software TPM simulator via
//! wolfTPM.
//!
//! See [`connection`] for the available transport types.
//!
//! # Quick start
//!
//! ```no_run,ignore
//! // Requires: features = ["tss"] and tpm2-rs git deps (see Cargo.toml)
//! use wolftpm_tss::connection::WolfTpmLinuxDev;
//! use tpm2_rs_client::run_command;
//! use tpm2_rs_base::commands::GetRandomCmd;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut transport = WolfTpmLinuxDev::open()?;
//! let resp = run_command(&GetRandomCmd { bytes_requested: 32 }, &mut transport)?;
//! println!("random bytes: {:?}", resp.random_bytes);
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
//! | `tss` | Enable `Connection` trait impls (requires tpm2-rs-client / tpm2-rs-base git deps) |

pub mod connection;
pub mod error;
