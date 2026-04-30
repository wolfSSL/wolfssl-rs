//! Safe Rust client for [wolfTPM](https://github.com/wolfSSL/wolfTPM),
//! a portable TPM 2.0 library.
//!
//! # Status
//!
//! This crate is a stub — the build infrastructure (`wolftpm-src`, `wolftpm-sys`)
//! is functional but the high-level Rust API has not yet been implemented.
//! Contributions welcome.
//!
//! # Quick start (planned API)
//!
//! ```no_run
//! use wolftpm::Device;
//!
//! # fn main() -> Result<(), wolftpm::Error> {
//! let mut dev = Device::open()?;           // opens /dev/tpm0 or swtpm socket
//! let rand = dev.get_random(32)?;          // TPM-sourced random bytes
//! # let _ = rand;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Feature | What it enables |
//! |---------|----------------|
//! | `linux-dev` | Linux `/dev/tpm0` kernel driver transport |
//! | `swtpm` | Software TPM socket transport (swtpm / IBM TPM2 simulator) |
//!
//! If neither feature is enabled, wolfTPM autodetects the available transport
//! at runtime on Linux.

pub mod error;
pub use error::Error;
