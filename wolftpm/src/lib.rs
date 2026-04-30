//! Safe Rust client for [wolfTPM](https://github.com/wolfSSL/wolfTPM),
//! a portable TPM 2.0 library.
//!
//! # Status
//!
//! Core API implemented: [`Device`] for TPM initialization and basic operations,
//! and [`EccKey`] for transient P-256 signing keys.
//! Advanced wolfTPM features (NV storage, attestation, HMAC sessions) are not yet wrapped.
//!
//! # Quick start
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

pub mod device;
pub use device::Device;

pub mod error;
pub use error::Error;

pub mod key;
pub use key::EccKey;
