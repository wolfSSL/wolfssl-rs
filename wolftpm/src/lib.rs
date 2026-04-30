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
//! let mut dev = Device::open()?;           // opens /dev/tpm0 or /dev/tpmrm0 via kernel driver
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
//! | `linux-dev` | Compile wolfTPM with explicit Linux kernel driver transport; without this, wolfTPM autodetects at runtime |
//! | `swtpm` | Software TPM socket transport (`Device::open_swtpm`; swtpm / IBM TPM2 simulator) |
//!
//! `Device::open()` (kernel driver) is always available regardless of feature flags;
//! `Device::open_swtpm()` requires the `swtpm` feature.

pub mod device;
pub use device::Device;

pub mod error;
pub use error::Error;
pub use error::TpmRc;

pub mod key;
pub use key::EccKey;
