#![cfg(feature = "unstable")]

//! This module contains unstable/experimental APIs.
//!
//! # Warning
//! The APIs under this module are not stable and may change in the future.
//! They are not covered by semver guarantees.
//!
#[cfg(all(not(feature = "fips"), wolfssl_dilithium))]
pub mod signature;
