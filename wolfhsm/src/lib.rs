//! Safe Rust client for the [wolfHSM](https://github.com/wolfSSL/wolfHSM)
//! hardware security module, wrapping the wolfHSM C client library.
//!
//! # Quick start
//!
//! ```no_run
//! use wolfhsm::{Client, Transport};
//!
//! # fn main() -> Result<(), wolfhsm::Error> {
//! let mut client = Client::connect(
//!     Transport::Tcp { ip: "127.0.0.1".into(), port: 8080 },
//!     1,
//! )?;
//!
//! let digest = [0u8; 32]; // SHA-256 of the data to sign
//! let sig = client.with_ecc_p256_key(|key, client| {
//!     key.sign_digest(client, &digest)
//! })?;
//! # let _ = sig;
//! # Ok(())
//! # }
//! ```
//!
//! # Why `&mut Client` is required for every operation
//!
//! The wolfHSM communication layer is a request/response protocol over a
//! socket.  Only one request can be in-flight at a time.  Requiring `&mut
//! Client` on every method enforces this at the type level — the borrow
//! checker prevents two callers from interleaving requests.
//!
//! `Client` is `Send` (ownership can be moved to another thread) but not
//! `Sync` (it cannot be shared).  For concurrent HSM access, open multiple
//! `Client` connections.
//!
//! # Why key operations use closures instead of RAII drop types
//!
//! HSM key handles occupy RAM cache slots on the server.  When you are done
//! with a key it must be explicitly evicted via a network request to the
//! server, which requires `&mut Client`.
//!
//! A drop-based RAII type cannot carry `&mut Client` inside it — Rust does
//! not allow a struct to hold `&mut Client` and then also accept `&mut
//! Client` in its own `Drop` impl without unsafe code.  The closure pattern
//! sidesteps this:
//!
//! ```no_run
//! # use wolfhsm::{Client, Transport};
//! # fn main() -> Result<(), wolfhsm::Error> {
//! # let mut client = Client::connect(Transport::Tcp { ip: "127.0.0.1".into(), port: 8080 }, 1)?;
//! let digest = [0u8; 32];
//! let (pub_der, sig) = client.with_ecc_p256_key(|key, client| {
//!     let pub_der = key.public_key_der(client)?;
//!     let sig = key.sign_digest(client, &digest)?;
//!     Ok((pub_der, sig))
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! `with_ecc_p256_key` generates the key, runs the closure, and always evicts
//! the cache slot — even when the closure returns `Err`.
//!
//! # Feature flags
//!
//! | Feature | What it enables |
//! |---------|----------------|
//! | `cert`  | Certificate management (`wh_Client_Cert*` API) |
//! | `auth`  | Authentication and user management (`wh_Client_Auth*` API) |
//! | `she`   | SHE (Secure Hardware Extension) automotive key management |
//! | `mldsa` | ML-DSA (Dilithium) key support; requires `HAVE_DILITHIUM` in wolfSSL |
//!
//! # Transport variants
//!
//! | Variant | Mechanism |
//! |---------|-----------|
//! | [`Transport::Tcp`] | TCP/IP socket |
//! | [`Transport::Uds`] | Unix domain socket |
//! | [`Transport::Shm`] | POSIX shared memory (same host, zero-copy) |

pub mod error;
pub use error::Error;

pub mod transport;
pub use transport::Transport;

pub mod client;
pub use client::{Client, ServerInfo};

pub mod key;
pub use key::KeyId;

pub mod nvm;
pub use nvm::{NvmAccess, NvmAvailability, NvmFlags, NvmId, NvmMetadata};

pub mod counter;

pub mod cryptocb;
pub use cryptocb::{CryptoCbGuard, DEV_ID};

pub mod crypto;

#[cfg(feature = "cert")]
pub mod cert;

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "auth")]
pub use auth::{AuthMethod, AuthPermissions, UserId};

#[cfg(feature = "she")]
pub mod she;
#[cfg(feature = "she")]
pub use she::SheKeyId;
