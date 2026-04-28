//! Cryptographic operation modules backed by the wolfHSM server.
//!
//! Each module wraps a class of HSM key objects: generate a key on the server,
//! obtain a typed handle, and perform operations (sign, verify, ECDH, encrypt,
//! decrypt) without the key material ever leaving the HSM.
//!
//! # Why operations take `&mut Client`
//!
//! All key-type methods take `client: &mut Client` as an explicit parameter.
//! This is intentional: the wolfHSM communication layer is a request/response
//! protocol over a socket — each operation sends a request and blocks until the
//! response arrives.  Exclusive access (`&mut`) ensures only one operation is
//! in-flight at a time, which is both a correctness requirement (the socket is
//! stateful) and a liveness guarantee (no two callers can interleave requests).
//!
//! If you need concurrent HSM access from multiple threads, each thread must
//! hold its own [`crate::Client`] connection.  The `Client` type is `Send`
//! (it can be moved to another thread) but not `Sync` (it cannot be shared).
//!
//! # RAII key lifetime
//!
//! Key handles ([`ecc::EccP256Key`], [`ed25519::Ed25519Key`], etc.) occupy a
//! slot in the HSM RAM key cache.  Use the `with_xxx_key` helpers on `Client`
//! (e.g. [`crate::Client::with_ecc_p256_key`]) to ensure the slot is always
//! released, even on error paths.  Direct `generate()`/`cache()` + manual
//! `evict()` is also supported but requires care.

pub mod aes;
pub mod cmac;
pub mod curve25519;
pub mod ecc;
pub mod ed25519;
#[cfg(feature = "mldsa")]
pub mod mldsa;
pub mod rng;
pub mod rsa;
pub mod sha;

pub use ecc::EccP256Signer;
pub use ed25519::Ed25519Signer;
pub use sha::{HsmSha256, HsmSha384, HsmSha512};
