/// Cryptographic operation modules backed by the wolfHSM server.
///
/// Each module wraps a class of HSM key objects: generate a key on the server,
/// obtain a typed handle, and perform operations (sign, verify, ECDH, encrypt,
/// decrypt) without the key material ever leaving the HSM.
///
/// All key handles contain a [`crate::KeyId`] and require a `&mut Client` for
/// each operation (the client holds the connection to the server).

pub mod ecc;
pub mod ed25519;
pub mod curve25519;
pub mod rsa;
#[cfg(feature = "mldsa")]
pub mod mldsa;
pub mod aes;
pub mod sha;
pub mod cmac;
pub mod rng;
