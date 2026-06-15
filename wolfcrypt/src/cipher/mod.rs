//! Cipher implementations backed by wolfCrypt.
//!
//! Provides block ciphers (AES-ECB, AES-CBC), stream ciphers (AES-CTR,
//! AES-CFB, ChaCha20), and 3DES-CBC, implementing the RustCrypto
//! [`cipher`](cipher_trait) 0.4 traits.

// All cipher trait imports in one place. Individual items are only used when
// their corresponding mode's cfg is active; unused_imports is allowed here
// to avoid a fragile cascade of `not(...)` cfg guards that must be updated
// every time a new cipher mode is added.
#[expect(unused_imports)]
pub(crate) use cipher_trait::generic_array::GenericArray;
#[expect(unused_imports)]
pub(crate) use cipher_trait::inout::InOut;
#[expect(unused_imports)]
pub(crate) use cipher_trait::{
    Block, BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockDecryptMut, BlockEncrypt,
    BlockEncryptMut, BlockSizeUser, IvSizeUser, KeyInit, KeyIvInit, KeySizeUser, ParBlocksSizeUser,
    StreamCipher, StreamCipherError,
};
#[expect(unused_imports)]
pub(crate) use typenum::{U1, U16};

pub use cipher_trait;

// Submodules — one per cipher mode family.

#[cfg(wolfssl_aes_ecb)]
mod ecb;
#[cfg(wolfssl_aes_ecb)]
pub use ecb::*;

#[cfg(wolfssl_aes_ctr)]
mod ctr;
#[cfg(wolfssl_aes_ctr)]
pub use ctr::*;

mod cbc;
pub use cbc::*;

#[cfg(wolfssl_chacha)]
mod chacha20;
#[cfg(wolfssl_chacha)]
pub use chacha20::*;

#[cfg(wolfssl_aes_cfb)]
mod cfb;
#[cfg(wolfssl_aes_cfb)]
pub use cfb::*;

#[cfg(wolfssl_aes_ofb)]
mod ofb;
#[cfg(wolfssl_aes_ofb)]
pub use ofb::*;

#[cfg(wolfssl_aes_xts)]
mod xts;
#[cfg(wolfssl_aes_xts)]
pub use xts::*;

#[cfg(wolfssl_aes_eax)]
mod eax;
#[cfg(wolfssl_aes_eax)]
pub use eax::*;

#[cfg(wolfssl_aes_ccm)]
mod ccm;
#[cfg(wolfssl_aes_ccm)]
pub use ccm::*;

#[cfg(wolfssl_aes_gcm_stream)]
mod gcm_stream;
#[cfg(wolfssl_aes_gcm_stream)]
pub use gcm_stream::*;
