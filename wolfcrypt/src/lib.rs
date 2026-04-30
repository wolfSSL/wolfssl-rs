//! RustCrypto trait implementations backed by wolfCrypt.
//!
//! This crate is `#![no_std]` (with `alloc`).  It wraps wolfCrypt's C
//! implementations behind standard RustCrypto trait interfaces so they
//! can be used as drop-in backends in generic Rust crypto code.
//!
//! # What implements RustCrypto traits
//!
//! | Module | Trait(s) implemented | Types |
//! |--------|---------------------|-------|
//! | [`digest`] | `Digest`, `Update`, `FixedOutput`, `Reset` | `Sha256`, `Sha384`, `Sha512`, … |
//! | [`hmac`] | `Mac` (via `KeyInit` + `Update` + `FixedOutput` + `MacMarker`) | `WolfHmacSha256`, … |
//! | [`cmac`] | `Mac` | `WolfCmacAes128`, `WolfCmacAes256` |
//! | [`aead`] | `AeadInPlace`, `KeyInit` | `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305` |
//! | [`cipher`] | `BlockCipher`, `BlockEncrypt`/`Decrypt`, `StreamCipher`, `KeyInit`/`KeyIvInit` | AES-ECB/CTR/CBC/CFB, `WolfChaCha20` |
//! | [`des3`] | `BlockEncryptMut`, `BlockDecryptMut`, `KeyIvInit` | `DesEde3CbcEnc`, `DesEde3CbcDec` |
//! | [`poly1305`] | `Mac` | `WolfPoly1305` |
//! | [`ed25519`] | `Signer`, `Verifier` (using `ed25519::Signature`) | `Ed25519SigningKey`, `Ed25519VerifyingKey` |
//! | [`ed448`] | `Signer`, `Verifier` | `Ed448SigningKey`, `Ed448VerifyingKey` |
//! | [`ecdsa`] | `Signer`, `Verifier` | `EcdsaSigningKey<P256>`, `EcdsaVerifyingKey<P256>`, … |
//! | [`rsa`] | `Signer`, `Verifier` | `RsaPrivateKey`, `RsaPublicKey` |
//! | [`mldsa`] | `Signer`, `Verifier` | `MlDsa44SigningKey`, `MlDsa65SigningKey`, …; `MlDsaSignature<L>` |
//! | [`rand`] | `TryRng`, `TryCryptoRng` (`Rng` + `CryptoRng` via blanket impl) | `WolfRng` |
//!
//! # What uses a bespoke (non-trait) API
//!
//! | Module | Why no trait | API shape |
//! |--------|-------------|-----------|
//! | [`hkdf`] | The `hkdf` crate provides a concrete struct, not a trait | `new()` / `extract()` / `expand()` — same method names as `hkdf::Hkdf` |
//! | [`pbkdf2`] | `pbkdf2::pbkdf2_hmac` requires `CoreProxy`; our EVP digests can't satisfy `Sync` | `pbkdf2_hmac_sha256(password, salt, rounds, &mut out)` |
//! | [`keywrap`] | No RustCrypto trait exists for AES Key Wrap | `aes_wrap_key()` / `aes_unwrap_key()` |
//! | [`dh`] | No RustCrypto trait for classic DH | `DhSecret::generate()` / `compute_shared_secret()` |
//! | [`ecdh`] | No RustCrypto trait for raw ECDH | `X25519StaticSecret`, `NistEcdhSecret<C>`, etc. |
//! | [`mlkem`] | No RustCrypto trait for ML-KEM | `MlKemDecapsulationKey` / `MlKemEncapsulationKey` |
//!
//! For HKDF and PBKDF2, our [`digest`] types are compatible with the standard
//! crates via `hkdf::SimpleHkdf<Sha256>` and `hmac::SimpleHmac<Sha256>`
//! respectively — see each module's docs for examples.
//!
//! # Panics vs `Result` in constructors
//!
//! Several RustCrypto traits define infallible constructors that return `Self`
//! rather than `Result<Self, _>`:
//!
//! - [`digest::Digest::new`](https://docs.rs/digest/0.10/digest/trait.Digest.html#tymethod.new) (`Default::default`)
//! - [`cipher::KeyInit::new`](https://docs.rs/cipher/0.4/cipher/trait.KeyInit.html#tymethod.new)
//! - [`aead::KeyInit::new`](https://docs.rs/aead/0.5/aead/trait.KeyInit.html#tymethod.new)
//!
//! Because these signatures leave no room for a `Result`, our implementations
//! `assert!` on the wolfCrypt return code and panic on failure. In practice
//! this means a panic only on OOM or a fundamental library-init failure — never
//! on user-supplied input of the correct length. Fallible alternatives
//! (`new_from_slice`, `generate`, `from_seed`, etc.) return `Result` wherever
//! the trait or our own API allows it.
//!
//! # Buffer size limit
//!
//! wolfCrypt's C API uses `u32` (or `c_int`) for buffer lengths.  This crate
//! casts Rust `usize` lengths to `u32` at each FFI boundary.  On 64-bit
//! targets, buffers larger than 4 GB (`u32::MAX`) will **panic** rather than
//! silently truncate.
//!
//! In practice, single-call buffers of 4 GB+ are extremely rare in
//! cryptographic operations.  If you need to process data of that size,
//! feed it incrementally through the streaming / update APIs.
//!
//! # RustCrypto trait ecosystem gaps
//!
//! Implementing the RustCrypto traits on top of a C FFI backend exposed
//! several design limitations that pure-Rust implementations never hit.
//! This section documents each gap and the workaround used in this crate,
//! both as guidance for contributors and as a reference for anyone
//! proposing upstream improvements.
//!
//! ## 1. Infallible constructors for fallible operations
//!
//! `KeyInit::new`, `Digest::new` (via `Default`) return `Self`, not
//! `Result`.  Any FFI backend can fail for reasons beyond the caller's
//! control — OOM in the C allocator, hardware device unavailable, library
//! not initialized.  The trait gives no way to report this.
//!
//! **Workaround:** We `assert!` on the wolfCrypt return code.  In practice
//! this panics only on OOM or device-init failure, never on valid input.
//! Fallible alternatives (`new_from_slice`, `generate`, `from_seed`)
//! return `Result` wherever the trait allows.
//!
//! ## 2. No `ZeroizeOnDrop` bound on key types
//!
//! `KeyInit` creates types holding secret key material, but the trait
//! doesn't require `ZeroizeOnDrop` or any cleanup guarantee.  Each
//! implementor must remember to add it manually — an easy thing to miss.
//!
//! **Workaround:** We manually implement `Drop` with `wc_AesFree` or
//! `zeroize` calls on every type that holds key material (AES key schedules,
//! ChaCha20Poly1305 keys, HKDF PRKs, keywrap temporaries).
//!
//! ## 3. `AeadInPlace` is the only AEAD trait
//!
//! There is no `Aead` variant with separate input and output buffers.
//! wolfCrypt's one-shot ChaCha20-Poly1305 API (`wc_ChaCha20Poly1305_Encrypt`)
//! required separate buffers, which would have forced a heap allocation
//! per encrypt/decrypt call.
//!
//! **Workaround:** We switched to wolfCrypt's streaming ChaCha20-Poly1305
//! API (`wc_ChaCha20Poly1305_Init` / `UpdateData` / `Final`), which
//! supports `input == output` pointers.  This eliminated the allocation
//! entirely.  A backend with no in-place path (e.g., a DMA-based hardware
//! accelerator) would have no such escape hatch.
//!
//! ## 4. No HKDF or PBKDF2 traits
//!
//! The `hkdf` and `pbkdf2` crates provide concrete implementations, not
//! traits.  There is no way to supply an alternative backend through trait
//! implementation.
//!
//! **Workaround:** Our HKDF module exposes a bespoke API with method names
//! matching `hkdf::Hkdf` (`new`, `extract`, `expand`).  Our PBKDF2 module
//! exposes standalone functions matching `pbkdf2::pbkdf2_hmac`'s signature.
//! For callers that need the actual `hkdf` or `pbkdf2` crate types, our
//! digest types compose with `hkdf::SimpleHkdf<Sha256>` and
//! `hmac::SimpleHmac<Sha256>` — see each module's docs for examples.
//!
//! ## 5. The `CoreProxy` cliff
//!
//! The `digest` crate has two tiers: high-level (`Digest`, `Update`,
//! `FixedOutput`) and low-level (`CoreProxy`, `UpdateCore`,
//! `FixedOutputCore`).  Our EVP-based digests implement the high-level
//! tier, but `pbkdf2::pbkdf2_hmac` requires `CoreProxy` (low-level),
//! which opaque FFI wrappers cannot satisfy.
//!
//! **Workaround:** Callers needing `pbkdf2_hmac` should use
//! `hmac::SimpleHmac<Sha256>` (which bridges from high-level digest to
//! low-level HMAC) or use our native `pbkdf2_hmac_sha256` function, which
//! calls wolfCrypt's `wc_PBKDF2` in a single FFI call.
//!
//! ## 6. `pbkdf2::pbkdf2` requires `Sync` unconditionally
//!
//! The function signature has `PRF: Sync` even when the `parallel` feature
//! is disabled.  Our EVP-based digest types are `!Sync` (correctly —
//! `EVP_MD_CTX` has interior mutable state), so
//! `pbkdf2::<SimpleHmac<Sha256>>(...)` does not compile.
//!
//! **Workaround:** Use our native `pbkdf2_hmac_sha256` function instead.
//! This is a candidate for an upstream fix (the `Sync` bound should be
//! conditional on the `parallel` feature).
//!
//! ## 7. `SignatureEncoding::Repr` assumes fixed-size signatures
//!
//! The trait works naturally for Ed25519 (`Repr = [u8; 64]`) but
//! post-quantum signatures are variable-length — ML-DSA-87 is 4627 bytes.
//! We use `Repr = Box<[u8]>`, which works but means the signature cannot
//! be stack-allocated and loses compile-time size guarantees.
//!
//! **Workaround:** Accepted as-is.  As PQC becomes standard across the
//! RustCrypto ecosystem, this will likely be revisited upstream.
//!
//! ## 8. Interior mutability for FFI verification calls
//!
//! wolfCrypt's C API requires `*mut` pointers even for logically read-only
//! operations like signature verification and public-key export.  The
//! RustCrypto `Verifier::verify` trait takes `&self`, so we cannot pass
//! `&mut self` to the FFI.
//!
//! **Workaround:** Signing and verifying key types wrap their C key handle
//! in `UnsafeCell` (see `ed25519.rs`, `ed448.rs`, `ecdsa_native.rs`, `rsa.rs`,
//! `mldsa.rs`, `lms.rs`, `aead.rs`, `cipher/ccm.rs`).  This lets us
//! obtain `*mut` from `&self` for FFI calls.  `UnsafeCell` also makes the
//! type `!Sync`, which is correct — wolfCrypt key handles are not
//! thread-safe.  Each `UnsafeCell` usage has a SAFETY comment at the call
//! site explaining why single-threaded access is guaranteed.
//!
//! # Testing
//!
//! This crate's in-tree tests (`tests/`) cover only functionality that has
//! no pure-Rust counterpart for cross-validation: classic DH, NIST-curve
//! ECDH, and RSA encryption.
//!
//! The bulk of correctness testing lives in the **`wolfcrypt-conformance`**
//! crate (a sibling workspace member).  That suite cross-validates every
//! algorithm against pure-Rust RustCrypto implementations, NIST CAVP/SHAVS
//! vectors, Wycheproof edge-case vectors, and RFC known-answer tests.
//! **Always run the conformance suite after modifying this crate:**
//!
//! ```sh
//! cargo test -p wolfcrypt-conformance
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod error;
pub use error::WolfCryptError;

// Module declarations — enabled as features are implemented.

#[cfg(feature = "digest")]
pub mod digest;

// Re-export digest types at crate root for ergonomic use.
#[cfg(all(feature = "digest", wolfssl_sha1))]
pub use digest::Sha1;

#[cfg(all(feature = "digest", wolfssl_sha224))]
pub use digest::Sha224;

#[cfg(all(feature = "digest", wolfssl_sha256))]
pub use digest::Sha256;

#[cfg(all(feature = "digest", wolfssl_sha384))]
pub use digest::Sha384;

#[cfg(all(feature = "digest", wolfssl_sha512))]
pub use digest::Sha512;

#[cfg(all(feature = "digest", wolfssl_sha512))]
pub use digest::Sha512_256;

#[cfg(all(feature = "digest", wolfssl_sha3))]
pub use digest::Sha3_256;

#[cfg(all(feature = "digest", wolfssl_sha3))]
pub use digest::Sha3_384;

#[cfg(all(feature = "digest", wolfssl_sha3))]
pub use digest::Sha3_512;

#[cfg(feature = "rand")]
pub mod rand;
#[cfg(feature = "rand")]
pub use rand::WolfRng;

#[cfg(feature = "hmac")]
pub mod hmac;

#[cfg(all(feature = "hmac", wolfssl_hmac))]
pub use hmac::WolfHmacSha1;
#[cfg(all(feature = "hmac", wolfssl_hmac))]
pub use hmac::WolfHmacSha256;
#[cfg(all(feature = "hmac", wolfssl_hmac, wolfssl_sha384))]
pub use hmac::WolfHmacSha384;
#[cfg(all(feature = "hmac", wolfssl_hmac, wolfssl_sha512))]
pub use hmac::WolfHmacSha512;

#[cfg(feature = "cmac")]
pub mod cmac;

#[cfg(all(feature = "cmac", wolfssl_cmac))]
pub use cmac::WolfCmacAes128;
#[cfg(all(feature = "cmac", wolfssl_cmac))]
pub use cmac::WolfCmacAes256;

#[cfg(feature = "hkdf")]
pub mod hkdf;

#[cfg(all(feature = "hkdf", wolfssl_hkdf))]
pub use hkdf::WolfHkdfSha256;
#[cfg(all(feature = "hkdf", wolfssl_hkdf, wolfssl_sha384))]
pub use hkdf::WolfHkdfSha384;
#[cfg(all(feature = "hkdf", wolfssl_hkdf, wolfssl_sha512))]
pub use hkdf::WolfHkdfSha512;

#[cfg(feature = "pbkdf2")]
pub mod pbkdf2;

#[cfg(all(feature = "pbkdf2", wolfssl_pbkdf2))]
pub use pbkdf2::pbkdf2_hmac_sha256;
#[cfg(all(feature = "pbkdf2", wolfssl_pbkdf2, wolfssl_sha384))]
pub use pbkdf2::pbkdf2_hmac_sha384;
#[cfg(all(feature = "pbkdf2", wolfssl_pbkdf2, wolfssl_sha512))]
pub use pbkdf2::pbkdf2_hmac_sha512;

#[cfg(feature = "aead")]
pub mod aead;

#[cfg(all(feature = "aead", wolfssl_aes_gcm))]
pub use aead::{Aes128Gcm, Aes256Gcm};

#[cfg(all(feature = "aead", wolfssl_aes_gcm, wolfssl_aes_192))]
pub use aead::Aes192Gcm;

#[cfg(all(feature = "aead", wolfssl_chacha20_poly1305))]
pub use aead::ChaCha20Poly1305;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(all(feature = "cipher", wolfssl_aes_ecb))]
pub use cipher::{Aes128EcbDec, Aes128EcbEnc, Aes256EcbDec, Aes256EcbEnc};

#[cfg(all(feature = "cipher", wolfssl_aes_ecb, wolfssl_aes_192))]
pub use cipher::{Aes192EcbDec, Aes192EcbEnc};

#[cfg(all(feature = "cipher", wolfssl_aes_ctr))]
pub use cipher::{Aes128Ctr, Aes256Ctr};

#[cfg(all(feature = "cipher", wolfssl_aes_ctr, wolfssl_aes_192))]
pub use cipher::Aes192Ctr;

#[cfg(feature = "cipher")]
pub use cipher::{Aes128CbcDec, Aes128CbcEnc, Aes256CbcDec, Aes256CbcEnc};

#[cfg(all(feature = "cipher", wolfssl_aes_192))]
pub use cipher::{Aes192CbcDec, Aes192CbcEnc};

#[cfg(all(feature = "cipher", wolfssl_chacha))]
pub use cipher::WolfChaCha20;

#[cfg(all(feature = "cipher", wolfssl_aes_cfb))]
pub use cipher::{Aes128CfbDec, Aes128CfbEnc, Aes256CfbDec, Aes256CfbEnc};

#[cfg(all(feature = "cipher", wolfssl_aes_cfb, wolfssl_aes_192))]
pub use cipher::{Aes192CfbDec, Aes192CfbEnc};

#[cfg(all(feature = "des3", wolfssl_des3))]
pub mod des3;

#[cfg(all(feature = "des3", wolfssl_des3))]
pub use des3::{DesEde3CbcDec, DesEde3CbcEnc};

#[cfg(all(feature = "dh", wolfssl_dh))]
pub mod dh;

#[cfg(all(feature = "dh", wolfssl_dh))]
pub use dh::{DhSecret, FfdheGroup};

#[cfg(feature = "poly1305")]
pub mod poly1305;

#[cfg(all(feature = "poly1305", wolfssl_poly1305))]
pub use poly1305::WolfPoly1305;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(all(feature = "ed25519", wolfssl_ed25519))]
pub use ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};

#[cfg(feature = "ed448")]
pub mod ed448;

#[cfg(all(feature = "ed448", wolfssl_ed448))]
pub use ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};

#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(all(feature = "ecdh", wolfssl_curve25519))]
pub use ecdh::{SharedSecret, X25519PublicKey, X25519StaticSecret};

#[cfg(all(feature = "ecdh", wolfssl_curve448))]
pub use ecdh::{X448PublicKey, X448SharedSecret, X448StaticSecret};

#[cfg(all(feature = "ecdh", wolfssl_ecc))]
pub use ecdh::{
    NistCurve, NistEcdhPublicKey, NistEcdhSecret, NistEcdhSharedSecret, NistP256, P256EcdhSecret,
};
#[cfg(all(feature = "ecdh", wolfssl_ecc, wolfssl_ecc_p384))]
pub use ecdh::{NistP384, P384EcdhSecret};

#[cfg(all(feature = "ecdh", wolfssl_ecc, wolfssl_ecc_p521))]
pub use ecdh::{NistP521, P521EcdhSecret};

// Native wc_ecc_*-based ECDSA.
#[cfg(all(feature = "ecdsa", wolfssl_ecc))]
#[path = "ecdsa_native.rs"]
pub mod ecdsa;

#[cfg(all(feature = "ecdsa", wolfssl_ecc))]
pub use ecdsa::{
    EcdsaCurve, EcdsaSignature, EcdsaSigningKey, EcdsaVerifyingKey, P256Signature, P256SigningKey,
    P256VerifyingKey, P256,
};

#[cfg(all(feature = "ecdsa", wolfssl_ecc, wolfssl_ecc_p384))]
pub use ecdsa::{P384Signature, P384SigningKey, P384VerifyingKey, P384};

#[cfg(all(feature = "ecdsa", wolfssl_ecc, wolfssl_ecc_p521, wolfssl_sha512))]
pub use ecdsa::{P521Signature, P521SigningKey, P521VerifyingKey, P521};

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(all(feature = "rsa", wolfssl_rsa))]
pub use rsa::{RsaDigest, RsaPkcs1v15Signature, RsaPrivateKey, RsaPssSignature, RsaPublicKey};

#[cfg(all(feature = "rsa-direct", wolfssl_rsa))]
pub use rsa::{NativeRsaKey, RsaDirectType, RsaRawComponents};

#[cfg(all(feature = "keywrap", wolfssl_aes_keywrap))]
pub mod keywrap;

#[cfg(all(feature = "keywrap", wolfssl_aes_keywrap))]
pub use keywrap::{aes_unwrap_key, aes_wrap_key};

#[cfg(all(feature = "mldsa", wolfssl_dilithium))]
pub mod mldsa;

#[cfg(all(feature = "mldsa", wolfssl_dilithium))]
pub use mldsa::{
    MlDsa44Signature, MlDsa44SigningKey, MlDsa44VerifyingKey, MlDsa65Signature, MlDsa65SigningKey,
    MlDsa65VerifyingKey, MlDsa87Signature, MlDsa87SigningKey, MlDsa87VerifyingKey, MlDsaSignature,
};

#[cfg(feature = "mlkem")]
pub mod mlkem;

#[cfg(all(feature = "mlkem", wolfssl_mlkem))]
pub use mlkem::{
    MlKem1024, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem512,
    MlKem512DecapsulationKey, MlKem512EncapsulationKey, MlKem768, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey,
};

// --- New algorithm modules ---

#[cfg(feature = "blake2")]
pub mod blake2;

#[cfg(feature = "shake")]
pub mod shake;

#[cfg(feature = "kdf")]
pub mod kdf;

#[cfg(feature = "ecc")]
pub mod ecc;

#[cfg(all(feature = "lms", wolfssl_lms))]
pub mod lms;

#[cfg(all(feature = "lms", wolfssl_lms))]
pub use lms::{LmsParams, LmsSigningKey, LmsVerifyingKey};

#[cfg(all(feature = "cipher", wolfssl_aes_ccm))]
pub use cipher::{Aes128Ccm, Aes256Ccm};

// AES-XTS, AES-OFB, AES-CTS, AES-EAX, AES-CCM are added to the cipher module tree.

#[cfg(all(feature = "cryptocb", wolfssl_cryptocb))]
pub mod cryptocb;

#[cfg(all(feature = "hpke", wolfssl_hpke))]
pub mod hpke;
