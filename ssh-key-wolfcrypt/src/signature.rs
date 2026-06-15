//! Signatures (e.g. CA signatures over SSH certificates)

use crate::{private, public, Algorithm, EcdsaCurve, Error, Mpint, PrivateKey, PublicKey, Result};
use alloc::vec::Vec;
use core::fmt;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use signature::{SignatureEncoding, Signer, Verifier};

#[cfg(feature = "ed25519")]
use crate::{private::Ed25519Keypair, public::Ed25519PublicKey};

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
use crate::{
    private::{EcdsaKeypair, EcdsaPrivateKey},
    public::EcdsaPublicKey,
};

#[cfg(feature = "rsa")]
use crate::{
    private::rsa::import_rsa_public_key, private::RsaKeypair, public::RsaPublicKey, HashAlg,
};

#[cfg(any(feature = "ed25519", feature = "p256"))]
use sha2::Sha256;

#[cfg(any(feature = "ed25519", feature = "p256"))]
use sha2::Digest;

const DSA_SIGNATURE_SIZE: usize = 40;
const ED25519_SIGNATURE_SIZE: usize = 64;
const SK_SIGNATURE_TRAILER_SIZE: usize = 5; // flags(u8), counter(u32)
const SK_ED25519_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + SK_SIGNATURE_TRAILER_SIZE;

/// Trait for signing keys which produce a [`Signature`].
///
/// This trait is automatically impl'd for any types which impl the
/// [`Signer`] trait for the SSH [`Signature`] type and also support a [`From`]
/// conversion for [`public::KeyData`].
pub trait SigningKey: Signer<Signature> {
    /// Get the [`public::KeyData`] for this signing key.
    fn public_key(&self) -> public::KeyData;
}

impl<T> SigningKey for T
where
    T: Signer<Signature>,
    public::KeyData: for<'a> From<&'a T>,
{
    fn public_key(&self) -> public::KeyData {
        self.into()
    }
}

/// Low-level digital signature (e.g. DSA, ECDSA, Ed25519).
///
/// These are low-level signatures used as part of the OpenSSH certificate
/// format to represent signatures by certificate authorities (CAs), as well
/// as the higher-level [`SshSig`][`crate::SshSig`] format, which provides
/// general-purpose signing functionality using SSH keys.
///
/// From OpenSSH's [PROTOCOL.certkeys] specification:
///
/// > Signatures are computed and encoded according to the rules defined for
/// > the CA's public key algorithm ([RFC4253 section 6.6] for ssh-rsa and
/// > ssh-dss, [RFC5656] for the ECDSA types, and [RFC8032] for Ed25519).
///
/// RSA signature support is implemented using the SHA2 family extensions as
/// described in [RFC8332].
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
/// [RFC4253 section 6.6]: https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
/// [RFC5656]: https://datatracker.ietf.org/doc/html/rfc5656
/// [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032
/// [RFC8332]: https://datatracker.ietf.org/doc/html/rfc8332
#[derive(Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Signature {
    /// Signature algorithm.
    algorithm: Algorithm,

    /// Raw signature serialized as algorithm-specific byte encoding.
    data: Vec<u8>,
}

impl Signature {
    /// Create a new signature with the given algorithm and raw signature data.
    ///
    /// See specifications in toplevel [`Signature`] documentation for how to
    /// format the raw signature data for a given algorithm.
    ///
    /// # Returns
    /// - [`Error::Encoding`] if the signature is not the correct length.
    pub fn new(algorithm: Algorithm, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();

        // Validate signature is well-formed per OpenSSH encoding
        match algorithm {
            Algorithm::Dsa if data.len() == DSA_SIGNATURE_SIZE => (),
            Algorithm::Ecdsa { curve } => ecdsa_sig_size(&data, curve, false)?,
            Algorithm::Ed25519 if data.len() == ED25519_SIGNATURE_SIZE => (),
            Algorithm::SkEd25519 if data.len() == SK_ED25519_SIGNATURE_SIZE => (),
            Algorithm::SkEcdsaSha2NistP256 => ecdsa_sig_size(&data, EcdsaCurve::NistP256, true)?,
            Algorithm::Rsa { .. } => (),
            Algorithm::Other(_) if !data.is_empty() => (),
            _ => return Err(encoding::Error::Length.into()),
        }

        Ok(Self { algorithm, data })
    }

    /// Get the [`Algorithm`] associated with this signature.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm.clone()
    }

    /// Get the raw signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Placeholder signature used by the certificate builder.
    ///
    /// This is guaranteed to generate an error if anything attempts to encode it.
    pub(crate) fn placeholder() -> Self {
        Self {
            algorithm: Algorithm::default(),
            data: Vec::new(),
        }
    }

    /// Check if this signature is the placeholder signature.
    pub(crate) fn is_placeholder(&self) -> bool {
        self.algorithm == Algorithm::default() && self.data.is_empty()
    }
}

/// Returns Ok() if data holds an ecdsa signature with components of appropriate size
/// according to curve.
fn ecdsa_sig_size(mut data: &[u8], curve: EcdsaCurve, sk_trailer: bool) -> Result<()> {
    let reader = &mut data;

    for _ in 0..2 {
        let component = Mpint::decode(reader)?;
        let bytes = component.as_positive_bytes().ok_or(Error::FormatEncoding)?;
        if bytes.len() > curve.field_size() {
            return Err(encoding::Error::Length.into());
        }
    }

    if sk_trailer {
        reader.drain(SK_SIGNATURE_TRAILER_SIZE)?;
    }

    Ok(reader.finish(())?)
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for Signature {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let algorithm = Algorithm::decode(reader)?;
        let mut data = Vec::decode(reader)?;

        if algorithm == Algorithm::SkEd25519 || algorithm == Algorithm::SkEcdsaSha2NistP256 {
            let flags = u8::decode(reader)?;
            let counter = u32::decode(reader)?;

            data.push(flags);
            data.extend(counter.to_be_bytes());
        }
        Self::new(algorithm, data)
    }
}

impl Encode for Signature {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.algorithm().encoded_len()?,
            self.as_bytes().encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        if self.is_placeholder() {
            return Err(encoding::Error::Length);
        }

        self.algorithm().encode(writer)?;

        if self.algorithm == Algorithm::SkEd25519
            || self.algorithm == Algorithm::SkEcdsaSha2NistP256
        {
            let signature_length = self
                .as_bytes()
                .len()
                .checked_sub(SK_SIGNATURE_TRAILER_SIZE)
                .ok_or(encoding::Error::Length)?;
            self.as_bytes()[..signature_length].encode(writer)?;
            writer.write(&self.as_bytes()[signature_length..])?;
        } else {
            self.as_bytes().encode(writer)?;
        }

        Ok(())
    }
}

impl SignatureEncoding for Signature {
    type Repr = Vec<u8>;
}

/// Decode [`Signature`] from an [`Algorithm`]-prefixed OpenSSH-encoded bytestring.
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(mut bytes: &[u8]) -> Result<Self> {
        Self::decode(&mut bytes)
    }
}

impl TryFrom<Signature> for Vec<u8> {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Vec<u8>> {
        Ok(signature.encode_vec()?)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature {{ algorithm: {:?}, data: {:X} }}",
            self.algorithm, self
        )
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl Signer<Signature> for PrivateKey {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        self.key_data().try_sign(message)
    }
}

impl Signer<Signature> for private::KeypairData {
    #[expect(unused_variables)]
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            #[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
            Self::Ecdsa(keypair) => keypair.try_sign(message),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(keypair) => keypair.try_sign(message),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.try_sign(message),
            _ => Err(self.algorithm()?.unsupported_error().into()),
        }
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        self.key_data().verify(message, signature)
    }
}

impl Verifier<Signature> for public::KeyData {
    #[expect(unused_variables)]
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match self {
            #[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
            Self::Ecdsa(pk) => pk.verify(message, signature),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(pk) => pk.verify(message, signature),
            #[cfg(feature = "ed25519")]
            Self::SkEd25519(pk) => pk.verify(message, signature),
            #[cfg(feature = "p256")]
            Self::SkEcdsaSha2NistP256(pk) => pk.verify(message, signature),
            #[cfg(feature = "rsa")]
            Self::Rsa(pk) => pk.verify(message, signature),
            _ => Err(self.algorithm().unsupported_error().into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification — direct wolfCrypt FFI
// ---------------------------------------------------------------------------
//
// WHY NOT USE wolfcrypt's Signer/Verifier TRAIT IMPLS?
//
// wolfcrypt implements `signature::Signer` and `signature::Verifier` from
// the `signature` crate **v2.2** (current stable).  This ssh-key fork's
// public API uses `signature` **v3-rc** (pre-release) because upstream
// RustCrypto SSH crates track the next-gen release candidates.
//
// These are semver-incompatible: the trait types, error types, and Signature
// types are different Rust types even though they have the same names.
//
// If we called wolfcrypt's trait methods, we'd need `signature` v2.2 in our
// dependency tree alongside v3-rc.  Two versions of the same crate means:
//   - Two `Signer` traits that can't be confused at compile time but confuse
//     humans reading the code ("which `Signer` is this?")
//   - Two `signature::Error` types that can't convert to each other
//   - A maintenance burden if either version is upgraded
//
// Instead, we call the wolfCrypt C functions directly through wolfcrypt-rs:
//   - `wc_ed25519_init` / `wc_ed25519_import_private_key` / `wc_ed25519_sign_msg`
//   - `wc_ed25519_init` / `wc_ed25519_import_public` / `wc_ed25519_verify_msg`
//
// This is the same approach used for ECDSA (via `EccKey::sign_hash`) and
// RSA (via `NativeRsaKey::sign_pkcs1v15_raw`): bypass the wolfcrypt safe
// wrapper's trait impls, call the FFI, and work with raw bytes.
//
// WHEN DOES THIS GO AWAY?
//
// This FFI bridging layer is blocked on `signature` v3 reaching a stable
// (non-rc) release. Once it does and wolfcrypt upgrades, we can use
// wolfcrypt's Signer/Verifier trait impls directly. See version policy
// in wolfcrypt/Cargo.toml.
// ---------------------------------------------------------------------------

/// Sign a message with Ed25519 via wolfcrypt's standalone function.
///
/// Returns [`Error::WolfCrypt`] if key import or the signing operation fails.
#[cfg(feature = "ed25519")]
fn ed25519_sign(seed: &[u8], pub_key: &[u8], message: &[u8]) -> Result<[u8; 64]> {
    wolfcrypt::ed25519::ed25519_sign_raw(seed, pub_key, message).map_err(Error::from)
}

/// Verify an Ed25519 signature via wolfcrypt's standalone function.
///
/// Returns [`Error::WolfCrypt`] if key import fails, or [`Error::Crypto`]
/// if the signature is invalid.
#[cfg(feature = "ed25519")]
fn ed25519_verify(pub_key: &[u8], message: &[u8], sig: &[u8]) -> Result<()> {
    wolfcrypt::ed25519::ed25519_verify_raw(pub_key, message, sig).map_err(Error::from)
}

#[cfg(feature = "ed25519")]
impl Signer<Signature> for Ed25519Keypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let sig = ed25519_sign(self.private.as_ref(), self.public.as_ref(), message)
            .map_err(|e| signature::Error::from_source(e))?;
        Ok(Signature {
            algorithm: Algorithm::Ed25519,
            data: sig.to_vec(),
        })
    }
}

#[cfg(feature = "ed25519")]
impl Verifier<Signature> for Ed25519PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Ed25519 => {}
            _ => return Err(signature::Error::new()),
        }
        ed25519_verify(self.as_ref(), message, signature.as_bytes())
            .map_err(|e| signature::Error::from_source(e))
    }
}

#[cfg(feature = "ed25519")]
impl Verifier<Signature> for public::SkEd25519 {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let (sig_part, flags_and_counter) = split_sk_signature(signature)?;
        let signed_data = make_sk_signed_data(self.application(), flags_and_counter, message);
        ed25519_verify(self.public_key().as_ref(), &signed_data, sig_part)
            .map_err(|e| signature::Error::from_source(e))
    }
}

#[cfg(feature = "p256")]
impl Verifier<Signature> for public::SkEcdsaSha2NistP256 {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let (signature_bytes, flags_and_counter) = split_sk_signature(signature)?;
        let signed_data = make_sk_signed_data(self.application(), flags_and_counter, message);
        ecdsa_verify_message(
            EcdsaCurve::NistP256,
            self.ec_point().as_bytes(),
            &signed_data,
            signature_bytes,
        )
        .map_err(|e| signature::Error::from_source(Error::from(e)))
    }
}

#[cfg(any(feature = "p256", feature = "ed25519"))]
fn make_sk_signed_data(application: &str, flags_and_counter: &[u8], message: &[u8]) -> Vec<u8> {
    const SHA256_OUTPUT_LENGTH: usize = 32;
    const SIGNED_SK_DATA_LENGTH: usize = 2 * SHA256_OUTPUT_LENGTH + SK_SIGNATURE_TRAILER_SIZE;

    let mut signed_data = Vec::with_capacity(SIGNED_SK_DATA_LENGTH);
    signed_data.extend(Sha256::digest(application));
    signed_data.extend(flags_and_counter);
    signed_data.extend(Sha256::digest(message));
    signed_data
}

#[cfg(any(feature = "p256", feature = "ed25519"))]
fn split_sk_signature(signature: &Signature) -> Result<(&[u8], &[u8])> {
    let signature_bytes = signature.as_bytes();
    let signature_len = signature_bytes
        .len()
        .checked_sub(SK_SIGNATURE_TRAILER_SIZE)
        .ok_or(Error::Encoding(encoding::Error::Length))?;
    Ok((
        &signature_bytes[..signature_len],
        &signature_bytes[signature_len..],
    ))
}

// ---------------------------------------------------------------------------
// wolfcrypt-backed ECDSA signing helpers
// ---------------------------------------------------------------------------

/// Maximum digest size across all supported ECDSA curves (SHA-512 = 64 bytes).
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
const MAX_ECDSA_DIGEST_SIZE: usize = 64;

/// Hash `message` with the curve-appropriate SHA, writing into a stack buffer.
/// Returns `(buffer, length)` — the digest is `&buf[..len]`.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ecdsa_hash_message(curve: EcdsaCurve, message: &[u8]) -> ([u8; MAX_ECDSA_DIGEST_SIZE], usize) {
    use sha2::{Digest as _, Sha256, Sha384, Sha512};
    let mut buf = [0u8; MAX_ECDSA_DIGEST_SIZE];
    let len = match curve {
        EcdsaCurve::NistP256 => {
            let d = Sha256::digest(message);
            buf[..d.len()].copy_from_slice(&d);
            d.len()
        }
        EcdsaCurve::NistP384 => {
            let d = Sha384::digest(message);
            buf[..d.len()].copy_from_slice(&d);
            d.len()
        }
        EcdsaCurve::NistP521 => {
            let d = Sha512::digest(message);
            buf[..d.len()].copy_from_slice(&d);
            d.len()
        }
    };
    (buf, len)
}

// ---------------------------------------------------------------------------
// ECDSA signature format bridge: DER ↔ SSH wire format
// ---------------------------------------------------------------------------
//
// wolfCrypt's `EccKey::sign_hash()` produces a **DER-encoded** ECDSA
// signature (ASN.1 SEQUENCE of two INTEGERs):
//
//     SEQUENCE { INTEGER r, INTEGER s }
//     30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
//
// The SSH wire format (RFC 5656 §3.1.2, extending RFC 4253 §6.6) encodes
// ECDSA signatures as two SSH `mpint` values concatenated:
//
//     string    identifier    (e.g. "ecdsa-sha2-nistp256")
//     string    signature_blob:
//         mpint   r
//         mpint   s
//
// An SSH `mpint` is a 4-byte big-endian length prefix followed by the
// minimal big-endian two's-complement encoding of the integer (with a
// leading 0x00 byte if the high bit is set, to avoid being negative).
//
// These two functions convert between the formats using wolfCrypt's own
// `wc_ecc_sig_to_rs` / `wc_ecc_rs_raw_to_sig` for DER parsing/encoding
// and ssh-encoding's `Mpint` for SSH wire encoding/decoding.
// ---------------------------------------------------------------------------

/// Convert a DER-encoded ECDSA signature to SSH wire format
/// (`Mpint(r) || Mpint(s)`).
///
/// Flow: DER → wolfCrypt extracts raw (r, s) → encode as SSH mpints.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn der_sig_to_ssh(der: &[u8]) -> Result<Vec<u8>> {
    let (r_bytes, s_bytes) = wolfcrypt::ecc::ecc_sig_der_to_rs(der).map_err(Error::from)?;

    let mut data = Vec::with_capacity(r_bytes.len() + s_bytes.len() + 12);
    Mpint::from_positive_bytes(&r_bytes)?.encode(&mut data)?;
    Mpint::from_positive_bytes(&s_bytes)?.encode(&mut data)?;
    Ok(data)
}

/// Convert SSH wire-format ECDSA signature (`Mpint(r) || Mpint(s)`) to
/// DER-encoded form for wolfCrypt's `verify_hash`.
///
/// Flow: decode SSH mpints → raw (r, s) bytes → wolfCrypt encodes as DER.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ssh_sig_to_der(data: &[u8]) -> Result<Vec<u8>> {
    let reader = &mut &*data;
    let r = Mpint::decode(reader)?;
    let s = Mpint::decode(reader)?;

    let r_bytes = r.as_positive_bytes().ok_or(Error::Crypto)?;
    let s_bytes = s.as_positive_bytes().ok_or(Error::Crypto)?;

    wolfcrypt::ecc::ecc_sig_rs_to_der(r_bytes, s_bytes).map_err(Error::from)
}

/// Map an [`EcdsaCurve`] to a wolfcrypt [`wolfcrypt::ecc::EccCurveId`].
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ecdsa_curve_to_ecc_id(curve: EcdsaCurve) -> wolfcrypt::ecc::EccCurveId {
    match curve {
        EcdsaCurve::NistP256 => wolfcrypt::ecc::EccCurveId::SecP256R1,
        EcdsaCurve::NistP384 => wolfcrypt::ecc::EccCurveId::SecP384R1,
        EcdsaCurve::NistP521 => wolfcrypt::ecc::EccCurveId::SecP521R1,
    }
}

/// Per-thread cached wolfCrypt RNG to avoid reinitializing the DRBG (and
/// reseeding from the OS entropy source) on every ECDSA/RSA signature.
#[cfg(all(
    feature = "std",
    any(feature = "p256", feature = "p384", feature = "p521", feature = "rsa")
))]
fn with_cached_rng<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut wolfcrypt::rand::WolfRng) -> Result<T>,
{
    std::thread_local! {
        static RNG: core::cell::RefCell<Option<wolfcrypt::rand::WolfRng>> =
            const { core::cell::RefCell::new(None) };
    }

    RNG.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let rng = match borrow.as_mut() {
            Some(rng) => rng,
            None => {
                *borrow = Some(wolfcrypt::rand::WolfRng::new().map_err(Error::from)?);
                borrow.as_mut().expect("RNG was just inserted into the Option")
            }
        };
        f(rng)
    })
}

/// Fallback for no_std: create a fresh RNG each time.
#[cfg(all(
    not(feature = "std"),
    any(feature = "p256", feature = "p384", feature = "p521", feature = "rsa")
))]
fn with_cached_rng<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut wolfcrypt::rand::WolfRng) -> Result<T>,
{
    let mut rng = wolfcrypt::rand::WolfRng::new().map_err(Error::from)?;
    f(&mut rng)
}

/// Sign `message` with an ECDSA private key using wolfcrypt's generic ECC API.
///
/// Returns the SSH wire-format signature data (`Mpint(r) || Mpint(s)`).
///
/// Imports the private scalar via `EccKey::from_private`, which tells
/// wolfCrypt the curve ID and lets it derive the public point internally.
/// This avoids a separate public-key derivation step.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ecdsa_sign_message(
    curve: EcdsaCurve,
    private_key_bytes: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let (hash_buf, hash_len) = ecdsa_hash_message(curve, message);
    let hash = &hash_buf[..hash_len];
    let curve_id = ecdsa_curve_to_ecc_id(curve);

    let mut key =
        wolfcrypt::ecc::EccKey::from_private(curve_id, private_key_bytes).map_err(Error::from)?;

    let der_sig = with_cached_rng(|rng| key.sign_hash(hash, rng).map_err(Error::from))?;

    der_sig_to_ssh(&der_sig)
}

/// Verify an SSH ECDSA signature using wolfcrypt's generic ECC API.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ecdsa_verify_message(
    curve: EcdsaCurve,
    public_key_sec1: &[u8],
    message: &[u8],
    ssh_sig_data: &[u8],
) -> Result<()> {
    let (hash_buf, hash_len) = ecdsa_hash_message(curve, message);
    let hash = &hash_buf[..hash_len];
    let der_sig = ssh_sig_to_der(ssh_sig_data)?;

    let mut key = wolfcrypt::ecc::EccKey::from_public_x963(public_key_sec1).map_err(Error::from)?;

    let valid = key.verify_hash(&der_sig, &hash).map_err(Error::from)?;
    if valid {
        Ok(())
    } else {
        Err(Error::Crypto)
    }
}

// Signing impls for each curve size

/// Sign with an `EcdsaPrivateKey` for the given curve.
///
/// Maps `SIZE` → `EcdsaCurve` and delegates to [`ecdsa_sign_message`],
/// which imports the private key once and derives the public point internally.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn ecdsa_try_sign(
    curve: EcdsaCurve,
    private_key: &[u8],
    message: &[u8],
) -> signature::Result<Signature> {
    let data = ecdsa_sign_message(curve, private_key, message)
        .map_err(|e| signature::Error::from_source(e))?;
    Ok(Signature {
        algorithm: Algorithm::Ecdsa { curve },
        data,
    })
}

#[cfg(feature = "p256")]
impl Signer<Signature> for EcdsaPrivateKey<32> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        ecdsa_try_sign(EcdsaCurve::NistP256, self.as_ref(), message)
    }
}

#[cfg(feature = "p384")]
impl Signer<Signature> for EcdsaPrivateKey<48> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        ecdsa_try_sign(EcdsaCurve::NistP384, self.as_ref(), message)
    }
}

#[cfg(feature = "p521")]
impl Signer<Signature> for EcdsaPrivateKey<66> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        ecdsa_try_sign(EcdsaCurve::NistP521, self.as_ref(), message)
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
impl Signer<Signature> for EcdsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            #[cfg(feature = "p256")]
            Self::NistP256 { private, .. } => private.try_sign(message),
            #[cfg(feature = "p384")]
            Self::NistP384 { private, .. } => private.try_sign(message),
            #[cfg(feature = "p521")]
            Self::NistP521 { private, .. } => private.try_sign(message),
            #[cfg(not(all(feature = "p256", feature = "p384", feature = "p521")))]
            _ => Err(self.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
impl Verifier<Signature> for EcdsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Ecdsa { curve } => {
                ecdsa_verify_message(curve, self.as_sec1_bytes(), message, signature.as_bytes())
                    .map_err(|e| signature::Error::from_source(Error::from(e)))
            }
            _ => Err(signature.algorithm().unsupported_error().into()),
        }
    }
}

/// Sign `message` with an RSA private key using PKCS#1v1.5 (RFC 8017 §8.2).
///
/// # Performance note
///
/// Creates a fresh `NativeRsaKey` from raw components on every call.
/// wolfCrypt recomputes CRT coefficients (dp, dq) and sets up internal
/// Montgomery tables each time — significant work for 4096-bit keys.
/// Caching the handle would help bulk-signing workloads (SSH agents)
/// but requires adding a non-Clone wolfCrypt handle to `RsaKeypair`,
/// which changes the struct layout.  Not done yet — the per-sign cost
/// is still dominated by the RSA modular exponentiation itself.
#[cfg(feature = "rsa")]
fn rsa_try_sign(
    keypair: &RsaKeypair,
    hash: Option<HashAlg>,
    message: &[u8],
) -> signature::Result<Signature> {
    let n_bytes = keypair
        .public()
        .n()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;
    let e_bytes = keypair
        .public()
        .e()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;
    let d_bytes = keypair
        .private()
        .d()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;
    let p_bytes = keypair
        .private()
        .p()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;
    let q_bytes = keypair
        .private()
        .q()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;
    let iqmp_bytes = keypair
        .private()
        .iqmp()
        .as_positive_bytes()
        .ok_or(signature::Error::new())?;

    // Import directly from raw components — wolfCrypt computes dp/dq.
    let wc_key = wolfcrypt::rsa::NativeRsaKey::from_raw_components(
        n_bytes, e_bytes, d_bytes, p_bytes, q_bytes, iqmp_bytes,
    )
    .map_err(|e| signature::Error::from_source(Error::from(e)))?;

    // Hash the message and build the DigestInfo (RFC 8017 §9.2)
    let digest_info = build_digest_info(hash, message)
        .map_err(|e| signature::Error::from_source(Error::from(e)))?;

    // PKCS#1v1.5 sign via NativeRsaKey — uses cached thread-local RNG
    let sig = with_cached_rng(|rng| {
        wc_key
            .sign_pkcs1v15_raw(&digest_info, rng)
            .map_err(Error::from)
    })
    .map_err(|e| signature::Error::from_source(e))?;

    Ok(Signature {
        algorithm: Algorithm::Rsa { hash },
        data: sig,
    })
}

/// Build a DER-encoded DigestInfo for RSA PKCS#1v1.5 signing (RFC 8017 §9.2).
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm  AlgorithmIdentifier,
///     digest           OCTET STRING
/// }
/// ```
///
/// The prefixes below are the fixed DER encodings of everything before the
/// hash value itself: the outer SEQUENCE header, the AlgorithmIdentifier
/// (OID + NULL parameters), and the OCTET STRING header.  They come
/// verbatim from RFC 8017 §9.2 Note 1 and never vary at runtime.
///
/// To add a new hash algorithm, encode:
///   `SEQUENCE { SEQUENCE { OID <hash-oid>, NULL }, OCTET STRING (<digest-len> bytes) }`
/// and extract everything up to (but not including) the hash bytes.
#[cfg(feature = "rsa")]
fn build_digest_info(hash: Option<HashAlg>, message: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256, Sha512};

    //                          ┌ SEQUENCE (outer)
    //                          │     ┌ SEQUENCE (AlgorithmIdentifier)
    //                          │     │     ┌ OID
    //                          │     │     │                              ┌ NULL params
    //                          │     │     │                              │     ┌ OCTET STRING header
    //                          ▼     ▼     ▼                              ▼     ▼
    // SHA-256 (32-byte digest):
    // 30 31  30 0d  06 09 60 86 48 01 65 03 04 02 01  05 00  04 20
    //
    // SHA-512 (64-byte digest):
    // 30 51  30 0d  06 09 60 86 48 01 65 03 04 02 03  05 00  04 40
    //
    // SHA-1   (20-byte digest):
    // 30 21  30 09  06 05 2b 0e 03 02 1a              05 00  04 14

    let (prefix, hash_output): (&[u8], Vec<u8>) = match hash {
        Some(HashAlg::Sha256) => (
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Sha256::digest(message).to_vec(),
        ),
        Some(HashAlg::Sha512) => (
            &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            Sha512::digest(message).to_vec(),
        ),
        #[cfg(feature = "sha1")]
        None => (
            &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            {
                use sha1::Sha1;
                Sha1::digest(message).to_vec()
            },
        ),
        #[cfg(not(feature = "sha1"))]
        None => return Err(Error::AlgorithmUnknown),
    };

    let mut di = Vec::with_capacity(prefix.len() + hash_output.len());
    di.extend_from_slice(prefix);
    di.extend_from_slice(&hash_output);
    Ok(di)
}

#[cfg(feature = "rsa")]
impl Signer<Signature> for RsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        rsa_try_sign(self, Some(HashAlg::Sha512), message)
    }
}

#[cfg(feature = "rsa")]
impl Verifier<Signature> for RsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Rsa { hash } => {
                let n_bytes = self
                    .n()
                    .as_positive_bytes()
                    .ok_or(signature::Error::new())?;
                let e_bytes = self
                    .e()
                    .as_positive_bytes()
                    .ok_or(signature::Error::new())?;

                // Import into wolfcrypt NativeRsaKey from raw (n, e)
                let wc_key = import_rsa_public_key(n_bytes, e_bytes)
                    .map_err(|e| signature::Error::from_source(Error::from(e)))?;

                // Recover the DigestInfo from the signature
                let recovered = wc_key
                    .verify_pkcs1v15_raw(&signature.data)
                    .map_err(|e| signature::Error::from_source(Error::from(e)))?;

                // Build the expected DigestInfo from the message
                let expected = build_digest_info(hash, message)
                    .map_err(|e| signature::Error::from_source(Error::from(e)))?;

                // Constant-time comparison
                use subtle::ConstantTimeEq;
                if recovered.ct_eq(&expected).into() {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                }
            }
            _ => Err(signature.algorithm().unsupported_error().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;
    use crate::{Algorithm, EcdsaCurve, HashAlg};
    use alloc::vec::Vec;
    use encoding::Encode;
    use hex_literal::hex;

    #[cfg(any(feature = "ed25519", all(feature = "rsa", feature = "sha1")))]
    use signature::Verifier;
    #[cfg(feature = "ed25519")]
    use {super::Ed25519Keypair, signature::Signer};

    const DSA_SIGNATURE: &[u8] = &hex!(
        "000000077373682d6473730000002866725bf3c56100e975e21fff28a60f73717534d285ea3e1beefc2891f7189d00bd4d94627e84c55c"
    );
    const ECDSA_SHA2_P256_SIGNATURE: &[u8] = &hex!(
        "0000001365636473612d736861322d6e6973747032353600000048000000201298ab320720a32139cda8a40c97a13dc54ce032ea3c6f09ea9e87501e48fa1d0000002046e4ac697a6424a9870b9ef04ca1182cd741965f989bd1f1f4a26fd83cf70348"
    );
    const ED25519_SIGNATURE: &[u8] = &hex!(
        "0000000b7373682d65643235353139000000403d6b9906b76875aef1e7b2f1e02078a94f439aebb9a4734da1a851a81e22ce0199bbf820387a8de9c834c9c3cc778d9972dcbe70f68d53cc6bc9e26b02b46d04"
    );
    const SK_ED25519_SIGNATURE: &[u8] = &hex!(
        "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d000000402f5670b6f93465d17423878a74084bf331767031ed240c627c8eb79ab8fa1b935a1fd993f52f5a13fec1797f8a434f943a6096246aea8dd5c8aa922cba3d95060100000009"
    );
    const RSA_SHA512_SIGNATURE: &[u8] = &hex!(
        "0000000c7273612d736861322d3531320000018085a4ad1a91a62c00c85de7bb511f38088ff2bce763d76f4786febbe55d47624f9e2cffce58a680183b9ad162c7f0191ea26cab001ac5f5055743eced58e9981789305c208fc98d2657954e38eb28c7e7f3fbe92393a14324ed77aebb772a41aa7a107b38cb9bd1d9ad79b275135d1d7e019bb1d56d74f2450be6db0771f48f6707d3fcf9789592ca2e55595acc16b6e8d0139b56c5d1360b3a1e060f4151a3d7841df2c2a8c94d6f8a1bf633165ee0bcadac5642763df0dd79d3235ae5506595145f199d8abe8f9980411bf70a16e30f273736324d047043317044c36374d6a5ed34cac251e01c6795e4578393f9090bf4ae3e74a0009275a197315fc9c62f1c9aec1ba3b2d37c3b207e5500df19e090e7097ebc038fb9c9e35aea9161479ba6b5190f48e89e1abe51e8ec0e120ef89776e129687ca52d1892c8e88e6ef062a7d96b8a87682ca6a42ff1df0cdf5815c3645aeed7267ca7093043db0565e0f109b796bf117b9d2bb6d6debc0c67a4c9fb3aae3e29b00c7bd70f6c11cf53c295ff"
    );

    /// Example test vector for signing.
    #[cfg(any(feature = "ed25519", all(feature = "rsa", feature = "sha1")))]
    const EXAMPLE_MSG: &[u8] = b"Hello, world!";

    #[test]
    fn decode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Dsa, signature.algorithm());
    }

    #[test]
    fn decode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            },
            signature.algorithm()
        );
    }

    #[test]
    fn decode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Ed25519, signature.algorithm());
    }

    #[test]
    fn decode_sk_ed25519() {
        let signature = Signature::try_from(SK_ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::SkEd25519, signature.algorithm());
    }

    #[test]
    fn decode_rsa() {
        let signature = Signature::try_from(RSA_SHA512_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            },
            signature.algorithm()
        );
    }

    #[test]
    fn encode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();
        let result = signature.encode_vec().unwrap();
        assert_eq!(DSA_SIGNATURE, &result);
    }

    #[test]
    fn encode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();
        let result = signature.encode_vec().unwrap();
        assert_eq!(ECDSA_SHA2_P256_SIGNATURE, &result);
    }

    #[test]
    fn encode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();
        let result = signature.encode_vec().unwrap();
        assert_eq!(ED25519_SIGNATURE, &result);
    }

    #[test]
    fn encode_sk_ed25519() {
        let signature = Signature::try_from(SK_ED25519_SIGNATURE).unwrap();
        let result = signature.encode_vec().unwrap();
        assert_eq!(SK_ED25519_SIGNATURE, &result);
    }

    const SK_ECDSA_P256_SIGNATURE: &[u8] = &hex!(
        "00000022736b2d65636473612d736861322d6e69737470323536406f70656e73"
        "73682e636f6d00000049000000201b35a1c6469a43a3d09d490d6ff8ca1bc248"
        "6a2edeb8aa7d119e4c70b9c1811000000021009724a2a4449a90357485ed1df0"
        "161274d20083342b02756794bc3f068fcdc15e01000000ec"
    );

    #[test]
    fn decode_sk_ecdsa_p256() {
        let signature = Signature::try_from(SK_ECDSA_P256_SIGNATURE).unwrap();
        assert_eq!(Algorithm::SkEcdsaSha2NistP256, signature.algorithm());
    }

    #[test]
    fn encode_sk_ecdsa_p256() {
        let signature = Signature::try_from(SK_ECDSA_P256_SIGNATURE).unwrap();
        let result = signature.encode_vec().unwrap();
        assert_eq!(SK_ECDSA_P256_SIGNATURE, &result);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn sign_and_verify_ed25519() {
        let keypair = Ed25519Keypair::from_seed(&[42; 32]);
        let signature = keypair.sign(EXAMPLE_MSG);
        assert!(keypair.public.verify(EXAMPLE_MSG, &signature).is_ok());
    }

    #[test]
    fn placeholder() {
        assert!(!Signature::try_from(ED25519_SIGNATURE)
            .unwrap()
            .is_placeholder());

        let placeholder = Signature::placeholder();
        assert!(placeholder.is_placeholder());

        let mut writer = Vec::new();
        assert_eq!(
            placeholder.encode(&mut writer),
            Err(encoding::Error::Length)
        );
    }

    #[cfg(all(feature = "rsa", feature = "sha1"))]
    #[test]
    fn sign_and_verify_rsa_sha1() {
        use encoding::Decode;

        use crate::PrivateKey;

        let key = PrivateKey::from_openssh(include_str!("../tests/examples/id_rsa_3072")).unwrap();
        let key = key.key_data().rsa().unwrap();
        let encoded = hex!(
            "000000077373682d727361000001809485247d72bf853272c86dd8c1c3fa0d2bebcdea9d91a376525a4bcc4a9ca2b19d31af48cfc07da086b244c65b37f3eb8fcab9661ccf777ed2f45404dd602b405526e19323f065b44d19f1bbda3eaf87b922b01049fcd8b82f08ffab6582e8427b0af3305f32961816d499d7b4925c1293b2d658dc6ca7cfb2d47c203c7d9512c0ee33e3d74f362d339a112fc94a74e8f388fc7fd1e9b95c7dd94e62ff16c9463476b7cf0e42af0f17fd2b9e325a50fc40ffd02b4a39e692727186b47c8ce9d7037de7e94615966df462238e214e7440bedabc5fbf79cfa93b96be5f27268da7c1ae2246bcabcc18a0d2c507be8727d04e41ed38686e5c455c159ee371f477668e89720191a72fbdb4eef86f1aa5c3596cefad12b20b1a1220accf6145f8583d7559751b2d0445e2e8a8fda85bf30f24b446ac6d0b943f7c519e5a021b1468cf120ed565d95ed8ddf022f97537ec5491226198ec58dd96c6bd218ddb237aa80785ceafa7722f1d2ba3e39dce2a9fdb0038f4124e2aa27d28eef927d87c8708f6"
        );

        let decoded = Signature::decode(&mut &encoded[..]).unwrap();

        assert!(Verifier::verify(key.public(), EXAMPLE_MSG, &decoded).is_ok());
    }
}
