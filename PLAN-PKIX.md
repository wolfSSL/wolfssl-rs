# Plan: wolfcrypt-pkix

Add a new workspace crate `wolfcrypt-pkix` that implements `pkix_path::SignatureVerifier`
backed by wolfCrypt, enabling FIPS-validated and hardware-offloaded certificate chain
verification in the PKIX stack.

**Reference source**: `~/PROJECT/PKIX/` — the pkix workspace (pkix-path, pkix-revocation,
pkix-chain). Do not modify those crates; this crate adapts to their published API.

**Pattern to follow**: `wolfcrypt-dpe` — no FFI, no unsafe, pure glue between an external
trait and the `wolfcrypt` crate's safe Rust API.

---

## Why this crate

`pkix-path` exposes a `SignatureVerifier` trait as its pluggable crypto seam. The default
backend (`DefaultVerifier`) uses pure-Rust RustCrypto crates. `wolfcrypt-pkix` provides an
alternative backend so that:

- **FIPS deployments** swap in FIPS 140-2/3 validated implementations by enabling
  `features = ["wolfcrypt-pkix/fips"]` — no logic changes needed.
- **Hardware-offloaded deployments** register a CryptoCb device (HSM/TPM) and use
  `features = ["wolfcrypt-pkix/cryptocb-only"]` to route all key operations there.
- **Post-quantum** certificate chains using ML-DSA are supported via `features = ["mldsa"]`,
  ahead of the RustCrypto ecosystem stabilising ML-DSA.

The pkix-path crate itself stays pure Rust and `no_std`-clean. This crate holds all C FFI
transitivity and the wolfSSL license constraint.

---

## Design decisions

1. **Single crate, not a 3-crate stack.** There is no FFI in this crate — all unsafe code
   lives in `wolfcrypt-rs` and `wolfcrypt`. This is glue code only.

2. **`no_std + alloc`.** `pkix-path` is `no_std`. This crate must be too, so it can be
   used in embedded environments (Caliptra, DPE) that also need FIPS certificate validation.

3. **`publish = false` until `pkix-path` hits crates.io.** The `pkix-path` dependency will
   initially be a path dep. Flip to a versioned dep and remove `publish = false` when
   pkix-path is published.

4. **`verify_prehash` for ECDSA, not the `Verifier` trait.** The `Verifier<EcdsaSignature<C>>`
   trait takes raw r||s bytes, but X.509 ECDSA signatures are DER-encoded. Using
   `verify_prehash(hash, sig_der)` avoids a DER-decode-to-r||s-then-reencode-to-DER round
   trip inside wolfcrypt. The hash is computed by calling the public `C::hash_message(msg)`
   method on the curve marker type.

5. **SPKI extraction per algorithm:**
   - RSA: `issuer_spki.to_der()` → `RsaPublicKey::from_der(&der)` (SPKI DER accepted directly).
   - ECDSA: `issuer_spki.subject_public_key.raw_bytes()` → uncompressed point (0x04||x||y)
     → `EcdsaVerifyingKey::from_uncompressed_point(bytes)`.
   - Ed25519: same raw_bytes approach → 32-byte key → `Ed25519VerifyingKey::from_bytes(&[u8; 32])`.
   - ML-DSA: raw_bytes → variable-length public key → `MlDsaVerifyingKey::from_bytes(bytes)`.

6. **Feature flags mirror `wolfcrypt-dpe`.** `fips`, `cryptocb-only`, `cryptocb-pure`, and
   `require-dev-id` are passthroughs to `wolfcrypt`. Algorithm features (`rsa`, `ecdsa`,
   `ed25519`, `mldsa`) are independent and additive.

---

## Cargo.toml

```toml
[package]
name        = "wolfcrypt-pkix"
authors     = ["WolfSSL Inc"]
version     = "0.1.0"
edition     = "2021"
license     = "GPL-3.0-only OR LicenseRef-wolfSSL-commercial"
description = "pkix-path SignatureVerifier backed by wolfCrypt"
homepage    = "http://wolfssl.com"
repository  = "https://github.com/wolfSSL/wolfssl-rs"
keywords    = ["wolfcrypt", "wolfssl", "x509", "pki", "fips"]
categories  = ["cryptography"]
# Remove publish = false once pkix-path is on crates.io and dep is versioned.
publish     = false

[lib]
name = "wolfcrypt_pkix"

[features]
default  = []

# Algorithm backends — additive and independent.
rsa      = ["wolfcrypt/rsa"]
ecdsa    = ["wolfcrypt/ecdsa"]
ed25519  = ["wolfcrypt/ed25519"]
mldsa    = ["wolfcrypt/mldsa"]

# All classical algorithms (RSA + ECDSA P-256/P-384 + Ed25519).
classical = ["rsa", "ecdsa", "ed25519"]

# wolfCrypt FIPS mode — routes all operations through the FIPS-validated boundary.
fips = ["wolfcrypt/fips"]

# CryptoCb passthrough features — mirror wolfcrypt-dpe exactly.
cryptocb-only  = ["wolfcrypt/cryptocb-only"]
cryptocb-pure  = ["wolfcrypt/cryptocb-pure"]
require-dev-id = ["wolfcrypt/require-dev-id"]

[dependencies]
wolfcrypt = { version = "0.1.0", path = "../wolfcrypt", default-features = false }

# pkix-path: the trait we implement.
# Path dep until pkix-path is published to crates.io.
pkix-path = { path = "../../PROJECT/PKIX/pkix-path", default-features = false }

# For re-encoding SubjectPublicKeyInfoRef → DER bytes (RSA key import).
spki = { version = "0.7", default-features = false, features = ["alloc"] }

# For constructing the error type returned by SignatureVerifier.
# Must match the version pkix-path uses internally (signature = "2").
signature = { version = "2", default-features = false }

[dev-dependencies]
der       = "0.7"
x509-cert = { version = "0.2", features = ["std"] }
hex-literal = "0.4"
```

---

## Module structure

```
wolfcrypt-pkix/src/
  lib.rs        pub struct WolfCryptVerifier; impl SignatureVerifier; OID constants
  rsa.rs        RSA-PKCS1v15 SHA-{256,384,512} and RSA-PSS SHA-{256,384,512}
  ecdsa.rs      ECDSA P-256 (SHA-256) and P-384 (SHA-384)
  ed25519.rs    Ed25519
  mldsa.rs      ML-DSA-44, ML-DSA-65, ML-DSA-87
```

---

## `lib.rs`

```rust
#![no_std]
extern crate alloc;

use pkix_path::SignatureVerifier;
use signature::Error as SignatureError;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use spki::der::Encode as _;

// OIDs -----------------------------------------------------------------------

const OID_SHA256_WITH_RSA:    der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_WITH_RSA:    der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_WITH_RSA:    der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_RSASSA_PSS:         der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_ECDSA_SHA256:       der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384:       der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ED25519:            der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_ML_DSA_44:          der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const OID_ML_DSA_65:          der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const OID_ML_DSA_87:          der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

// WolfCryptVerifier ----------------------------------------------------------

/// A [`SignatureVerifier`] backed by wolfCrypt.
///
/// Dispatches to wolfCrypt for all signature verification. Enable the `fips`
/// feature to route operations through the FIPS-validated boundary, or
/// `cryptocb-only` + a registered CryptoCb device to offload to hardware.
///
/// Algorithms supported per feature:
///
/// | Feature  | OIDs handled |
/// |----------|-------------|
/// | `rsa`    | sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption |
/// | `ecdsa`  | ecdsa-with-SHA256 (P-256), ecdsa-with-SHA384 (P-384) |
/// | `ed25519`| id-Ed25519 |
/// | `mldsa`  | id-ML-DSA-44, id-ML-DSA-65, id-ML-DSA-87 |
#[derive(Clone, Copy, Debug, Default)]
pub struct WolfCryptVerifier;

impl SignatureVerifier for WolfCryptVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        let oid = algorithm.oid;

        #[cfg(feature = "rsa")]
        match oid {
            OID_SHA256_WITH_RSA => return crate::rsa::verify_pkcs1v15(issuer_spki, message, signature, wolfcrypt::rsa::RsaDigest::Sha256),
            OID_SHA384_WITH_RSA => return crate::rsa::verify_pkcs1v15(issuer_spki, message, signature, wolfcrypt::rsa::RsaDigest::Sha384),
            OID_SHA512_WITH_RSA => return crate::rsa::verify_pkcs1v15(issuer_spki, message, signature, wolfcrypt::rsa::RsaDigest::Sha512),
            _ => {}
        }

        #[cfg(feature = "ecdsa")]
        match oid {
            OID_ECDSA_SHA256 => return crate::ecdsa::verify_p256(issuer_spki, message, signature),
            OID_ECDSA_SHA384 => return crate::ecdsa::verify_p384(issuer_spki, message, signature),
            _ => {}
        }

        #[cfg(feature = "ed25519")]
        if oid == OID_ED25519 {
            return crate::ed25519::verify(issuer_spki, message, signature);
        }

        #[cfg(feature = "mldsa")]
        match oid {
            OID_ML_DSA_44 => return crate::mldsa::verify_44(issuer_spki, message, signature),
            OID_ML_DSA_65 => return crate::mldsa::verify_65(issuer_spki, message, signature),
            OID_ML_DSA_87 => return crate::mldsa::verify_87(issuer_spki, message, signature),
            _ => {}
        }

        Err(SignatureError::new())
    }
}
```

---

## `rsa.rs`

```rust
use crate::SignatureError;
use spki::SubjectPublicKeyInfoRef;
use spki::der::Encode as _;
use wolfcrypt::rsa::{RsaDigest, RsaPkcs1v15Signature, RsaPublicKey};

/// Verify RSA-PKCS1v15 for a given digest.
///
/// Key import: re-encode the SubjectPublicKeyInfoRef to DER so wolfCrypt's
/// `wolfcrypt_rsa_import_public_spki` can parse it. This is a one-time
/// heap allocation per verification call (tracked for v0.2 caching).
pub(crate) fn verify_pkcs1v15(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
    digest: RsaDigest,
) -> Result<(), SignatureError> {
    let spki_der = issuer_spki.to_der().map_err(|_| SignatureError::new())?;
    let key = RsaPublicKey::from_der(&spki_der).map_err(|_| SignatureError::new())?;
    let sig = RsaPkcs1v15Signature::try_from(signature).map_err(|_| SignatureError::new())?;
    key.verify_pkcs1v15_with_digest(message, &sig, digest)
        .map_err(|_| SignatureError::new())
}
```

**RSA-PSS note**: `OID_RSASSA_PSS` uses algorithm parameters to encode the hash and MGF1
algorithm. Parsing `AlgorithmIdentifierRef::parameters` for PSS is tracked as a v0.2 item.
v0.1 returns `SignatureError::new()` for PSS OID (i.e., unsupported).

---

## `ecdsa.rs`

```rust
use crate::SignatureError;
use spki::SubjectPublicKeyInfoRef;
use wolfcrypt::ecdsa::{EcdsaCurve, EcdsaVerifyingKey, P256};
#[cfg(wolfssl_ecc_p384)]
use wolfcrypt::ecdsa::P384;

/// Verify ECDSA-P256-SHA256.
///
/// Key import: extract the raw uncompressed public point (0x04 || x || y)
/// from the SPKI bit string. wolfCrypt's `wc_ecc_import_x963` accepts this format.
///
/// Signature: `verify_prehash(hash, sig_der)` is used directly rather than
/// the `Verifier<EcdsaSignature<C>>` trait, because X.509 ECDSA signatures
/// are DER-encoded (SEQUENCE { r, s }) not raw r||s. This avoids a
/// DER→r||s→DER round trip inside wolfCrypt.
pub(crate) fn verify_p256(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let raw_key = issuer_spki.subject_public_key.raw_bytes();
    let key = EcdsaVerifyingKey::<P256>::from_uncompressed_point(raw_key)
        .map_err(|_| SignatureError::new())?;
    let hash = P256::hash_message(message).map_err(|_| SignatureError::new())?;
    key.verify_prehash(&hash, signature).map_err(|_| SignatureError::new())
}

/// Verify ECDSA-P384-SHA384.
#[cfg(wolfssl_ecc_p384)]
pub(crate) fn verify_p384(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let raw_key = issuer_spki.subject_public_key.raw_bytes();
    let key = EcdsaVerifyingKey::<P384>::from_uncompressed_point(raw_key)
        .map_err(|_| SignatureError::new())?;
    let hash = P384::hash_message(message).map_err(|_| SignatureError::new())?;
    key.verify_prehash(&hash, signature).map_err(|_| SignatureError::new())
}

/// Stub for builds where P-384 is not compiled into wolfSSL.
#[cfg(not(wolfssl_ecc_p384))]
pub(crate) fn verify_p384(
    _issuer_spki: SubjectPublicKeyInfoRef<'_>,
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), SignatureError> {
    Err(SignatureError::new())
}
```

---

## `ed25519.rs`

```rust
use crate::SignatureError;
use spki::SubjectPublicKeyInfoRef;
use wolfcrypt::ed25519::Ed25519VerifyingKey;
use signature::Verifier as _;

const ED25519_KEY_SIZE: usize = 32;
const ED25519_SIG_SIZE: usize = 64;

pub(crate) fn verify(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let raw_key = issuer_spki.subject_public_key.raw_bytes();
    let key_bytes: &[u8; ED25519_KEY_SIZE] = raw_key
        .try_into()
        .map_err(|_| SignatureError::new())?;
    let key = Ed25519VerifyingKey::from_bytes(key_bytes).map_err(|_| SignatureError::new())?;

    let sig_bytes: &[u8; ED25519_SIG_SIZE] = signature
        .try_into()
        .map_err(|_| SignatureError::new())?;
    let sig = ed25519::Signature::from_bytes(sig_bytes);

    key.verify(message, &sig).map_err(|_| SignatureError::new())
}
```

**Note**: `ed25519::Signature` comes from the `ed25519` crate (already a dep of wolfcrypt
via `ed25519_trait`). Add `ed25519 = { version = "2.2", default-features = false }` to
`[dependencies]` in Cargo.toml alongside the wolfcrypt dep.

---

## `mldsa.rs`

```rust
use crate::SignatureError;
use spki::SubjectPublicKeyInfoRef;
use wolfcrypt::mldsa::{MlDsa44VerifyingKey, MlDsa65VerifyingKey, MlDsa87VerifyingKey};
use signature::Verifier as _;

pub(crate) fn verify_44(issuer_spki: SubjectPublicKeyInfoRef<'_>, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    verify_mldsa::<MlDsa44VerifyingKey>(issuer_spki, message, signature)
}

pub(crate) fn verify_65(issuer_spki: SubjectPublicKeyInfoRef<'_>, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    verify_mldsa::<MlDsa65VerifyingKey>(issuer_spki, message, signature)
}

pub(crate) fn verify_87(issuer_spki: SubjectPublicKeyInfoRef<'_>, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    verify_mldsa::<MlDsa87VerifyingKey>(issuer_spki, message, signature)
}

fn verify_mldsa<K>(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError>
where
    K: for<'a> TryFrom<&'a [u8], Error = wolfcrypt::WolfCryptError>
     + signature::Verifier<wolfcrypt::mldsa::MlDsaSignature<K::Level>>,
    K: MlDsaVerifyingKeyLevel,  // sealed helper trait — see below
{
    let raw_key = issuer_spki.subject_public_key.raw_bytes();
    let key = K::try_from(raw_key).map_err(|_| SignatureError::new())?;
    let sig = wolfcrypt::mldsa::MlDsaSignature::<K::Level>::try_from(signature)
        .map_err(|_| SignatureError::new())?;
    key.verify(message, &sig).map_err(|_| SignatureError::new())
}
```

**Note**: The generic helper above requires wolfcrypt to expose `from_bytes(&[u8])` (i.e.
`TryFrom<&[u8]>`) on each `MlDsaVerifyingKey<L>`. Verify this is available before coding;
if not, write three non-generic functions instead.

---

## Testing

All tests must use an independent oracle — never verify wolfcrypt output with wolfcrypt.

### Cross-validation suite (`tests/cross_verify.rs`)

For each supported algorithm:

1. **Key pair** generated by `openssl` or `pyca/cryptography`.
2. **Certificate** self-signed with that key, in DER binary.
3. **Expected result**: `Ok(())` for valid sig, `Err` for corrupted sig.

The certificates are the same PKITS fixture set used by `pkix-path`'s own tests. Copy
(do not regenerate) the fixtures from `~/PROJECT/PKIX/pkix-path/tests/fixtures/` to
`wolfcrypt-pkix/tests/fixtures/`.

Cross-validation strategy: for each fixture, verify using both `DefaultVerifier` (from
pkix-path) and `WolfCryptVerifier`. Both must return the same result. This catches
wolfcrypt returning `Ok` where RustCrypto returns `Err`, or vice versa.

```rust
fn cross_verify(cert_der: &[u8]) {
    let cert = Certificate::from_der(cert_der).unwrap();
    let tbs = cert.tbs_certificate.to_der().unwrap();
    let sig = cert.signature.raw_bytes();
    let alg = cert.signature_algorithm.owned_to_ref();
    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

    let rustcrypto = DefaultVerifier.verify_signature(alg, spki, &tbs, sig);
    let wc         = WolfCryptVerifier.verify_signature(alg, spki, &tbs, sig);

    assert_eq!(
        rustcrypto.is_ok(), wc.is_ok(),
        "RustCrypto and wolfCrypt disagree on {cert_der:02x?}"
    );
}
```

### Negative tests

For each algorithm, provide a fixture with a corrupted last byte of the signature DER.
Both verifiers must return `Err`.

### Unsupported OID

Feed an unknown OID (e.g., DSA with SHA-1). Must return `Err(SignatureError)`, not panic.

---

## Workspace integration

Add to `wolfssl-rs/Cargo.toml` workspace members:

```toml
"wolfcrypt-pkix",
```

No workspace-level dep entry needed — `wolfcrypt-pkix` uses path deps internally and is
not depended on by other workspace members.

---

## v0.1 scope limits

Document these in rustdoc `# Limitations`:

- RSA-PSS is not supported (OID `id-RSASSA-PSS`). v0.1 returns `SignatureError::new()`
  for PSS. Support requires parsing the `AlgorithmIdentifier.parameters` field (RSASSA-PSS
  params DER) to extract the hash and MGF1 algorithm. Tracked for v0.2.
- ECDSA P-521 is not supported in v0.1.
- ML-DSA requires `wolfssl_dilithium` cfg flag (wolfSSL compiled with `HAVE_DILITHIUM`).
  `verify_mldsa` returns `SignatureError::new()` when not compiled in.
- `TryFrom<&[u8]>` on `MlDsaVerifyingKey<L>` must be confirmed before implementation.
  If absent, open a wolfcrypt issue and use three non-generic functions instead.
- SPKI re-encoding for RSA (`.to_der()`) allocates on every call. Tracked for v0.2
  (cache parsed key in `WolfCryptVerifier`).

---

## Key constraints and gotchas

1. **`wolfssl_ecc_p384` is a `rustc-cfg` flag, not a Cargo feature.** Gate P-384 code with
   `#[cfg(wolfssl_ecc_p384)]` (emitted by `wolfcrypt-sys`), not `#[cfg(feature = "...")]`.

2. **ECDSA signature format mismatch.** X.509 ECDSA signatures are DER (SEQUENCE { r, s }).
   `EcdsaSignature<C>::from_bytes` takes raw r||s. Use `verify_prehash(hash, sig_der)`
   instead of the `Verifier` trait to avoid the round trip.

3. **`EcdsaCurve::hash_message` is public.** It is a method on the `pub trait EcdsaCurve`
   (sealed, so external types cannot implement it, but existing impls are callable). The
   call `P256::hash_message(msg)` is safe and does not require unsafe.

4. **RSA SPKI re-encoding.** `SubjectPublicKeyInfoRef` implements `spki::der::Encode`, so
   `.to_der()` works. This requires `spki` with `alloc` feature. If `spki::der::Encode` is
   not in scope, add `use spki::der::Encode as _;`.

5. **`signature` version alignment.** pkix-path uses `signature = "2"` internally but does
   not re-export `SignatureError`. wolfcrypt-pkix must depend on `signature = "2"` directly
   to construct `SignatureError::new()`. Verify semver compatibility with wolfcrypt's
   `signature 2.2` dep — they are in the same `^2` range and will unify.

6. **`ed25519` trait dep.** The `ed25519::Signature` type is from the `ed25519` crate
   (not `signature`). wolfcrypt already depends on it as `ed25519_trait`; wolfcrypt-pkix
   needs its own dep entry as `ed25519 = "2.2"`.

7. **`no_std` discipline.** Do not use `std::` anywhere. `alloc::vec::Vec` is fine.
   `spki::der::Encode::to_der()` returns `Result<Vec<u8>, ...>` — requires `alloc`.
