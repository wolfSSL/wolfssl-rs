//! ML-DSA key pair implementation using wolfCrypt's native Dilithium API.

use crate::wolfcrypt_rs::{
    wc_dilithium_key, WC_RNG,
    wc_dilithium_init, wc_dilithium_free, wc_dilithium_set_level,
    wc_dilithium_make_key, wc_dilithium_make_key_from_seed,
    wc_dilithium_sign_ctx_msg,
    wc_dilithium_export_public, wc_dilithium_export_private,
    wc_dilithium_import_key,
    wc_InitRng, wc_FreeRng,
};
use crate::error::{KeyRejected, Unspecified};
use crate::pqdsa::signature::{PqdsaSigningAlgorithm, PublicKey};
use crate::pqdsa::AlgorithmID;
use crate::signature::KeyPair;
use core::fmt::{Debug, Formatter};

#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// A PQDSA (Post-Quantum Digital Signature Algorithm) key pair, used for signing and verification.
///
/// Wraps wolfCrypt Dilithium key material: both the expanded private key and
/// the corresponding public key bytes are stored for efficient sign operations.
#[allow(clippy::module_name_repetitions)]
pub struct PqdsaKeyPair {
    algorithm: &'static PqdsaSigningAlgorithm,
    /// Raw private key bytes (expanded secret key, KEY_SIZE bytes).
    priv_key: Box<[u8]>,
    /// Raw public key bytes.
    pubkey: PublicKey,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for PqdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqdsaKeyPair")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl KeyPair for PqdsaKeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

/// A PQDSA private key reference (for serialization).
pub struct PqdsaPrivateKey<'a>(pub(crate) &'a PqdsaKeyPair);

impl PqdsaPrivateKey<'_> {
    /// Returns the raw key bytes in combined format: `private_key || public_key`.
    ///
    /// The returned bytes can be passed to `PqdsaKeyPair::from_raw_private_key`
    /// for reconstruction. The combined format is used because wolfCrypt requires
    /// both private and public key components for signing operations.
    pub fn as_raw_bytes(&self) -> Result<PqdsaPrivateKeyRaw, Unspecified> {
        let mut combined = Vec::with_capacity(
            self.0.priv_key.len() + self.0.pubkey.octets.len()
        );
        combined.extend_from_slice(&self.0.priv_key);
        combined.extend_from_slice(&self.0.pubkey.octets);
        Ok(PqdsaPrivateKeyRaw(combined.into_boxed_slice()))
    }
}

/// Wrapper for raw ML-DSA private key bytes.
pub struct PqdsaPrivateKeyRaw(Box<[u8]>);

impl AsRef<[u8]> for PqdsaPrivateKeyRaw {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Helper: initialize a dilithium_key with the given security level.
unsafe fn init_dilithium_key(key: &mut wc_dilithium_key, id: &AlgorithmID) -> Result<(), Unspecified> {
    let rc = wc_dilithium_init(key);
    if rc != 0 {
        return Err(Unspecified);
    }
    let rc = wc_dilithium_set_level(key, id.level());
    if rc != 0 {
        wc_dilithium_free(key);
        return Err(Unspecified);
    }
    Ok(())
}

/// Helper: export public key bytes from an initialized dilithium_key.
unsafe fn export_public_key(key: &mut wc_dilithium_key, id: &AlgorithmID) -> Result<Box<[u8]>, Unspecified> {
    let pub_size = id.pub_key_size_bytes();
    let mut pub_buf = vec![0u8; pub_size];
    let mut pub_len = pub_size as u32;
    let rc = wc_dilithium_export_public(key, pub_buf.as_mut_ptr(), &mut pub_len);
    if rc != 0 || pub_len as usize != pub_size {
        return Err(Unspecified);
    }
    Ok(pub_buf.into_boxed_slice())
}

/// Helper: export private key bytes from an initialized dilithium_key.
unsafe fn export_private_key(key: &mut wc_dilithium_key, id: &AlgorithmID) -> Result<Box<[u8]>, Unspecified> {
    let priv_size = id.priv_key_size_bytes();
    let mut priv_buf = vec![0u8; priv_size];
    let mut priv_len = priv_size as u32;
    let rc = wc_dilithium_export_private(key, priv_buf.as_mut_ptr(), &mut priv_len);
    if rc != 0 || priv_len as usize != priv_size {
        return Err(Unspecified);
    }
    Ok(priv_buf.into_boxed_slice())
}

/// Helper: import both private + public key into a dilithium_key for signing.
unsafe fn import_key_pair(
    key: &mut wc_dilithium_key,
    priv_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), Unspecified> {
    let rc = wc_dilithium_import_key(
        priv_bytes.as_ptr(),
        priv_bytes.len() as u32,
        pub_bytes.as_ptr(),
        pub_bytes.len() as u32,
        key,
    );
    if rc != 0 {
        return Err(Unspecified);
    }
    Ok(())
}

impl PqdsaKeyPair {
    /// Generates a new PQDSA key pair for the specified algorithm.
    ///
    /// # Errors
    /// Returns `Unspecified` if the key generation fails.
    pub fn generate(algorithm: &'static PqdsaSigningAlgorithm) -> Result<Self, Unspecified> {
        let id = algorithm.0.id;
        // SAFETY: zeroed structs are valid initial state; wolfCrypt key/rng freed on all paths.
        unsafe {
            let mut rng = WC_RNG::zeroed();
            let rc = wc_InitRng(&mut rng);
            if rc != 0 {
                return Err(Unspecified);
            }

            let mut key = wc_dilithium_key::zeroed();
            let result = (|| -> Result<Self, Unspecified> {
                init_dilithium_key(&mut key, id)?;

                let rc = wc_dilithium_make_key(&mut key, &mut rng);
                if rc != 0 {
                    return Err(Unspecified);
                }

                let pub_bytes = export_public_key(&mut key, id)?;
                let priv_bytes = export_private_key(&mut key, id)?;

                Ok(Self {
                    algorithm,
                    priv_key: priv_bytes,
                    pubkey: PublicKey::new(pub_bytes),
                })
            })();

            wc_dilithium_free(&mut key);
            wc_FreeRng(&mut rng);
            result
        }
    }

    /// Constructs a key pair from raw key bytes.
    ///
    /// Accepts the combined format: `private_key || public_key` where
    /// `private_key` is `KEY_SIZE` bytes and `public_key` is `PUB_KEY_SIZE`
    /// bytes. This is the format produced by `PqdsaPrivateKey::as_raw_bytes`.
    ///
    /// wolfCrypt requires both private and public key components for import
    /// and signing operations — the public key cannot be derived from the
    /// private key alone.
    ///
    /// # Errors
    /// Returns `KeyRejected` if the key bytes are the wrong size or invalid
    /// for the specified signing algorithm.
    pub fn from_raw_private_key(
        algorithm: &'static PqdsaSigningAlgorithm,
        raw_private_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        let id = algorithm.0.id;
        let priv_size = id.priv_key_size_bytes();
        let pub_size = id.pub_key_size_bytes();
        let combined_size = priv_size + pub_size;

        if raw_private_key.len() != combined_size {
            return Err(KeyRejected::wrong_algorithm());
        }

        let priv_bytes = &raw_private_key[..priv_size];
        let pub_bytes = &raw_private_key[priv_size..];

        // SAFETY: zeroed struct is valid initial state; wolfCrypt key freed on all paths.
        unsafe {
            let mut key = wc_dilithium_key::zeroed();
            let result = (|| -> Result<Self, KeyRejected> {
                init_dilithium_key(&mut key, id)
                    .map_err(|_| KeyRejected::unspecified())?;

                import_key_pair(&mut key, priv_bytes, pub_bytes)
                    .map_err(|_| KeyRejected::unspecified())?;

                Ok(Self {
                    algorithm,
                    priv_key: priv_bytes.to_vec().into_boxed_slice(),
                    pubkey: PublicKey::new(pub_bytes.to_vec().into_boxed_slice()),
                })
            })();

            wc_dilithium_free(&mut key);
            result
        }
    }

    /// Constructs a key pair deterministically from a 32-byte seed.
    ///
    /// Per FIPS 204, the same seed always produces the same key pair.
    ///
    /// # Errors
    /// Returns `KeyRejected::too_small()` if `seed.len() < 32`.
    /// Returns `KeyRejected::too_large()` if `seed.len() > 32`.
    /// Returns `KeyRejected::unspecified()` if the underlying cryptographic operation fails.
    pub fn from_seed(
        algorithm: &'static PqdsaSigningAlgorithm,
        seed: &[u8],
    ) -> Result<Self, KeyRejected> {
        let id = algorithm.0.id;
        let expected_seed_len = id.seed_size_bytes();
        match seed.len().cmp(&expected_seed_len) {
            core::cmp::Ordering::Less => return Err(KeyRejected::too_small()),
            core::cmp::Ordering::Greater => return Err(KeyRejected::too_large()),
            core::cmp::Ordering::Equal => {}
        }

        // SAFETY: zeroed struct is valid initial state; wolfCrypt key freed on all paths.
        unsafe {
            let mut key = wc_dilithium_key::zeroed();
            let result = (|| -> Result<Self, KeyRejected> {
                init_dilithium_key(&mut key, id)
                    .map_err(|_| KeyRejected::unspecified())?;

                let rc = wc_dilithium_make_key_from_seed(&mut key, seed.as_ptr());
                if rc != 0 {
                    return Err(KeyRejected::unspecified());
                }

                let pub_bytes = export_public_key(&mut key, id)
                    .map_err(|_| KeyRejected::unspecified())?;
                let priv_bytes = export_private_key(&mut key, id)
                    .map_err(|_| KeyRejected::unspecified())?;

                Ok(Self {
                    algorithm,
                    priv_key: priv_bytes,
                    pubkey: PublicKey::new(pub_bytes),
                })
            })();

            wc_dilithium_free(&mut key);
            result
        }
    }

    /// Uses this key to sign the message provided. The signature is written to the `signature`
    /// slice provided. It returns the length of the signature on success.
    ///
    /// # Errors
    /// Returns `Unspecified` if signing fails.
    pub fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Unspecified> {
        let id = self.algorithm.0.id;
        let sig_length = id.signature_size_bytes();
        if signature.len() < sig_length {
            return Err(Unspecified);
        }

        // SAFETY: zeroed structs are valid initial state; wolfCrypt key/rng freed on all paths.
        unsafe {
            let mut rng = WC_RNG::zeroed();
            let rc = wc_InitRng(&mut rng);
            if rc != 0 {
                return Err(Unspecified);
            }

            let mut key = wc_dilithium_key::zeroed();
            let result = (|| -> Result<usize, Unspecified> {
                init_dilithium_key(&mut key, id)?;

                // Import both private and public key for signing
                import_key_pair(
                    &mut key,
                    &self.priv_key,
                    self.pubkey.octets.as_ref(),
                )?;

                let mut sig_len = sig_length as u32;
                // Use FIPS 204 context-aware signing with empty context.
                let rc = wc_dilithium_sign_ctx_msg(
                    core::ptr::null(),  // empty context
                    0,                  // context length = 0
                    msg.as_ptr(),
                    msg.len() as u32,
                    signature.as_mut_ptr(),
                    &mut sig_len,
                    &mut key,
                    &mut rng,
                );
                if rc != 0 {
                    return Err(Unspecified);
                }

                Ok(sig_len as usize)
            })();

            wc_dilithium_free(&mut key);
            wc_FreeRng(&mut rng);
            result
        }
    }

    /// Returns the signing algorithm associated with this key pair.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaSigningAlgorithm {
        self.algorithm
    }

    /// Returns the private key associated with this key pair.
    #[must_use]
    pub fn private_key(&self) -> PqdsaPrivateKey<'_> {
        PqdsaPrivateKey(self)
    }
}

unsafe impl Send for PqdsaKeyPair {}
unsafe impl Sync for PqdsaKeyPair {}

#[cfg(all(test, feature = "unstable"))]
mod tests {
    use super::*;
    use crate::signature::UnparsedPublicKey;
    use crate::unstable::signature::{ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};

    const TEST_ALGORITHMS: &[&PqdsaSigningAlgorithm] =
        &[&ML_DSA_44_SIGNING, &ML_DSA_65_SIGNING, &ML_DSA_87_SIGNING];

    #[test]
    fn test_generate_sign_verify_roundtrip() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            let message = b"Test message for ML-DSA";
            let mut signature = vec![0u8; alg.signature_len()];
            let sig_len = keypair.sign(message, &mut signature).unwrap();
            assert_eq!(sig_len, alg.signature_len());

            let verify_alg = alg.0;
            let pk = UnparsedPublicKey::new(verify_alg, keypair.public_key().as_ref());
            pk.verify(message, &signature).unwrap();
        }
    }

    #[test]
    fn test_sign_buffer_too_small() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            let message = b"Test message";
            let mut small_buf = vec![0u8; alg.signature_len() - 1];
            assert!(keypair.sign(message, &mut small_buf).is_err());
        }
    }

    #[test]
    fn test_from_seed() {
        for &alg in TEST_ALGORITHMS {
            let seed = [1u8; 32];
            let kp = PqdsaKeyPair::from_seed(alg, &seed).unwrap();
            assert_eq!(kp.algorithm(), alg);
            let msg = b"seed test";
            let mut sig = vec![0; alg.signature_len()];
            let sig_len = kp.sign(msg, &mut sig).unwrap();
            assert_eq!(sig_len, alg.signature_len());
        }
    }

    #[test]
    fn test_from_seed_deterministic() {
        for &alg in TEST_ALGORITHMS {
            let seed = [42u8; 32];
            let kp1 = PqdsaKeyPair::from_seed(alg, &seed).unwrap();
            let kp2 = PqdsaKeyPair::from_seed(alg, &seed).unwrap();
            assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
        }
    }

    #[test]
    fn test_from_seed_wrong_size() {
        for &alg in TEST_ALGORITHMS {
            assert_eq!(
                PqdsaKeyPair::from_seed(alg, &[0u8; 31]).err(),
                Some(KeyRejected::too_small())
            );
            assert_eq!(
                PqdsaKeyPair::from_seed(alg, &[0u8; 33]).err(),
                Some(KeyRejected::too_large())
            );
            assert_eq!(
                PqdsaKeyPair::from_seed(alg, &[]).err(),
                Some(KeyRejected::too_small())
            );
        }
    }

    #[test]
    fn test_from_seed_different_seeds_different_keys() {
        for &alg in TEST_ALGORITHMS {
            let kp1 = PqdsaKeyPair::from_seed(alg, &[1u8; 32]).unwrap();
            let kp2 = PqdsaKeyPair::from_seed(alg, &[2u8; 32]).unwrap();
            assert_ne!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
        }
    }

    #[test]
    fn test_from_seed_raw_private_key_roundtrip() {
        for &alg in TEST_ALGORITHMS {
            let seed = [55u8; 32];
            let kp = PqdsaKeyPair::from_seed(alg, &seed).unwrap();
            let raw_bytes = kp.private_key().as_raw_bytes().unwrap();
            let kp2 = PqdsaKeyPair::from_raw_private_key(alg, raw_bytes.as_ref()).unwrap();
            assert_eq!(kp.public_key().as_ref(), kp2.public_key().as_ref());
        }
    }

    #[test]
    fn test_from_seed_same_seed_different_algorithms() {
        let seed = [42u8; 32];
        let kp_44 = PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, &seed).unwrap();
        let kp_65 = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed).unwrap();
        let kp_87 = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).unwrap();
        assert_ne!(
            kp_44.public_key().as_ref().len(),
            kp_65.public_key().as_ref().len()
        );
        assert_ne!(
            kp_65.public_key().as_ref().len(),
            kp_87.public_key().as_ref().len()
        );
    }

    #[test]
    fn test_algorithm_getter() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            assert_eq!(keypair.algorithm(), alg);
        }
    }

    #[test]
    fn test_debug() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            let debug_str = format!("{keypair:?}");
            assert!(
                debug_str.starts_with("PqdsaKeyPair { algorithm: PqdsaSigningAlgorithm(PqdsaVerificationAlgorithm { id:"),
                "{debug_str}"
            );
            let pubkey = keypair.public_key();
            let pk_debug = format!("{pubkey:?}");
            assert!(pk_debug.starts_with("PqdsaPublicKey("), "{pk_debug}");
        }
    }

    #[test]
    fn test_negative_verify_wrong_key() {
        for &alg in TEST_ALGORITHMS {
            let kp1 = PqdsaKeyPair::generate(alg).unwrap();
            let kp2 = PqdsaKeyPair::generate(alg).unwrap();
            let msg = b"wrong key test";
            let mut sig = vec![0u8; alg.signature_len()];
            kp1.sign(msg, &mut sig).unwrap();

            let wrong_pk = UnparsedPublicKey::new(alg.0, kp2.public_key().as_ref());
            assert!(wrong_pk.verify(msg, &sig).is_err());
        }
    }

    #[test]
    fn test_negative_corrupted_signature() {
        for &alg in TEST_ALGORITHMS {
            let kp = PqdsaKeyPair::generate(alg).unwrap();
            let msg = b"corrupted sig test";
            let mut sig = vec![0u8; alg.signature_len()];
            kp.sign(msg, &mut sig).unwrap();

            sig[0] ^= 0xff;
            let pk = UnparsedPublicKey::new(alg.0, kp.public_key().as_ref());
            assert!(pk.verify(msg, &sig).is_err());
        }
    }
}
