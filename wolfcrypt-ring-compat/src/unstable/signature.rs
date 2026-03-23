//! Unstable/experimental signature APIs: ML-DSA (post-quantum).
//!
//! # Warning
//! The APIs under this module are not stable and may change in the future.
//! They are not covered by semver guarantees.

pub use crate::pqdsa::key_pair::{PqdsaKeyPair, PqdsaPrivateKey};
pub use crate::pqdsa::signature::{
    PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, PublicKey as PqdsaPublicKey,
};

use crate::pqdsa::AlgorithmID;

/// ML-DSA-44 verification algorithm.
pub static ML_DSA_44: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::ML_DSA_44,
};

/// ML-DSA-65 verification algorithm.
pub static ML_DSA_65: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::ML_DSA_65,
};

/// ML-DSA-87 verification algorithm.
pub static ML_DSA_87: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::ML_DSA_87,
};

/// ML-DSA-44 signing algorithm.
pub static ML_DSA_44_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&ML_DSA_44);

/// ML-DSA-65 signing algorithm.
pub static ML_DSA_65_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&ML_DSA_65);

/// ML-DSA-87 signing algorithm.
pub static ML_DSA_87_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&ML_DSA_87);
