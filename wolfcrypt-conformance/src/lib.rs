//! Cross-validation and trait conformance tests for wolfcrypt.
//!
//! # Test vectors
//!
//! Tests require external vector files not shipped with the crate:
//!
//! - **Wycheproof**: Clone <https://github.com/google/wycheproof> and set
//!   `WYCHEPROOF_DIR` to the repo root.
//! - **CAVP/SHAVS**: Set `CONFORMANCE_VECTORS_DIR` to a directory containing
//!   `cavp/` and `shavs/` subdirectories with NIST test vector files.
//!
//! When running from the workspace checkout, vectors are found automatically
//! in `third_party/` and `vectors/`.
