# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2025-03-22)

Fork of [RustCrypto/SSH `ssh-key` v0.6.6](https://github.com/RustCrypto/SSH)
with all cryptographic operations replaced by a wolfCrypt backend.

### Changed
- Replaced all RustCrypto crypto backends (ed25519-dalek, p256, p384, p521,
  rsa) with wolfCrypt via the `wolfcrypt` crate
- Ed25519 signing/verification uses `wc_ed25519_sign_msg` / `wc_ed25519_verify_msg`
- ECDSA (P-256, P-384, P-521) signing/verification uses wolfCrypt's `EccKey` API
- RSA PKCS#1v1.5 signing/verification uses `wc_RsaSSL_Sign` / `wc_RsaSSL_Verify`
- RSA key generation uses `wc_MakeRsaKey` via `NativeRsaKey`
- ECDSA key generation uses wolfCrypt's `EccKey::generate`

### Removed
- DSA support (deprecated by NIST FIPS 186-5, removed from OpenSSH 9.8;
  enabling the `dsa` feature produces a compile error with rationale)
- All pure-Rust RustCrypto crypto dependencies (`ed25519-dalek`, `p256`,
  `p384`, `p521`, `rsa`, `dsa`)
