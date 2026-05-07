# ssh-key-wolfcrypt

SSH key file format decoders, encoders, signatures, and certificates,
with [wolfCrypt][wolfCrypt] as the cryptographic backend. Drop-in
replacement for the [RustCrypto `ssh-key`][upstream] crate.

## Why

`ssh-key` is the de-facto Rust crate for OpenSSH key, certificate, and
signature handling. Its pure-Rust crypto stack (`ed25519-dalek`,
`p256`/`p384`/`p521`, `rsa`) is not FIPS 140-3 certifiable.
`ssh-key-wolfcrypt` provides the same API with a FIPS-validatable
backend:

- **Drop-in replacement** — exports `lib.name = "ssh_key"`, so downstream
  code keeps `use ssh_key::PrivateKey;` unchanged. Swap the Cargo
  dependency and rebuild.
- **FIPS 140-3** — wolfCrypt is FIPS 140-3 validated; this is the
  migration path if your project uses `ssh-key`'s API and needs a
  FIPS-certifiable backend
  ([contact wolfSSL](https://www.wolfssl.com/license/) for the
  commercial FIPS license and validated source).
- **Single crypto stack** — Ed25519, ECDSA P-256/P-384/P-521, and RSA all
  go through wolfCrypt instead of four separate RustCrypto crates.
- **Format coverage unchanged** — non-cryptographic functionality (key
  parsing, encoding, certificates, fingerprints, `authorized_keys` and
  `known_hosts` files) is byte-for-byte identical to upstream.

## Usage

```toml
# Before (upstream RustCrypto):
# ssh-key = { version = "0.6", features = ["ed25519"] }

# After (wolfCrypt backend):
ssh-key-wolfcrypt = { path = "../ssh-key-wolfcrypt", features = ["ed25519"] }
```

```rust
use ssh_key::{PrivateKey, PublicKey};

let private = PrivateKey::from_openssh(include_bytes!("id_ed25519"))?;
let public = private.public_key();
let fingerprint = public.fingerprint(Default::default());
```

> **Do not pull in both `ssh-key` and `ssh-key-wolfcrypt`** in the same
> dependency tree. They export the same Rust library name (`ssh_key`)
> and will collide at link time. If a transitive dependency requires
> upstream `ssh-key`, redirect it via `[patch]`:
>
> ```toml
> [patch.crates-io]
> ssh-key = { path = "path/to/ssh-key-wolfcrypt" }
> ```

By default no SSH signature algorithms are enabled — calls return
`Error::AlgorithmUnsupported`. Enable individual algorithms via the
feature flags in the table below, or `crypto` for all of them.

## How it works

```text
ssh-key-wolfcrypt              ← this crate
   │  lib.name = "ssh_key"     (drop-in replacement)
   │
   ├─ format layer   (decoders, encoders, certs, sshsig, authorized_keys)
   │   └─ unchanged from upstream RustCrypto/ssh-key
   │
   └─ signature.rs   (FFI bridge to wolfCrypt)
       │   wolfcrypt::ed25519, wolfcrypt::ecc, wolfcrypt::rsa
       ▼
       wolfCrypt (wolfssl-src → wolfcrypt-sys → wolfcrypt-rs → wolfcrypt)
```

`signature.rs` calls wolfCrypt module APIs directly
(`ed25519_sign_raw`, `EccKey::from_private`, `NativeRsaKey::from_raw_components`,
etc.) rather than going through wolfCrypt's `signature::Signer` /
`signature::Verifier` trait impls. The reason is a transitive trait
version mismatch: this crate tracks upstream's `signature = 3.0.0-rc`,
while `wolfcrypt` is on the current stable `signature = 2.2`. The FFI
bridge lets the format layer move forward on the pre-release trait
version without waiting for `signature 3.0` to stabilise.

DSA support is intentionally absent. NIST deprecated DSA in FIPS 186-5
(2023) and OpenSSH 9.8 removed it (2024). Enabling the `dsa` feature
produces a compile error. DSA key *parsing* still works (gated on
`alloc`); only signing and verification are removed.

### Supported signature algorithms

| Name                                 | Decode | Encode | Cert | Keygen | Sign | Verify | Feature   | `no_std` |
|--------------------------------------|--------|--------|------|--------|------|--------|-----------|----------|
| `ecdsa-sha2-nistp256`                | yes    | yes    | yes  | yes    | yes  | yes    | `p256`    | heapless |
| `ecdsa-sha2-nistp384`                | yes    | yes    | yes  | yes    | yes  | yes    | `p384`    | heapless |
| `ecdsa-sha2-nistp521`                | yes    | yes    | yes  | yes    | yes  | yes    | `p521`    | heapless |
| `ssh-ed25519`                        | yes    | yes    | yes  | yes    | yes  | yes    | `ed25519` | heapless |
| `ssh-rsa`                            | yes    | yes    | yes  | yes    | yes  | yes    | `rsa`     | `alloc`  |
| `sk-ecdsa-sha2-nistp256@openssh.com` | yes    | yes    | yes  | n/a    | n/a  | yes    | n/a       | `alloc`  |
| `sk-ssh-ed25519@openssh.com`         | yes    | yes    | yes  | n/a    | n/a  | yes    | `ed25519` | `alloc`  |

FIDO/U2F keys (`sk-*`) are decoded and verified but not generated or
signed — those operations require a FIDO authenticator, not a software
backend.

### Other capability flags

| Feature | Description |
|---|---|
| `crypto` | Enable all signature algorithms (`ed25519`, `p256`, `p384`, `p521`, `rsa`) |
| `encryption` | OpenSSH private-key encryption (`bcrypt-pbkdf` + `aes256-ctr`) |
| `ppk` | PuTTY `.ppk` private-key format |
| `sha1` | SHA-1 fingerprints (legacy) |
| `tdes` | Triple-DES private-key encryption (legacy) |
| `serde` | `serde::Serialize`/`Deserialize` for public keys, fingerprints, certs |
| `std` | Default; depends on `alloc` |

## References

- [RustCrypto `ssh-key`][upstream] — upstream crate this is forked from
- [wolfCrypt][wolfCrypt] — cryptographic backend
- [RFC 4251] — SSH protocol architecture
- [RFC 4253] — SSH transport layer protocol
- [PROTOCOL.key] — OpenSSH private-key file format
- [PROTOCOL.certkeys] — OpenSSH certificates
- [PROTOCOL.sshsig] — OpenSSH detached signatures
- [PROTOCOL.u2f] — OpenSSH FIDO/U2F keys
- [wolfcrypt](../wolfcrypt) — safe Rust wolfCrypt API used for all crypto
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

The non-cryptographic portions of this crate are derived from the
[RustCrypto `ssh-key`][upstream] crate, copyright RustCrypto developers.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.

The underlying wolfSSL C library is licensed under GPL-3.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)

[upstream]: https://github.com/RustCrypto/SSH/tree/master/ssh-key
[wolfCrypt]: https://www.wolfssl.com/products/wolfcrypt/
[RFC 4251]: https://datatracker.ietf.org/doc/html/rfc4251
[RFC 4253]: https://datatracker.ietf.org/doc/html/rfc4253
[PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
[PROTOCOL.key]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
[PROTOCOL.sshsig]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD
[PROTOCOL.u2f]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD
