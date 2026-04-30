# ssh-key-wolfcrypt

SSH key file format decoders/encoders with wolfCrypt as the cryptographic
backend.

Fork of the [RustCrypto `ssh-key`][upstream] crate, replacing the pure-Rust
cryptographic implementations with [wolfCrypt] FFI calls for all signing,
verification, and key generation operations.

## Drop-in replacement for `ssh-key`

This crate exports `lib.name = "ssh_key"` so that downstream code written
against the upstream `ssh-key` crate works without source changes — just swap
the Cargo dependency:

```toml
# Before (upstream RustCrypto):
# ssh-key = { version = "0.6", features = ["ed25519"] }

# After (wolfCrypt backend):
ssh-key-wolfcrypt = { path = "../ssh-key-wolfcrypt", features = ["ed25519"] }
```

Downstream source files continue to use `use ssh_key::PrivateKey;` etc.

> **You must not have both `ssh-key` and `ssh-key-wolfcrypt` in the same
> dependency tree.** They export the same Rust library name (`ssh_key`) and
> will cause a linker/symbol collision. This crate is a *replacement*, not a
> companion. If another dependency pulls in `ssh-key`, use a `[patch]` section
> in your workspace `Cargo.toml` to redirect it:
>
> ```toml
> [patch.crates-io]
> ssh-key = { path = "path/to/ssh-key-wolfcrypt" }
> ```

## About

Implements SSH key file format decoders/encoders as described in [RFC4251]
and [RFC4253] as well as OpenSSH's [PROTOCOL.key] format specification.

Additionally provides support for SSH signatures as described in
[PROTOCOL.sshsig], OpenSSH certificates as specified in [PROTOCOL.certkeys]
including certificate validation and certificate authority (CA) support,
FIDO/U2F keys as specified in [PROTOCOL.u2f] (and certificates thereof), and
also the `authorized_keys` and `known_hosts` file formats.

Supports a minimal profile which works on heapless `no_std` targets. See
"Supported algorithms" table below for which key formats work on heapless
targets and which algorithms require `alloc`.

When the `ed25519`, `p256`, and/or `rsa` features of this crate are enabled,
provides key generation and certificate signing/verification support for that
respective SSH key algorithm, powered by wolfCrypt.

## Differences from upstream `ssh-key`

- All cryptographic operations (Ed25519, ECDSA, RSA) use wolfCrypt via FFI
  instead of pure-Rust `ed25519-dalek`, `p256`/`p384`/`p521`, and `rsa` crates.
- DSA support is removed. DSA was deprecated by NIST (FIPS 186-5, 2023) and
  removed from OpenSSH 9.8 (2024). Enabling the `dsa` feature produces a
  compile error.
- Non-cryptographic functionality (key parsing, encoding, certificates,
  fingerprints, `authorized_keys`/`known_hosts` files) is unchanged from
  upstream.

## Features

- [x] Constant-time Base64 decoder/encoder
- [x] OpenSSH-compatible decoder/encoders for the following formats:
  - [x] OpenSSH public keys
  - [x] OpenSSH private keys (i.e. `BEGIN OPENSSH PRIVATE KEY`)
  - [x] OpenSSH certificates
  - [x] OpenSSH signatures (a.k.a. "sshsig")
- [x] OpenSSH certificate support
  - [x] OpenSSH certificate validation
  - [x] OpenSSH certificate authority (CA) support i.e. cert builder/signer
- [x] Private key encryption/decryption (`bcrypt-pbkdf` + `aes256-ctr` only)
- [x] Private key generation support: Ed25519, ECDSA (P-256/P-384/P-521),
      and RSA
- [x] FIDO/U2F key support (`sk-*`) as specified in [PROTOCOL.u2f]
- [x] Fingerprint support
  - [x] "randomart" fingerprint visualizations
- [x] `no_std` support including support for "heapless" (no-`alloc`) targets
- [x] Parsing `authorized_keys` files
- [x] Parsing `known_hosts` files
- [x] `serde` support
- [x] `zeroize` support for private keys

### Supported Signature Algorithms

| Name                                 | Decode | Encode | Cert | Keygen | Sign | Verify | Feature   | `no_std` |
|--------------------------------------|--------|--------|------|--------|------|--------|-----------|----------|
| `ecdsa‑sha2‑nistp256`                | ✅     | ✅     | ✅   | ✅     | ✅   | ✅     | `p256`    | heapless |
| `ecdsa‑sha2‑nistp384`                | ✅     | ✅     | ✅   | ✅     | ✅   | ✅     | `p384`    | heapless |
| `ecdsa‑sha2‑nistp521`                | ✅     | ✅     | ✅   | ✅     | ✅   | ✅     | `p521`    | heapless |
| `ssh‑ed25519`                        | ✅     | ✅     | ✅   | ✅     | ✅   | ✅     | `ed25519` | heapless |
| `ssh‑rsa`                            | ✅     | ✅     | ✅   | ✅     | ✅   | ✅     | `rsa`     | `alloc`  |
| `sk‑ecdsa‑sha2‑nistp256@openssh.com` | ✅     | ✅     | ✅   | ⛔     | ⛔   | ✅     | ⛔        | `alloc`  |
| `sk‑ssh‑ed25519@openssh.com`         | ✅     | ✅     | ✅   | ⛔     | ⛔   | ✅     | `ed25519` | `alloc`  |

By default *no SSH signature algorithms are enabled* and you will get an
`Error::AlgorithmUnsupported` error if you try to use them.

Enable the `crypto` feature or the "Feature" for specific algorithms in the
chart above (e.g. `p256`, `rsa`) in order to use cryptographic functionality.

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum.

## FIPS 140-3

Need FIPS 140-3 validation in your Rust application?  wolfCrypt — the
cryptographic backend used by this crate — is FIPS 140-3 validated.
[Contact wolfSSL](https://www.wolfssl.com/license/) for a commercial FIPS
license and the validated source tree.

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

The non-cryptographic portions of this crate are derived from the
[RustCrypto ssh-key](https://github.com/RustCrypto/SSH/tree/master/ssh-key)
crate, copyright RustCrypto developers.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

The underlying wolfSSL/wolfCrypt C library is licensed under GPL-2.0-or-later
with a commercial option available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[upstream]: https://github.com/RustCrypto/SSH/tree/master/ssh-key
[wolfCrypt]: https://www.wolfssl.com/products/wolfcrypt/
[RFC4251]: https://datatracker.ietf.org/doc/html/rfc4251
[RFC4253]: https://datatracker.ietf.org/doc/html/rfc4253
[PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
[PROTOCOL.key]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
[PROTOCOL.sshsig]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD
[PROTOCOL.u2f]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD
