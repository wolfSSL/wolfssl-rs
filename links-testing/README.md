# links-testing

Internal build-system regression test for the wolfcrypt-rs workspace.
Not published to crates.io (`publish = false`).

## Why

The wolfcrypt-sys / wolfcrypt-rs / wolfcrypt-ring-compat chain relies on
Cargo's `links =` metadata to propagate include paths, library locations,
and `cargo:rustc-cfg` flags from the C-library-building crate to downstream
consumers. If any link in that chain stops emitting `DEP_<LINKS>_*` env
vars or `cargo:rustc-cfg`, downstream builds break in subtle ways that are
hard to diagnose at the use site.

`links-testing` exercises the propagation chain end-to-end so a CI run
fails immediately when the metadata path is broken, not weeks later when a
downstream crate misbehaves.

## How it works

`build.rs` selects exactly one upstream crate via mutually-exclusive
features (`wolfcrypt-rs`, `wolfcrypt-rs-fips`, `wolfcrypt-ring-compat`,
`wolfcrypt-ring-compat-fips`), reads that crate's `links` key from its
`Cargo.toml`, then verifies the full `DEP_<LINKS>_*` env-var contract:

| Variable | Purpose |
|---|---|
| `DEP_<L>_INCLUDE` | wolfSSL public header dir |
| `DEP_<L>_SETTINGS_INCLUDE` | `user_settings.h` include dir |
| `DEP_<L>_ROOT` | library output root for `rustc-link-search` |
| `DEP_<L>_LIBCRYPTO` | name of the static archive to link |
| `DEP_<L>_CFGS` | active `cargo:rustc-cfg` flags (re-emitted) |
| `DEP_<L>_ALL_CFGS` | full set for `rustc-check-cfg` |

A small C shim (`src/testing.c`) calls `wc_GetErrorString(0)` to confirm
the linked archive resolves wolfCrypt symbols. The `main` binary prints
the resulting string; `link_test` asserts the pointer is non-null.

Cfg propagation is verified by `#[cfg(wolfssl_*)]`-gated tests
(`cfg_propagation_aes_gcm`, `cfg_propagation_ecc`, etc.). These tests
contain no assertions — they exist only to be discovered by `cargo test`.
If a cfg flag did not propagate, the corresponding test compiles to
nothing and is absent from the run, so the test count drops below the
expected number for the active feature set.

## References

- [wolfcrypt-sys](../wolfcrypt-sys) — origin of the `links` metadata
- [wolfcrypt-rs](../wolfcrypt-rs) — typed wrapper consumer
- [wolfcrypt-ring-compat](../wolfcrypt-ring-compat) — `ring`-API consumer
- [Cargo `links` documentation](https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial.
