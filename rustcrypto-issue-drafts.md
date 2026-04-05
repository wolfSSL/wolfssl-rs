# RustCrypto Issue Drafts

These issues were discovered while implementing the `wolfcrypt` crate
([`wolfSSL/wolfssl-rs`](https://github.com/wolfSSL/wolfssl-rs)), which wraps
wolfCrypt — a widely-deployed, FIPS 140-3 validated C cryptographic library —
behind the standard RustCrypto trait interfaces (`digest`, `cipher`, `aead`,
`signature`, `rand_core`).

wolfCrypt is unusual among RustCrypto backends in two ways.  First, it is a C
FFI backend, so operations that are infallible in pure Rust (allocation, state
initialization) can fail at the C layer.  Second, it supports hardware
dispatch via its `WOLF_CRYPTO_CB` callback mechanism, which routes individual
algorithm operations to hardware accelerators or HSMs at runtime.  This means
that *every* crypto operation — not just key generation — can fail with a
device-specific error code at any point.

Together these two properties exposed gaps in the RustCrypto trait design that
pure-Rust implementations never encounter.  Each issue below documents one gap,
the exact workaround we were forced to use, and a proposed fix.  Code links
point to commit `0f3af10` of `wolfSSL/wolfssl-rs`.

If any of these are already tracked elsewhere, please point us to the existing
issue.

---

## Issue 1: Infallible constructors prevent FFI and hardware backends from reporting initialization failures

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `digest`, `cipher`, `aead`

### Background

Several RustCrypto traits define constructors that return `Self` rather than
`Result<Self, _>`:

- `KeyInit::new(key: &Key<Self>) -> Self` (used by `cipher`, `aead`, `mac`)
- `Digest::new() -> Self` (via `Default::default()`)
- `KeyIvInit::new(key: &Key<Self>, iv: &Iv<Self>) -> Self`

This is a reasonable design for pure-Rust implementations: once the key bytes
are valid (enforced by the type-level `GenericArray<u8, KeySize>`), construction
cannot fail.  There is nothing else to go wrong.

### The problem

For an FFI or hardware backend, "key bytes are valid" is necessary but not
sufficient.  Construction can fail for reasons that have nothing to do with the
key material:

- **C heap allocation failure** — wolfCrypt heap-allocates its hash and HMAC
  context structs (`wc_Sha256`, `Hmac`, etc.) because their sizes are not
  stable across wolfSSL versions.  If the allocator returns NULL, there is
  nothing the Rust type can do except panic or return zeroed memory.
- **Library not yet initialized** — wolfCrypt requires `wolfCrypt_Init()` to be
  called once at program startup.  Constructing a hash context before that
  returns an error code.
- **Hardware device unavailable** — when `WOLF_CRYPTO_CB` is active and a
  hardware device ID is registered, key schedule setup is dispatched to the
  hardware.  If the HSM is offline or busy, `wc_AesGcmSetKey` returns a
  non-zero error code.

The trait's `Self` return type gives us nowhere to put that error.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

Every constructor in the `wolfcrypt` crate that implements an infallible trait
method must `assert!` on the C return code, converting all initialization
failures into panics:

- AES-GCM `KeyInit::new` asserts on `wc_AesInit` and `wc_AesGcmSetKey`:
  [`wolfcrypt/src/aead.rs:60-70`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/aead.rs#L60-L70)
- SHA-256 `Default::default` asserts that the heap-allocated context pointer is
  non-null: [`wolfcrypt/src/digest.rs:57`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L57)
- HMAC `KeyInit::new` (via `init_with_key`) asserts on the allocator return:
  [`wolfcrypt/src/hmac.rs:64`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hmac.rs#L64)
- The crate-level documentation explains the policy and why it was unavoidable:
  [`wolfcrypt/src/lib.rs:75-85`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L75-L85)

### Why the obvious alternative doesn't work

`KeyInit::new_from_slice` returns `Result`, but its error type is
`InvalidLength` — it signals that the key bytes were the wrong size.  It is
not an appropriate channel for "the C allocator returned NULL" or "the HSM is
offline."

### Proposed change

Add a fallible constructor to the affected traits, leaving the infallible
version in place for pure-Rust implementations:

```rust
// In KeyInit:
fn try_new(key: &Key<Self>) -> Result<Self, impl Error>;

// Or as a separate trait with a blanket impl:
pub trait TryKeyInit: Sized {
    type Error: Error;
    fn try_new(key: &Key<Self>) -> Result<Self, Self::Error>;
}

impl<T: KeyInit> TryKeyInit for T {
    type Error = Infallible;
    fn try_new(key: &Key<Self>) -> Result<Self, Infallible> {
        Ok(Self::new(key))
    }
}
```

The separate-trait approach avoids any breaking change: existing code using
`KeyInit::new` continues to compile, and FFI backends implement `TryKeyInit`
instead of (or in addition to) `KeyInit`.

---

## Issue 2: `KeyInit` and related traits impose no `ZeroizeOnDrop` requirement on key-holding types

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `security`, `zeroize`

### Background

`KeyInit::new` and `KeyIvInit::new` create values that hold secret key
material — AES key schedules, HMAC keys, ECDSA signing keys.  The `zeroize`
crate provides `ZeroizeOnDrop`, a marker trait that guarantees memory holding
secret material is overwritten before it is freed.

### The problem

The `KeyInit` trait has no `ZeroizeOnDrop` supertrait bound and no
documentation requirement that implementors zeroize on drop.  Every implementor
must independently remember to add the guarantee.  The compiler does not warn
if it is missing.

This is a latent correctness problem for the ecosystem.  A crate that
implements `KeyInit` but forgets `ZeroizeOnDrop` compiles, passes tests, and
leaks key material from freed memory — silently.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

The `wolfcrypt` crate has at least ten distinct `impl Drop` blocks that call
the appropriate wolfCrypt free function and/or zeroize backing memory.  Each
one was written by hand, with no trait-level prompt that it was necessary:

- `Ed25519SigningKey::drop` calls `wc_ed25519_free` and `wc_FreeRng`:
  [`wolfcrypt/src/ed25519.rs:158-167`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L158-L167)
- `Ed25519VerifyingKey::drop` calls `wc_ed25519_free`:
  [`wolfcrypt/src/ed25519.rs:243-251`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L243-L251)
- `EccKey::drop` calls `wc_ecc_key_free`:
  [`wolfcrypt/src/ecc.rs:332-341`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ecc.rs#L332-L341)
- HMAC `Drop` calls `wolfcrypt_hmac_free`:
  [`wolfcrypt/src/hmac.rs:38-45`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hmac.rs#L38-L45)
- Digest macro-generated `Drop` calls the appropriate `wc_Sha*_Free`:
  [`wolfcrypt/src/digest.rs:73-79`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L73-L79)

### Proposed change

Add `ZeroizeOnDrop` as a supertrait on `KeyInit`:

```rust
pub trait KeyInit: KeySizeUser + Sized + ZeroizeOnDrop {
    fn new(key: &Key<Self>) -> Self;
    // ...
}
```

This is a breaking change for any existing `KeyInit` impl that does not already
derive or implement `ZeroizeOnDrop`.  For most pure-Rust crates, adding
`#[derive(ZeroizeOnDrop)]` or `impl ZeroizeOnDrop for MyKey {}` is a
one-line fix.

If a full supertrait bound is too disruptive for this release cycle, an
intermediate option is to document the requirement explicitly (with a
`#[must_implement = "ZeroizeOnDrop"]` lint or clippy rule) so that missing
implementations are at least detectable.

---

## Issue 3: No non-allocating separate-input/output AEAD interface; `AeadInPlace` is the only option for allocation-free code

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `aead`, `no-alloc`

### Background

The `aead` crate provides two interfaces:

- `Aead::encrypt(nonce, payload) -> Result<Vec<u8>>` — allocates a `Vec` for
  the output.
- `AeadInPlace::encrypt_in_place_detached(nonce, aad, buffer)` — mutates the
  plaintext buffer in-place; no allocation.

For `no_std + no alloc` code, `Aead::encrypt` is unavailable because it
requires `alloc`.  The only option is `AeadInPlace`.

### The problem

`AeadInPlace` requires that the plaintext and ciphertext occupy the *same*
buffer.  For some hardware and C library backends, this is not possible:

- **DMA-based hardware accelerators** write output to a separate DMA destination
  buffer.  They physically cannot write the ciphertext back over the plaintext
  in the same memory region.
- **C one-shot APIs** — wolfCrypt's `wc_ChaCha20Poly1305_Encrypt` takes
  separate `inData` and `outData` pointers.  There is no API contract that
  `inData == outData` is safe; the function may read from `inData` and write
  to `outData` simultaneously in ways that are undefined if they overlap.

The net result: a backend with a separate-buffer C API or DMA engine has no
allocation-free path to satisfy `AeadInPlace`.  Either it allocates a staging
buffer (negating the purpose of `AeadInPlace`) or it is ineligible to
implement the trait at all.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

We discovered this when implementing ChaCha20-Poly1305.  wolfCrypt's one-shot
API (`wc_ChaCha20Poly1305_Encrypt`) requires separate source and destination
pointers.  Wiring it to `AeadInPlace` would have required a heap allocation per
call to stage the output before copying it back over the input.

We worked around it by switching to wolfCrypt's streaming ChaCha20-Poly1305 API
(`wc_ChaCha20Poly1305_Init` / `UpdateData` / `Final`), which explicitly
supports identical `input == output` pointers via XOR-based keystream
application.  That escape hatch happened to exist for ChaCha20-Poly1305.  It
will not exist for every algorithm or every hardware backend.

- Comment explaining the streaming API choice:
  [`wolfcrypt/src/aead.rs:198-207`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/aead.rs#L198-L207)
- The streaming `wc_ChaCha20Poly1305_Init` call replacing the one-shot API:
  [`wolfcrypt/src/aead.rs:255-265`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/aead.rs#L255-L265)
- Crate-level docs explain the tradeoff:
  [`wolfcrypt/src/lib.rs:97-108`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L97-L108)

### Why `Aead::encrypt` doesn't solve this

`Aead::encrypt` takes separate input and output, but returns `Vec<u8>`.  It
requires `alloc` and is not available in `no_std` firmware targets.  A
DMA-backed hardware accelerator running on bare metal cannot use it.

### Proposed change

Add a non-allocating, separate-buffer AEAD trait alongside `AeadInPlace`:

```rust
pub trait AeadOutOfPlace: AeadCore + KeySizeUser {
    fn encrypt_into(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],  // must be >= plaintext.len() + Self::TagSize
    ) -> Result<(), Error>;

    fn decrypt_into(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<(), Error>;
}
```

A blanket `impl<T: AeadInPlace> AeadOutOfPlace for T` would give existing
implementations the two-buffer interface automatically (at the cost of one
`copy_from_slice`), while hardware backends that can do better implement it
directly.  No existing code breaks.

---

## Issue 4: No traits for HKDF or PBKDF2; alternative backends cannot interoperate with generic callers

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `hkdf`, `pbkdf2`

### Background

The `digest`, `cipher`, and `aead` crates define traits (`Digest`, `KeyInit`,
`AeadInPlace`) that any implementation can satisfy, making backends
interchangeable.  The `hkdf` and `pbkdf2` crates are different: they provide
concrete implementations, not traits.

There is no `HkdfExpand` trait, no `Pbkdf2` trait.  A function that needs
"some HKDF implementation" must name `hkdf::Hkdf<Sha256>` explicitly.

### The problem

This makes it impossible to swap in an alternative HKDF or PBKDF2 backend
without forking calling code.  The two most important cases where an
alternative backend matters are:

1. **FIPS 140-3 validated builds** — the validated HKDF and PBKDF2
   implementations are in wolfCrypt, not in the pure-Rust `hkdf`/`pbkdf2`
   crates.  A validated build must route through wolfCrypt's `wc_HKDF` and
   `wc_PBKDF2`.  Without a trait, any library that calls `hkdf::Hkdf::expand`
   directly cannot be used with a FIPS-validated backend.

2. **Hardware-accelerated key derivation** — some HSMs provide HKDF and PBKDF2
   as hardware-accelerated primitives.  There is no way to dispatch through
   them from generic Rust code that uses the `hkdf` or `pbkdf2` crates.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

The `wolfcrypt` crate's `hkdf` and `pbkdf2` modules expose bespoke APIs whose
method names mirror the `hkdf` and `pbkdf2` crates by convention, not by
trait:

- `hkdf` module header explains the absence of a trait:
  [`wolfcrypt/src/hkdf.rs:1-21`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hkdf.rs#L1-L21)
- Bespoke `new` / `extract` / `expand` API that mirrors `hkdf::Hkdf` by name
  only: [`wolfcrypt/src/hkdf.rs:46-134`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hkdf.rs#L46-L134)
- `pbkdf2` module and standalone functions:
  [`wolfcrypt/src/pbkdf2.rs:1-92`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/pbkdf2.rs#L1-L92)
- Crate-level docs explain why these are bespoke:
  [`wolfcrypt/src/lib.rs:110-121`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L110-L121)

### Proposed change

Define traits in a `kdf-traits` crate (or in `RustCrypto/traits`):

```rust
pub trait HkdfExpand {
    type Error;
    fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait HkdfExtract {
    type Prk: HkdfExpand;
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self::Prk;
}

pub trait Pbkdf2 {
    type Error;
    fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) -> Result<(), Self::Error>;
}
```

The concrete `hkdf::Hkdf` and `pbkdf2::pbkdf2_hmac` would implement these
traits.  Alternative backends (wolfCrypt, BoringSSL, HSMs) implement them
independently.  Generic code parameterizes over `impl HkdfExpand` instead of
naming a concrete type.

---

## Issue 5: `pbkdf2_hmac` requires low-level digest internals that opaque FFI backends structurally cannot provide

**Repo:** `RustCrypto/traits` (affects `pbkdf2` crate)
**Labels:** `api-design`, `pbkdf2`, `digest`

### Background

The `digest` crate has two implementation tiers:

**High-level tier** — the public API:
- `digest::Update::update(&mut self, data: &[u8])`
- `digest::FixedOutput::finalize_into(self, out: &mut Output<Self>)`
- The blanket `Digest` impl combines these with `Clone + Default + HashMarker`.

**Low-level (`core_api`) tier** — the composable building blocks:
- `UpdateCore::update_blocks(&mut self, blocks: &[Block<Self>])` — processes
  data one fixed-size block at a time.
- `FixedOutputCore::finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>)`
- `BufferKindUser` — specifies how the type buffers partial blocks.
- `CoreProxy` — a supertrait that bundles these together.

The low-level tier exists so that `hmac::SimpleHmac<D>` can be built from any
digest without knowing the concrete type.  `SimpleHmac<D>` is bounded on
`D: CoreProxy`.  `pbkdf2_hmac` builds a `SimpleHmac<D>` internally, so it
transitively requires `D: CoreProxy`.

### The problem

An opaque FFI wrapper structurally cannot implement the `core_api` tier.
`UpdateCore::update_blocks` requires processing data *exactly one fixed-size
block at a time*, handing partial blocks to a `Buffer` abstraction.  wolfCrypt's
`wc_Sha256Update` accepts arbitrary-length slices and handles its own internal
buffering in C.  There is no C API to call with individual 64-byte SHA-256
blocks and get back a partially-updated state.

This is not a matter of effort — the block-level API simply does not exist in
the C library.  The C implementation buffers internally and exposes only the
`update(data: *const u8, len: u32)` / `final(out: *mut u8)` interface.

Note: our digest types *do* implement `BlockSizeUser` (block size is a compile-
time constant we know) and the full high-level `Digest` trait:
[`wolfcrypt/src/digest.rs:87-89`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L87-L89).
The gap is specifically `UpdateCore` and `FixedOutputCore` — the block-granular
streaming API that `CoreProxy` requires.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

Despite implementing the complete high-level `Digest` trait, our types cannot
be used with `pbkdf2_hmac`:

```
error[E0277]: the trait bound `WolfSha256: CoreProxy` is not satisfied
```

We cannot satisfy this bound because `CoreProxy` requires `UpdateCore`, which
requires a block-level C API that wolfCrypt does not expose.

- `pbkdf2` module header explains the `CoreProxy` block:
  [`wolfcrypt/src/pbkdf2.rs:6-9`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/pbkdf2.rs#L6-L9)
- Crate-level docs § "The `CoreProxy` cliff":
  [`wolfcrypt/src/lib.rs:123-134`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L123-L134)
- Workaround — native `pbkdf2_hmac_sha256` calling `wc_PBKDF2` directly:
  [`wolfcrypt/src/pbkdf2.rs:28-92`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/pbkdf2.rs#L28-L92)

### Proposed change

The root cause is that `pbkdf2_hmac` forces the construction of `SimpleHmac<D>`
internally, pulling in the `CoreProxy` requirement.  A version that accepts a
`Mac` directly (already keyed with the password) would remove this:

```rust
pub fn pbkdf2_with_mac<M: Mac + KeyInit + Clone>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    res: &mut [u8],
) -> Result<(), InvalidLength>
```

Callers who currently use `pbkdf2_hmac::<Sha256>(password, salt, rounds, out)`
could migrate to `pbkdf2_with_mac::<HmacSha256>(password, salt, rounds, out)`.
FFI backends implement `Mac` (the high-level MAC trait, which only requires
`update` and `finalize_into`) and become immediately usable.

---

## Issue 6: `pbkdf2::pbkdf2` has an unconditional `PRF: Sync` bound; correctly `!Sync` MAC types cannot use it even single-threaded

**Repo:** `RustCrypto/traits` (affects `pbkdf2` crate)
**Labels:** `api-design`, `pbkdf2`

### Background

`pbkdf2::pbkdf2` has this signature (simplified):

```rust
pub fn pbkdf2<PRF: Mac + Sync>(prf: PRF, salt: &[u8], rounds: u32, res: &mut [u8])
    -> Result<(), InvalidLength>
```

The `Sync` bound exists to support the `parallel` feature, which distributes
PBKDF2 rounds across a thread pool.  When multiple threads run rounds
concurrently, they need to share the PRF instance — hence `Sync`.

### The problem

The `Sync` bound is present unconditionally, even when the `parallel` feature
is disabled and the function runs entirely on a single thread.  A type that is
correctly `!Sync` — because it holds interior mutable state that is unsafe to
share — cannot call `pbkdf2`, even in a single-threaded program with
`parallel = false`.

This is a logic error in the API: `Sync` is a *sharing* guarantee, and no
sharing occurs when `parallel` is off.  Requiring it in that case excludes
legitimate types for no benefit.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

wolfCrypt's EVP-based digest types (`WolfSha256`, etc.) are `!Sync`.  The
`EVP_MD_CTX` C struct contains interior mutable state — counter values, partial
block buffers — that is updated on every call.  It is not safe to read from two
threads simultaneously.  Marking these types `Sync` would be unsound.

Because `pbkdf2::pbkdf2` requires `PRF: Sync` unconditionally, this does not
compile even in a single-threaded binary with `parallel = false`:

```rust
pbkdf2::pbkdf2::<hmac::SimpleHmac<WolfSha256>>(password, salt, rounds, &mut out)?;
// error[E0277]: `WolfSha256` cannot be shared between threads safely
//   = help: the trait `Sync` is not implemented for `WolfSha256`
//   note: required by a bound in `pbkdf2`
```

- Crate-level docs § "`pbkdf2::pbkdf2` requires `Sync` unconditionally":
  [`wolfcrypt/src/lib.rs:136-145`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L136-L145)
- `pbkdf2` module explains why `SimpleHmac<WolfSha256>` is blocked:
  [`wolfcrypt/src/pbkdf2.rs:8-16`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/pbkdf2.rs#L8-L16)
- AES-GCM documents why the types are `!Sync`:
  [`wolfcrypt/src/aead.rs:22-27`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/aead.rs#L22-L27)

### Proposed change

Gate the `Sync` bound on the `parallel` feature flag:

```rust
#[cfg(feature = "parallel")]
pub fn pbkdf2<PRF: Mac + Clone + Sync>(
    prf: PRF, salt: &[u8], rounds: u32, res: &mut [u8],
) -> Result<(), InvalidLength> { ... }

#[cfg(not(feature = "parallel"))]
pub fn pbkdf2<PRF: Mac + Clone>(
    prf: PRF, salt: &[u8], rounds: u32, res: &mut [u8],
) -> Result<(), InvalidLength> { ... }
```

This is fully backward-compatible: all existing callers use `Sync` types and
are unaffected.  Callers with `!Sync` types gain access to the function when
`parallel` is not enabled.  This is the smallest and most self-contained change
in this set of issues.

---

## Issue 7: `SignatureEncoding::Repr` cannot represent variable-length or large post-quantum signatures

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `signature`, `post-quantum`

### Background

`signature::SignatureEncoding` allows a signature type to describe its wire
encoding:

```rust
pub trait SignatureEncoding: Clone + Sized + for<'a> TryFrom<&'a [u8]> {
    type Repr: 'static + AsRef<[u8]> + Clone + Send + Sync;
}
```

For classical signature schemes, `Repr` is always a fixed-size array.
Ed25519 signatures are exactly 64 bytes, so `type Repr = [u8; 64]`.
ECDSA-P256 (DER) is bounded and small.  The fixed-size array approach
compiles to stack allocation with no indirection.

### The problem

Post-quantum signature schemes break this model in two ways:

**1. Large sizes.**  ML-DSA-87 (FIPS 204) signatures are 4,627 bytes.  A
`[u8; 4627]` Repr is technically valid Rust, but it is 4 KB of stack space
per signature — enough to overflow typical embedded stacks.  Stack-allocating
signatures is inappropriate for PQC.

**2. Parameter-set variation.**  The ML-DSA family has three parameter sets
with different signature sizes: ML-DSA-44 (2,420 bytes), ML-DSA-65 (3,309
bytes), ML-DSA-87 (4,627 bytes).  A generic `MlDsaSignature<L>` type that
covers all three cannot have a single `[u8; N]` Repr because `N` is not a
single constant — it varies with `L`.  The `typenum`-based const-generic
approach works for key sizes but becomes unwieldy for unifying signature sizes
across a generic parameter.

**3. SPHINCS+, XMSS, and other schemes** have variable-length or
parameter-set-dependent sizes for the same reasons.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

We implemented ML-DSA (FIPS 204) signing and verifying keys behind `Signer`
and `Verifier`.  We use `Repr = Box<[u8]>` as the only workable choice:

- `type Repr = Box<[u8]>` in the ML-DSA `SignatureEncoding` impl:
  [`wolfcrypt/src/mldsa.rs:71-73`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/mldsa.rs#L71-L73)
- `From<MlDsaSignature<L>> for Box<[u8]>` conversion:
  [`wolfcrypt/src/mldsa.rs:87-91`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/mldsa.rs#L87-L91)
- Crate-level docs § "`SignatureEncoding::Repr` assumes fixed-size signatures":
  [`wolfcrypt/src/lib.rs:147-155`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L147-L155)

`Box<[u8]>` satisfies the `'static + AsRef<[u8]> + Clone + Send + Sync` bounds,
so it compiles.  But it heap-allocates on every `Into<Repr>` conversion, and
downstream code that calls `sig.to_bytes()` gets a `Box<[u8]>` with no
compile-time size information.

### Proposed change

There are several options of increasing complexity:

1. **Document `Box<[u8]>` as the blessed `Repr` for variable-length schemes**
   and add an example.  Zero API change, but clarifies intent.

2. **Add a `VariableLengthSignature` marker trait** that opts a signature type
   out of fixed-size assumptions, so downstream code can branch:

   ```rust
   pub trait VariableLengthSignature: SignatureEncoding<Repr = Box<[u8]>> {}
   ```

3. **Add a `MAX_SIZE: usize` associated constant** to `SignatureEncoding` so
   that callers can stack-allocate a worst-case buffer without heap allocation,
   while still accommodating variable-length encoding.

As PQC standardisation continues (FIPS 204, 205, and beyond are now published),
the ecosystem will need a principled answer here.  Leaving it to per-crate
workarounds (`Box<[u8]>`) means every PQC implementor rediscovers the same
problem independently.

---

## Issue 8 (Documentation): The `UnsafeCell` pattern for FFI-backed `Signer`/`Verifier` is correct but undocumented

**Repo:** `RustCrypto/traits`
**Labels:** `documentation`, `ffi`, `signature`

### Background

`signature::Verifier::verify` takes `&self`:

```rust
fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
```

This is correct for pure-Rust implementations: a verifying key is logically
immutable, and a shared reference communicates that no mutation occurs.

### The problem

wolfCrypt's C API requires `*mut` pointers for verification, even though the
operation is logically read-only:

```c
int wc_ed25519_verify_msg(
    const byte* sig, word32 sigLen,
    const byte* msg, word32 msgLen,
    int* res,
    ed25519_key* key   // <-- *mut, not *const
);
```

The C function signature requires mutability even for pure verification because
the wolfCrypt implementation uses the key struct's scratch fields internally.
Rust cannot see through the C ABI to know that no observable mutation occurs.

The only way to obtain a `*mut key` from a `&self` reference is via
`UnsafeCell`.  This is the correct solution, but it is not obvious, and it is
not documented anywhere in the `signature` crate or RustCrypto trait
documentation.  Each FFI implementor must discover it independently.

`UnsafeCell` has the useful side effect of making the type `!Sync`, which is
*also* correct: C key handles are not safe to share across threads, so a type
wrapping one should not be `Sync`.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

Every signing and verifying key type in the `wolfcrypt` crate uses `UnsafeCell`
for this reason:

- `Ed25519SigningKey` and `Ed25519VerifyingKey`:
  [`wolfcrypt/src/ed25519.rs:30`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L30)
  and
  [`wolfcrypt/src/ed25519.rs:207`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L207),
  with `// SAFETY:` comments at
  [L176](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L176)
  and
  [L264](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ed25519.rs#L264)
- `EcdsaSigningKey` and `EcdsaVerifyingKey`:
  [`wolfcrypt/src/ecdsa_native.rs:293`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ecdsa_native.rs#L293)
  and
  [`wolfcrypt/src/ecdsa_native.rs:470`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/ecdsa_native.rs#L470)
- `RsaPrivateKey` and `RsaPublicKey`:
  [`wolfcrypt/src/rsa.rs:407`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/rsa.rs#L407)
  and
  [`wolfcrypt/src/rsa.rs:586`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/rsa.rs#L586)
- `MlDsaSigningKey` and `MlDsaVerifyingKey`:
  [`wolfcrypt/src/mldsa.rs:151`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/mldsa.rs#L151)
  and
  [`wolfcrypt/src/mldsa.rs:284`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/mldsa.rs#L284),
  with `// SAFETY:` at
  [L351](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/mldsa.rs#L351)
- AES-GCM key:
  [`wolfcrypt/src/aead.rs:36`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/aead.rs#L36)
- Crate-level docs § "Interior mutability for FFI verification calls":
  [`wolfcrypt/src/lib.rs:157-170`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/lib.rs#L157-L170)

### Proposed change

No API change is needed.  `UnsafeCell` is the correct solution and requires no
modification to the trait.

We ask that a documentation section be added to the `signature` crate (or a
RustCrypto FFI implementation guide, if one exists) covering:

- Why `Verifier::verify` taking `&self` creates the interior-mutability
  requirement when the underlying C function takes `*mut`.
- The `UnsafeCell` pattern as the standard solution.
- Why `UnsafeCell` makes the type `!Sync` and why this is correct for C key handles.
- The `// SAFETY:` comment obligation at each call site explaining why
  single-threaded access is guaranteed.

A worked example would save every future FFI implementor from having to reason
through this from scratch.

---

## Issue 9: `digest::Update`, `FixedOutput`, and `Mac` are infallible; hardware backends are forced to panic when operations fail

**Repo:** `RustCrypto/traits`
**Labels:** `api-design`, `digest`, `hardware`

### Background

Issue 1 covers infallible *constructors*.  This issue covers infallible *runtime
operations*.

The core streaming traits define methods that return `()`:

- `digest::Update::update(&mut self, data: &[u8])`
- `digest::FixedOutput::finalize_into(self, out: &mut Output<Self>)`
- `digest::FixedOutputReset::finalize_into_reset(&mut self, out: &mut Output<Self>)`
- `universal_hash::UniversalHash::update(&mut self, blocks: &[Block<Self>])`

For a pure-Rust software implementation, these are genuinely infallible.
A SHA-256 `update` call is a few arithmetic operations; it cannot fail.
Making the return type `Result<(), E>` for software implementations would be
noise — the `Err` branch is unreachable.

### The problem

For a hardware backend, every one of these operations dispatches to a driver,
HSM, or hardware accelerator that can fail at runtime:

| Trait | Method | Return type | Hardware failure mode |
|-------|--------|-------------|-----------------------|
| `digest::Update` | `update(&mut self, data: &[u8])` | `()` | HSM busy, DMA fault, CryptoCb error |
| `digest::FixedOutput` | `finalize_into(self, out: &mut Output<Self>)` | `()` | Hardware finalization error |
| `digest::FixedOutputReset` | `finalize_into_reset(&mut self, out: &mut Output<Self>)` | `()` | Finalization + re-init failure |
| `universal_hash::UniversalHash` | `update(&mut self, blocks)` | `()` | Hardware MAC block fault |
| `digest::FixedOutput` | `finalize_into` (used by `Mac` via blanket) | `()` | Hardware MAC finalization error |
| `cipher::StreamCipher` | `apply_keystream(&mut self, buf: &mut [u8])` | `()` | Hardware cipher fault |

wolfCrypt's `WOLF_CRYPTO_CB` mechanism routes each algorithm operation through a
registered C callback.  That callback can return `WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)`
when the hardware device is busy, or a device-specific error code if the
hardware operation fails.  The trait gives us nowhere to put that error.

### In our implementation

*Discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`.*

In every case, we are forced to `assert!` on the C return code, converting
hardware failures into panics:

- `digest::Update::update` asserts on `wc_Sha256Update`:
  [`wolfcrypt/src/digest.rs:94-97`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L94-L97)
- `digest::FixedOutput::finalize_into` asserts on `wc_Sha256Final`:
  [`wolfcrypt/src/digest.rs:103-105`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L103-L105)
- `digest::FixedOutputReset::finalize_into_reset` asserts on both finalize and
  re-init: [`wolfcrypt/src/digest.rs:119-124`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/digest.rs#L119-L124)
- `Mac` (HMAC) `Update::update` asserts on `wolfcrypt_hmac_update`:
  [`wolfcrypt/src/hmac.rs:88-91`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hmac.rs#L88-L91)
- `Mac` (HMAC) `FixedOutput::finalize_into` asserts on `wolfcrypt_hmac_final`:
  [`wolfcrypt/src/hmac.rs:99-102`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/hmac.rs#L99-L102)
- `Mac` (CMAC) `Update::update` asserts on `wolfcrypt_cmac_update`:
  [`wolfcrypt/src/cmac.rs:90-93`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/cmac.rs#L90-L93)
- `UniversalHash::update` (Poly1305) asserts on `wc_Poly1305Update`:
  [`wolfcrypt/src/poly1305.rs:96-99`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/poly1305.rs#L96-L99)
- `UniversalHash` finalize (Poly1305) asserts on `wc_Poly1305Final`:
  [`wolfcrypt/src/poly1305.rs:111-114`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/poly1305.rs#L111-L114)

### Proposed change

Add `Try*` variants of the affected traits with fallible signatures and blanket
impls for existing software implementations:

```rust
pub trait TryUpdate {
    type Error;
    fn try_update(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

// Blanket impl: all existing Update implementors get TryUpdate for free
impl<T: Update> TryUpdate for T {
    type Error = core::convert::Infallible;
    fn try_update(&mut self, data: &[u8]) -> Result<(), Infallible> {
        self.update(data);
        Ok(())
    }
}

pub trait TryFixedOutput: TryUpdate {
    fn try_finalize_into(self, out: &mut Output<Self>) -> Result<(), Self::Error>;
}
```

Hardware backends implement `TryUpdate` and `TryFixedOutput` directly.
Software implementations get them via the blanket impls at zero cost.  The
existing `Update` and `FixedOutput` traits are unchanged; no existing code
breaks.

### Prior art

`rand_core` 0.9 already solved this exact problem for the RNG case by adding
`TryCryptoRng` with a fallible `try_fill_bytes` method (see companion
Issue 10).  We are asking for the same pattern to be applied to `digest::Update`
and `digest::FixedOutput`.

The `embedded-hal` crate uses `type Error` associated types on all peripheral
traits for the same reason: hardware peripherals can fail at any method call,
not just at construction time.

---

## Issue 10: `RngCore::fill_bytes` is infallible; hardware RNG failure cannot be surfaced — `TryCryptoRng` is the fix and needs to be the primary recommended path

**Repo:** `RustCrypto/traits` (affects `rand_core`)
**Labels:** `api-design`, `rand`, `hardware`, `fips`

### Background

`rand_core::RngCore::fill_bytes(&mut self, dest: &mut [u8])` returns `()`.
For a software PRNG (ChaCha20, DRBG backed by a software seed), this is
fine — filling bytes from a seeded generator cannot fail.

For a *hardware* entropy source, failure is a normal operational condition,
not a programmer error:

- The hardware may not be ready (power-on self-test still running).
- The entropy pool may be temporarily exhausted (valid in some designs).
- The hardware may report a fault that must be handled — this is precisely what
  FIPS 140-3's Continuous Random Bit Generator (CRBG) test is designed to
  detect.

`rand_core` 0.9 added `TryCryptoRng` with a fallible `try_fill_bytes` to
address exactly this.  We have adopted it, and it solves the problem for our
crate.

### What remains

The issue is adoption and discoverability:

**1. `TryCryptoRng` is not the documented primary interface for hardware RNG
backends.**  The `rand_core` documentation and ecosystem treat it as an
advanced feature.  A developer writing a new hardware entropy driver will reach
for `RngCore` first and implement `fill_bytes` with a panic or a silent
discard of errors, because that is what the documentation implies.

**2. Key generation APIs still take `impl CryptoRng`**, not `impl TryCryptoRng`.
For example:

```rust
// In signature crates:
pub fn generate(rng: &mut impl CryptoRng) -> Self;

// In KeyInit:
pub fn generate(rng: &mut impl CryptoRng) -> Self;
```

A hardware RNG backend correctly implements `TryCryptoRng` but has no
`CryptoRng` blanket impl (or the blanket impl panics on failure, defeating the
purpose).  Key generation from a hardware source that can fail cannot propagate
errors through these APIs.

**In our codebase** *(discovered while implementing [`wolfcrypt`](https://github.com/wolfSSL/wolfssl-rs), a RustCrypto backend wrapping wolfCrypt — a FIPS 140-3 validated C cryptographic library with hardware dispatch via `WOLF_CRYPTO_CB`)*:

Our `WolfRng` type implements `TryCryptoRng`.  The `fill_bytes` implementation
is forced to `assert!` because `RngCore::fill_bytes` returns `()`, and the code
comment explicitly documents why:

> *"RNG failure is unrecoverable" as a direct consequence of the trait signature*

[`wolfcrypt/src/rand.rs:80-90`](https://github.com/wolfSSL/wolfssl-rs/blob/0f3af10/wolfcrypt/src/rand.rs#L80-L90)

### What we are asking for

1. **Document `TryCryptoRng` as the *required* interface for hardware entropy
   sources**, not just an optional extra.  A hardware RNG backend that
   implements only `RngCore::fill_bytes` with a panic is not a correct
   implementation; this should be stated clearly.

2. **Audit key generation entry points** — `KeyInit::generate`,
   `SigningKey::generate`, and similar — and add `TryCryptoRng`-accepting
   variants so that hardware entropy sources can propagate failures through key
   generation without panicking.

3. **Apply the same `Try*` pattern to `digest::Update` and `Mac`** (see
   companion Issue 9) to complete the hardware-dispatch story: if entropy,
   hashing, and MACing can all fail and propagate errors, a hardware-backed
   crypto pipeline becomes first-class.

### Prior art

- `rand_core` 0.9: `TryCryptoRng` / `try_fill_bytes` — already shipped; this
  is exactly the right design.
- `embedded-hal` 1.0: fallible `type Error` on all peripheral traits, including
  RNG.
- `embedded-hal-async`: async + fallible, showing the pattern composes with
  async hardware dispatch.
