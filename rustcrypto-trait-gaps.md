# RustCrypto Trait Ecosystem Gaps

Discovered while implementing the `wolfcrypt` crate, which wraps wolfCrypt's C
FFI behind standard RustCrypto trait interfaces.  Each gap is a design
limitation that pure-Rust implementations never encounter — either because they
compose Rust types rather than wrapping a C library, or because they do not have
hardware-dispatch or key-handle lifecycle concerns.

The gaps are documented here as a reference for anyone proposing upstream
improvements to the RustCrypto trait crates.

---

## 1. Infallible constructors for fallible operations

**Affected traits:** `digest::Digest` (via `Default`), `cipher::KeyInit`,
`aead::KeyInit`

These traits define constructors that return `Self`, not `Result<Self, _>`.  Any
FFI backend can fail for reasons outside the caller's control: OOM in the C
allocator, hardware device unavailable, or the library not yet initialized.  The
trait signature gives no way to surface that failure.

**Workaround in `wolfcrypt`:** We `assert!` on the wolfCrypt return code.  In
practice this panics only on OOM or device-init failure, never on valid input of
the correct key length.  Fallible alternatives (`new_from_slice`, `generate`,
`from_seed`) return `Result` wherever the trait allows.

**Upstream fix:** Make constructors return `Result<Self, E>`, or add a parallel
`TryKeyInit` / `TryDigestNew` trait set with fallible constructors.

---

## 2. No `ZeroizeOnDrop` bound on key types

**Affected traits:** `cipher::KeyInit`, `aead::KeyInit`, `signature::Keypair`,
and all traits that create types holding secret key material.

The traits create types that hold key material (AES key schedules, AEAD keys,
signing keys) but impose no cleanup guarantee.  There is no `ZeroizeOnDrop` or
similar bound; each implementor must remember to add it manually.  This is an
easy thing to miss and makes it possible to publish a crate that leaks key
material from freed memory.

**Workaround in `wolfcrypt`:** We manually implement `Drop` with the appropriate
wolfCrypt free function (`wc_AesFree`, `wc_HmacFree`, etc.) and/or `zeroize`
calls on every type that holds key material.

**Upstream fix:** Add a `ZeroizeOnDrop` supertrait bound (or at minimum a
documentation requirement with a linting mechanism) to all `KeyInit`-producing
traits.

---

## 3. `AeadInPlace` is the only AEAD trait

**Affected trait:** `aead::AeadInPlace`

The `aead` crate provides only an in-place encrypt/decrypt interface — the
plaintext/ciphertext buffer is mutated in-place.  There is no variant that takes
separate input and output buffers.

This caused an allocation problem with wolfCrypt's one-shot
ChaCha20-Poly1305 API (`wc_ChaCha20Poly1305_Encrypt`), which requires
separate source and destination buffers.  Adapting it to the in-place trait
would have required a heap allocation per call to hold the output before
copying back.

**Workaround in `wolfcrypt`:** We use wolfCrypt's streaming
ChaCha20-Poly1305 API (`wc_ChaCha20Poly1305_Init` / `UpdateData` /
`Final`), which accepts `input == output` pointers and works natively in-place.
A backend with no in-place path — for example, a DMA-based hardware accelerator
— would have no such escape hatch and would be forced to allocate.

**Upstream fix:** Add an `Aead` trait variant with separate input and output
slices, or provide a blanket adapter from `AeadInPlace` to a two-buffer variant.

---

## 4. No HKDF or PBKDF2 traits

**Affected crates:** `hkdf`, `pbkdf2`

These crates expose concrete implementations, not traits.  There is no trait
that an alternative backend can implement to plug in a different HKDF or PBKDF2
engine.  Any generic code that needs to accept "an HKDF implementation" must
pick one concrete type.

**Workaround in `wolfcrypt`:** The `hkdf` module exposes a bespoke API whose
method names match `hkdf::Hkdf` (`new`, `extract`, `expand`).  The `pbkdf2`
module exposes standalone functions matching `pbkdf2::pbkdf2_hmac`'s signature.
For callers that need the actual `hkdf` or `pbkdf2` crate types, our digest
types compose with `hkdf::SimpleHkdf<Sha256>` and `hmac::SimpleHmac<Sha256>`.

**Upstream fix:** Define `HkdfExpand` / `HkdfExtract` and `Pbkdf2` traits in
the respective crates so that alternative backends (wolfCrypt, BoringSSL, HSMs)
can implement them.

---

## 5. The `CoreProxy` cliff

**Affected trait:** `digest::Digest` (specifically `pbkdf2::pbkdf2_hmac`'s
`CoreProxy` bound)

The `digest` crate has two implementation tiers:
- **High-level:** `Digest`, `Update`, `FixedOutput` — the public-facing API.
- **Low-level:** `CoreProxy`, `UpdateCore`, `FixedOutputCore` — the internal
  composable building blocks.

Our EVP-based digest types implement the high-level tier, which is sufficient
for almost all uses.  However, `pbkdf2::pbkdf2_hmac` requires its hash argument
to implement `CoreProxy` (the low-level tier).  An opaque FFI wrapper cannot
satisfy `CoreProxy` because the trait requires exposing the block size and
internal state as associated types at compile time.

**Workaround in `wolfcrypt`:** Callers needing `pbkdf2_hmac` should use
`hmac::SimpleHmac<WolfSha256>` (which bridges from high-level digest to
low-level HMAC) or use our native `pbkdf2_hmac_sha256` function, which calls
wolfCrypt's `wc_PBKDF2` directly.

**Upstream fix:** Remove the `CoreProxy` bound from `pbkdf2::pbkdf2_hmac` and
accept any `Mac` directly, which is the actual requirement.

---

## 6. `pbkdf2::pbkdf2` requires `Sync` unconditionally

**Affected function:** `pbkdf2::pbkdf2` (the lower-level function, distinct from
`pbkdf2_hmac`)

The function signature is:

```rust
pub fn pbkdf2<PRF: Mac + Sync>(prf: PRF, ...) { ... }
```

The `Sync` bound exists to support the `parallel` feature, which distributes
PBKDF2 rounds across threads.  However, the bound is present unconditionally —
even when the `parallel` feature is disabled and the function runs entirely
single-threaded.

Our EVP-based digest types are correctly `!Sync`: `EVP_MD_CTX` contains
interior mutable state that is not safe to share across threads.  This means
`pbkdf2::<SimpleHmac<WolfSha256>>(...)` does not compile, even in a
single-threaded context where `Sync` is semantically unnecessary.

**Workaround in `wolfcrypt`:** Use our native `pbkdf2_hmac_sha256` function
instead, which calls wolfCrypt's `wc_PBKDF2` directly.

**Upstream fix:** Gate the `Sync` bound on the `parallel` feature:

```rust
#[cfg(feature = "parallel")]
pub fn pbkdf2<PRF: Mac + Sync>(prf: PRF, ...) { ... }
#[cfg(not(feature = "parallel"))]
pub fn pbkdf2<PRF: Mac>(prf: PRF, ...) { ... }
```

This is the clearest actionable upstream fix of the eight gaps documented here.

---

## 7. `SignatureEncoding::Repr` assumes fixed-size signatures

**Affected trait:** `signature::SignatureEncoding`

The trait requires:

```rust
type Repr: 'static + AsRef<[u8]> + Clone + Send + Sync;
```

In practice, implementations use `[u8; N]` — a fixed-size stack-allocated array.
This works for classical signature schemes (Ed25519 is always 64 bytes, ECDSA-P256
is always 64 bytes) but breaks down for post-quantum signatures, which are
variable-length.  ML-DSA-87 signatures are 4,627 bytes; SPHINCS+ variants vary
by parameter set.

A `[u8; 4627]` associated type loses the "variable length" property (it forces
the largest possible allocation even for small signatures) and is not composable
across parameter sets.

**Workaround in `wolfcrypt`:** We use `Repr = Box<[u8]>`, which satisfies the
trait bounds, but at the cost of a heap allocation per signature and the loss of
compile-time size guarantees.

**Upstream fix:** Introduce a `VariableLengthSignature` marker trait or change
`Repr` to allow `Vec<u8>` / `Box<[u8]>` without prejudicing fixed-size
implementations.  As PQC becomes standard across the RustCrypto ecosystem, this
will need to be revisited.

---

## 8. Interior mutability required for FFI verification calls

**Affected traits:** `signature::Verifier`, `signature::Signer`

wolfCrypt's C API takes `*mut` pointers for operations that are logically
read-only, including signature verification and public-key export.  The
`Verifier::verify` and `Signer::sign` traits take `&self` (a shared reference),
which cannot be coerced to `*mut` without interior mutability.

```rust
// Trait requires &self:
fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;

// wolfCrypt requires *mut:
wc_Ed25519Verify(sig, sig_len, msg, msg_len, &mut result, &mut key as *mut _);
//                                                                  ^^^^
```

This is not a correctness concern for single-threaded use — wolfCrypt's verify
functions do not actually mutate the key — but Rust's type system cannot see
into the C ABI to know that.

**Workaround in `wolfcrypt`:** Signing and verifying key types wrap their C key
handle in `UnsafeCell`.  This allows obtaining `*mut` from `&self` for FFI
calls while making the type `!Sync`, which is correct — wolfCrypt key handles
are not safe to share across threads.  Each `UnsafeCell` usage has a `// SAFETY:`
comment at the call site explaining why single-threaded access is guaranteed.
Affected types: `Ed25519SigningKey`, `Ed25519VerifyingKey`, `Ed448SigningKey`,
`Ed448VerifyingKey`, `EcdsaSigningKey`, `EcdsaVerifyingKey`, `RsaPrivateKey`,
`RsaPublicKey`, `MlDsa*SigningKey`, `MlDsa*VerifyingKey`.

**Upstream fix:** No change to the trait API is needed.  This is an inherent
tension between Rust's aliasing rules and C FFI.  The `UnsafeCell` pattern is
the correct solution.  Documenting it as a known pattern for FFI-backed
implementations would help future implementors.
