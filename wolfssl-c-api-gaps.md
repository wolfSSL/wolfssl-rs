# wolfSSL C API Gaps

Discovered while wrapping wolfCrypt behind safe Rust in the `wolfcrypt-rs` and
`wolfcrypt` crates.  Each gap required either a workaround in Rust or a shim
function in `wolfcrypt-rs/src/compat_shim.c`.

The gaps are grouped into three categories: confirmed bugs in wolfSSL's C API,
missing API surface (functionality that should be in wolfSSL but isn't), and
API design quirks that are not wrong per se but impose friction on FFI wrappers.

---

## Bugs

### 1. `d2i_ECPrivateKey` does not derive the public point

**Affected function:** `wolfSSL_d2i_ECPrivateKey`

RFC 5915 DER encodings of EC private keys include an optional `publicKey`
field.  When that field is absent, OpenSSL derives the public point from the
private scalar automatically.  wolfSSL instead sets `type = ECC_PRIVATEKEY_ONLY`
and leaves the public point uninitialized.  Any subsequent operation that needs
the public key — ECDSA sign, ECDH, key export — fails or produces garbage.

**Workaround in `compat_shim.c`:** `wolfcrypt_fix_ec_privatekey_only()` detects
`ECC_PRIVATEKEY_ONLY`, calls `wc_ecc_make_pub()` to derive the public point
from the private scalar, resets `type = ECC_PRIVATEKEY`, then syncs the OpenSSL
compat layer via the internal `SetECKeyExternal()`.  Called unconditionally
after every `d2i_ECPrivateKey` import.

**Fix:** `wolfSSL_d2i_ECPrivateKey` should call `wc_ecc_make_pub` when the
`publicKey` field is absent, matching OpenSSL behavior.

**Filed:** Zendesk #21732

---

### 2. `EVP_CIPHER_iv_length` returns 0 for CFB128 modes

**Affected function:** `wolfSSL_EVP_CIPHER_iv_length`

`EVP_CIPHER_iv_length(EVP_aes_128_cfb128())` — and the 192-bit and 256-bit
variants — returns 0.  The correct IV length for AES-CFB128 is 16 bytes.
This causes callers that derive IV size from the cipher descriptor to produce
zero-length IVs, silently corrupting every encryption.

**Workaround in `wolfcrypt-ring-compat`:** A wrapper function
`evp_cipher_iv_length()` (streaming.rs:690) checks for a 0 return and, if the
cipher pointer matches one of the three CFB128 descriptors, substitutes 16.

```rust
/// EVP_CIPHER_iv_length with wolfSSL CFB128 bug workaround.
/// wolfSSL incorrectly returns 0 for CFB128 cipher IV lengths.
unsafe fn evp_cipher_iv_length(cipher: *const EVP_CIPHER) -> c_int {
    let len = EVP_CIPHER_iv_length_raw(cipher);
    if len == 0 && (cipher == EVP_aes_128_cfb128() || ...) {
        return 16;
    }
    len
}
```

**Fix:** The CFB128 cipher descriptors in wolfSSL should report `iv_len = 16`.

**Filed:** Zendesk #21730

---

### 3. `EVP_DigestSignUpdate` and `EVP_DigestVerifyUpdate` have mismatched `cnt` types

**Affected functions:** `wolfSSL_EVP_DigestSignUpdate`, `wolfSSL_EVP_DigestVerifyUpdate`

OpenSSL declares both functions with `size_t cnt`.  wolfSSL declares
`DigestSignUpdate` with `unsigned int cnt` and `DigestVerifyUpdate` with
`size_t cnt`.  The inconsistency means a Rust binding (or any caller) cannot
use the same type for both and must special-case `DigestSignUpdate`.

**Workaround in `wolfcrypt-rs/src/lib.rs:975`:** The FFI declarations match
wolfSSL's inconsistency exactly, with a comment noting it is a wolfSSL bug:

```
// NOTE: wolfSSL declares SignUpdate with `unsigned int cnt` but
// VerifyUpdate with `size_t cnt`. OpenSSL uses `size_t` for both.
// This is a wolfSSL bug; the mismatch below matches upstream as-is.
```

**Fix:** Change `wolfSSL_EVP_DigestSignUpdate`'s `cnt` parameter to `size_t`.

**Filed:** Zendesk #21734

---

### 4. `wolfSSL_ERR_error_string` pulls in the 30k-line TLS state machine

**Affected function:** `wolfSSL_ERR_error_string`

This function calls `SetErrorString`, which is defined in `internal.c` — the
TLS handshake state machine, over 30,000 lines.  A crypto-only build that does
not compile `internal.c` gets a linker error for this single symbol, even
though `SetErrorString` has no dependency on TLS state.

**Workaround in `compat_shim.c:392`:** A `__attribute__((weak))` stub converts
the numeric error code to a decimal string without calling any wolfSSL code.
The weak attribute ensures that if a downstream binary links the full wolfSSL
(including `internal.c`), the real implementation wins and the stub is
discarded.

The comment reads: *"TODO: upstream wolfSSL issue to decouple SetErrorString
from internal.c so crypto-only builds don't need this stub."*

**Fix:** Move `SetErrorString` (or its error-code-to-string mapping) out of
`internal.c` into a file compiled for all wolfSSL configurations.

**Filed:** Zendesk #21735

---

## Missing APIs

### 5. RFC 5649 padded AES key wrap is absent

**Missing function:** no equivalent of `AES_wrap_key_padded` / `AES_unwrap_key_padded`

wolfSSL provides `AES_wrap_key` / `AES_unwrap_key` for RFC 3394 standard key
wrap.  RFC 5649 (padded key wrap, supporting non–block-multiple plaintext
lengths) is not implemented.

The RFC 5649 multi-block unwrap path also cannot use wolfSSL's `AES_unwrap_key`
even as a building block, because wolfSSL's implementation validates the
recovered A register against a caller-supplied IV before returning.  RFC 5649
requires recovering the AIV — which encodes the plaintext length — and then
validating it; wolfSSL's validation happens first and rejects the AIV.  The
entire RFC 3394 unwrap loop had to be reimplemented from scratch on top of
AES-ECB.

**Workaround in `compat_shim.c:443`:** Full RFC 5649 wrap and unwrap are
implemented using wolfSSL's `wolfSSL_AES_ecb_encrypt` (single-block case) and
`wolfSSL_AES_wrap_key` with a custom IV (multi-block wrap).  Multi-block unwrap
reimplements the RFC 3394 loop using AES-ECB to recover the AIV before
validating it.

**Fix:** Add native `wolfSSL_AES_wrap_key_padded` / `wolfSSL_AES_unwrap_key_padded`
per RFC 5649.

**Filed:** Zendesk #21736

---

### 6. KBKDF counter mode with HMAC is absent

**Missing function:** HMAC-based KBKDF per NIST SP 800-108r1 §4.1

wolfSSL provides `wc_KDA_KDF_PRF_cmac` for CMAC-based key-based key derivation
(SP 800-108) but has no HMAC variant.  The HMAC variant is required for
interoperability with systems (TLS, SSH, JOSE) that specify KBKDF-CTR-HMAC
rather than KBKDF-CTR-CMAC.

**Workaround in `compat_shim.c:792`:** `KBKDF_ctr_hmac()` implements the
NIST SP 800-108r1 §4.1 counter-mode KDF using wolfSSL's `WOLFSSL_HMAC_CTX`
primitives directly: per-iteration counter as a 32-bit big-endian prefix,
concatenated with the caller-supplied FixedInfo, hashed with HMAC.

**Fix:** Add a native `wc_KBKDF_ctr_hmac` function (or extend `wc_KDA_KDF_PRF`
to accept a MAC type selector) matching the existing CMAC variant.

**Filed:** Zendesk #21737

---

## API Design Quirks

### 7. ChaCha20-Poly1305 state machine rejects empty input without a dummy update

**Affected function:** `wc_ChaCha20Poly1305_Final`

wolfCrypt's streaming ChaCha20-Poly1305 API (`Init` / `UpdateAad` /
`UpdateData` / `Final`) tracks a state machine (READY → AAD → DATA → DONE).
`Final` requires the state to be AAD or DATA, not READY.  When both AAD and
plaintext are empty — a valid case per RFC 8439 — neither `UpdateAad` nor
`UpdateData` is called, the state remains READY, and `Final` returns
`BAD_STATE_E`.

**Workaround in `wolfcrypt/src/aead.rs:290`:** `UpdateData` is called
unconditionally with a zero-length buffer (using a stack sentinel pointer
because empty Rust slices may have dangling `as_ptr()` values).  This
transitions state to DATA without processing any bytes, which is correct per
RFC 8439.

```rust
// We always call UpdateData even when buffer is empty because
// wolfCrypt's state machine requires at least one UpdateAad or
// UpdateData call before Final (state must be AAD or DATA, not
// READY).
```

**Fix:** `wc_ChaCha20Poly1305_Final` should accept READY state as valid when
both AAD length and data length are zero, or the state machine should advance
to DATA implicitly when `Init` is called.

**Filed:** GitHub issue #10040, PR #10046

---

### 8. `wc_curve25519_make_pub` requires the caller to clamp the private scalar

**Affected function:** `wc_curve25519_make_pub`

RFC 7748 §5 specifies that Curve25519 private keys must be clamped (clear bits
0, 1, 2 of byte 0; clear bit 7 of byte 31; set bit 6 of byte 31) before use.
wolfSSL's `wc_curve25519_make_pub` requires that clamping has already been
applied by the caller.  It does not clamp internally.  Passing an unclamped
scalar produces a wrong public key without returning an error.

**Workaround in `wolfcrypt/src/ecdh.rs:64`:** The clamping step is performed
explicitly before calling `wc_curve25519_make_pub`:

```rust
// Clamp the private scalar per RFC 7748 Section 5.
// wolfSSL requires clamped keys for `wc_curve25519_make_pub`.
let mut clamped = *private;
clamp(&mut clamped);
```

**Fix:** `wc_curve25519_make_pub` should clamp internally, matching the
behavior of every other Curve25519 implementation.  Alternatively, the
documentation should state this requirement explicitly.

**Filed:** Zendesk #21731

---

### 9. Curve25519 blinding requires attaching an RNG to the key before each scalar multiply

**Affected function:** `wc_curve25519_shared_secret_ex`

wolfSSL enables Curve25519 scalar-multiplication blinding by default.  Blinding
requires an RNG to be attached to the private-key struct via
`wc_curve25519_set_rng()` before any scalar multiply.  The DH API
(`wc_curve25519_shared_secret_ex`) does not accept an RNG parameter inline.

This forces every DH operation to initialise a throwaway RNG, set it on the
key, perform the multiply, and then free the RNG — four extra steps per
operation, one of which (`wc_InitRng`) may touch the entropy source.

**Workaround in `wolfcrypt/src/ecdh.rs:157`:**

```rust
// wolfSSL enables Curve25519 blinding by default, which requires
// an RNG attached to the private key for scalar multiplication.
// Create a temporary RNG for this operation.
let mut rng = WC_RNG::zeroed();
wc_InitRng(&mut rng);
wc_curve25519_set_rng(&mut self.key, &mut rng);
// ... wc_curve25519_shared_secret_ex ...
wc_FreeRng(&mut rng);
```

**Fix:** Accept an optional `WC_RNG *` parameter in `wc_curve25519_shared_secret_ex`
(and the make-public equivalent), so callers can pass their existing RNG rather
than constructing a temporary one.

**Filed:** Zendesk #21738

---

### 10. All sign and verify operations require `*mut` pointers for logically read-only operations

**Affected functions:** `wc_Ed25519Sign`, `wc_Ed25519Verify`, `wc_Ed448Sign`,
`wc_Ed448Verify`, `wc_ecc_sign_hash`, `wc_ecc_verify_hash`, and their RSA,
ML-DSA, and LMS equivalents.

wolfCrypt's C API takes `*mut key` for operations that are logically read-only,
including signature verification and public-key access.  This is a common
pattern in C ("const-correctness debt") but it breaks straightforwardly in Rust:
the `signature::Verifier` trait takes `&self`, and there is no safe way to
obtain `*mut` from `&self` without interior mutability.

**Workaround in `wolfcrypt/src/`:** Every key type that backs a sign or verify
operation wraps its C key handle in `UnsafeCell`, which allows obtaining `*mut`
from `&self` for FFI calls.  The `UnsafeCell` makes the type `!Sync`, which is
correct — wolfCrypt key handles are not safe to share across threads.

Affected types: `Ed25519SigningKey`, `Ed25519VerifyingKey`, `Ed448SigningKey`,
`Ed448VerifyingKey`, `EcdsaSigningKey`, `EcdsaVerifyingKey`, `RsaPrivateKey`,
`RsaPublicKey`, `MlDsa*SigningKey`, `MlDsa*VerifyingKey`.

**Fix:** Mark key parameters `const` in the C signatures of verification and
public-key-export functions where the key is not actually modified.  This is
routine C const-correctness work.

**Filed:** Zendesk #21739 (covers bugs 10 and 11)

---

### 11. Ed448 DER functions take `*mut key` but their Ed25519 counterparts take `const`

**Affected functions:** `wc_Ed448PrivateKeyDecode`, `wc_Ed448PrivateKeyToDer`,
`wc_Ed448KeyToDer`

The equivalent Ed25519 functions (`wc_Ed25519PrivateKeyDecode`,
`wc_Ed25519PrivateKeyToDer`, `wc_Ed25519KeyToDer`) take `const *` key
pointers where the operation is read-only.  The Ed448 versions take `*mut`.
The asymmetry is unexplained; neither set of operations modifies the key.

**Workaround in `wolfcrypt-rs/src/lib.rs:1949`:** The FFI declarations match
wolfSSL's inconsistency and a comment explains the discrepancy:

```
// NOTE: Ed448 DER functions take non-const key pointers, unlike their
// Ed25519 counterparts which take `const`. This matches the upstream
// wolfSSL API — the inconsistency is in wolfSSL itself.
```

**Fix:** Change `wc_Ed448PrivateKeyToDer` and `wc_Ed448KeyToDer` to accept
`const wc_ed448_key *` where the key is not modified.

**Filed:** Zendesk #21739 (covers bugs 10 and 11)

---

### 12. `wc_curve25519_make_pub` has output parameters before input parameters

**Affected function:** `wc_curve25519_make_pub`

The signature is:

```c
int wc_curve25519_make_pub(int pubSz, byte *pub_, int privSz, const byte *priv_);
```

Output parameters (`pubSz`, `pub_`) come before input parameters (`privSz`,
`priv_`).  The rest of the wolfCrypt API follows the conventional C ordering
of input before output.  This is a readability hazard: callers can silently
swap arguments and get no compile error because both size parameters are `int`.

**Workaround:** The FFI binding in `wolfcrypt-rs/src/lib.rs:1972` carries an
explicit comment:

```
// NOTE: wolfSSL signature has output params before input params
```

**Fix:** Swap the parameter order in a future wolfSSL major release, or
introduce a correctly-ordered `wc_curve25519_make_public_key` alias.

**Filed:** Zendesk #21733

---

### 13. Opaque struct sizes must be manually over-approximated and verified at build time

**Affected structs:** `Aes`, `WC_RNG`, `Poly1305`, `ChaCha`, `ChaChaPoly_Aead`,
`ed25519_key`, `curve25519_key`, `ed448_key`, `curve448_key`, `dilithium_key`,
`LmsKey`, `XtsAes`, `Hpke`, and others.

Rust cannot know the layout of wolfSSL C structs without running bindgen for
every build configuration.  bindgen output is fragile — struct sizes change
with `WOLF_CRYPTO_CB` (adds `devId`, `devCtx`, `devKey` fields to key types),
platform word size, and enabled algorithm sets.

**Workaround in `wolfcrypt-rs`:** Each struct is stack-allocated as a
`[u8; N]` blob with a hand-chosen `N` that is rounded up to a safe
over-approximation.  `compat_shim.c:82–206` contains `_Static_assert` checks
that fire at compile time if the actual struct outgrows the allocation:

```c
_Static_assert(sizeof(Aes) <= 512,
    "Aes exceeds WC_AES_ALLOC_SIZE (512) in lib.rs");
_Static_assert(_Alignof(Aes) <= 16,
    "Aes alignment exceeds repr(C, align(16)) in lib.rs");
```

When a wolfSSL upgrade changes a struct's size or alignment, the build fails
with a diagnostic, and only `compat_shim.c` and the corresponding constant in
`lib.rs` need updating.

**Fix:** wolfSSL could provide stable C accessor functions and heap-allocate
opaque handle types (returning `Aes *` rather than requiring `Aes` in the
caller's stack frame).  Alternatively, exporting a `wc_AesSize()` function
that returns `sizeof(Aes)` at runtime would let the Rust side allocate the
right amount without a compile-time constant.

**Filed:** Zendesk #21740
