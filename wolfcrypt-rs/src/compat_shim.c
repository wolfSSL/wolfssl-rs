/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT */

/*
 * compat_shim.c — C helper functions for wolfcrypt-rs
 *
 * Why this file exists:
 *
 * wolfcrypt-rs needs to access internal wolfSSL struct fields (EVP_PKEY,
 * EVP_PKEY_CTX, ecc_key), but Rust can't know their layouts without
 * bindgen. Instead of generating full struct bindings (which are fragile
 * across wolfSSL versions and add build complexity), this small C file
 * includes the wolfSSL headers and exposes only the specific fields Rust
 * needs through stable accessor functions. On a wolfSSL upgrade, only
 * this file needs updating — not the entire Rust binding surface.
 *
 * Contents:
 *   1. Compile-time struct size verification (_Static_assert)
 *   2. EVP_PKEY / EVP_PKEY_CTX field accessors
 *   3. wolfcrypt_fix_ec_privatekey_only (wolfSSL bug workaround)
 *   4. SetErrorString stub (avoids linking the 30k-line internal.c)
 *
 * All sections are guarded by the same defines used in user_settings.h
 * so this file compiles cleanly regardless of which features are enabled.
 */

#include <wolfssl/wolfcrypt/settings.h>

/* Only pull in OpenSSL compat headers when OPENSSL_EXTRA is active */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/aes.h>
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_CURVE448
#include <wolfssl/wolfcrypt/curve448.h>
#endif
#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>
#endif
#ifdef HAVE_CHACHA
#include <wolfssl/wolfcrypt/chacha.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#ifdef HAVE_DILITHIUM
#include <wolfssl/wolfcrypt/dilithium.h>
#endif
#if defined(HAVE_BLAKE2B) || defined(HAVE_BLAKE2S)
#include <wolfssl/wolfcrypt/blake2.h>
#endif
#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
#include <wolfssl/wolfcrypt/sha3.h>
#endif
#ifdef HAVE_LMS
#include <wolfssl/wolfcrypt/lms.h>
#endif
#ifdef WOLF_CRYPTO_CB
#include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#if defined(HAVE_HPKE) && defined(HAVE_ECC)
#include <wolfssl/wolfcrypt/hpke.h>
#endif


/* ================================================================
 * Compile-time size verification for opaque Rust struct allocations.
 * If any of these fail, increase the corresponding _opaque size in lib.rs.
 * ================================================================ */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
/* C11 _Static_assert is available */
#elif defined(_MSC_VER)
/* MSVC supports static_assert as a keyword since VS 2010 */
#define _Static_assert static_assert
#else
/* No compile-time assertion support; skip size checks */
#define _Static_assert(expr, msg)
#endif

/* These sizes and alignments must match the Rust struct definitions in lib.rs.
 * If a _Static_assert fires, update the corresponding constant or alignment. */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
_Static_assert(sizeof(WOLFSSL_AES_KEY) <= 352,
    "WOLFSSL_AES_KEY exceeds AES_KEY_ALLOC_SIZE (352) in lib.rs");
#endif

_Static_assert(sizeof(Aes) <= 512,
    "Aes exceeds WC_AES_ALLOC_SIZE (512) in lib.rs");
_Static_assert(_Alignof(Aes) <= 16,
    "Aes alignment exceeds repr(C, align(16)) in lib.rs");

_Static_assert(sizeof(WC_RNG) <= 64,
    "WC_RNG exceeds WC_RNG_ALLOC_SIZE (64) in lib.rs");
_Static_assert(_Alignof(WC_RNG) <= 8,
    "WC_RNG alignment exceeds repr(C, align(8)) in lib.rs");

#ifdef HAVE_POLY1305
_Static_assert(sizeof(Poly1305) <= 512,
    "Poly1305 exceeds POLY1305_ALLOC_SIZE (512) in lib.rs");
_Static_assert(_Alignof(Poly1305) <= 64,
    "Poly1305 alignment exceeds repr(C, align(64)) in lib.rs");
#endif
#ifdef HAVE_CHACHA
_Static_assert(sizeof(ChaCha) <= 128,
    "ChaCha exceeds CHACHA_ALLOC_SIZE (128) in lib.rs");
_Static_assert(_Alignof(ChaCha) <= 16,
    "ChaCha alignment exceeds repr(C, align(16)) in lib.rs");
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
_Static_assert(sizeof(ChaChaPoly_Aead) <= 192,
    "ChaChaPoly_Aead exceeds CHACHA_POLY_AEAD_ALLOC_SIZE (192) in lib.rs");
_Static_assert(_Alignof(ChaChaPoly_Aead) <= 8,
    "ChaChaPoly_Aead alignment exceeds repr(C, align(8)) in lib.rs");
#endif

#ifdef HAVE_ED25519
_Static_assert(sizeof(ed25519_key) <= 256,
    "ed25519_key exceeds WC_ED25519_KEY_ALLOC_SIZE (256) in lib.rs");
_Static_assert(_Alignof(ed25519_key) <= 8,
    "ed25519_key alignment exceeds repr(C, align(8)) in lib.rs");
#endif
#ifdef HAVE_CURVE25519
_Static_assert(sizeof(curve25519_key) <= 256,
    "curve25519_key exceeds WC_CURVE25519_KEY_ALLOC_SIZE (256) in lib.rs");
_Static_assert(_Alignof(curve25519_key) <= 8,
    "curve25519_key alignment exceeds repr(C, align(8)) in lib.rs");
#endif
#ifdef HAVE_ED448
_Static_assert(sizeof(ed448_key) <= 256,
    "ed448_key exceeds WC_ED448_KEY_ALLOC_SIZE (256) in lib.rs");
_Static_assert(_Alignof(ed448_key) <= 8,
    "ed448_key alignment exceeds repr(C, align(8)) in lib.rs");
#endif
#ifdef HAVE_CURVE448
_Static_assert(sizeof(curve448_key) <= 256,
    "curve448_key exceeds WC_CURVE448_KEY_ALLOC_SIZE (256) in lib.rs");
_Static_assert(_Alignof(curve448_key) <= 8,
    "curve448_key alignment exceeds repr(C, align(8)) in lib.rs");
#endif
#ifdef HAVE_DILITHIUM
_Static_assert(sizeof(dilithium_key) <= 8192,
    "dilithium_key exceeds WC_DILITHIUM_KEY_ALLOC_SIZE (8192) in lib.rs");
_Static_assert(_Alignof(dilithium_key) <= 8,
    "dilithium_key alignment exceeds repr(C, align(8)) in lib.rs");
#endif

#ifdef HAVE_BLAKE2B
_Static_assert(sizeof(Blake2b) <= 512,
    "Blake2b exceeds WC_BLAKE2B_ALLOC_SIZE (512) in lib.rs");
_Static_assert(_Alignof(Blake2b) <= 8,
    "Blake2b alignment exceeds repr(C, align(8)) in lib.rs");
#endif
#ifdef HAVE_BLAKE2S
_Static_assert(sizeof(Blake2s) <= 256,
    "Blake2s exceeds WC_BLAKE2S_ALLOC_SIZE (256) in lib.rs");
_Static_assert(_Alignof(Blake2s) <= 4,
    "Blake2s alignment exceeds repr(C, align(4)) in lib.rs");
#endif

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
_Static_assert(sizeof(wc_Shake) <= 512,
    "wc_Shake exceeds WC_SHAKE_ALLOC_SIZE (512) in lib.rs");
_Static_assert(_Alignof(wc_Shake) <= 8,
    "wc_Shake alignment exceeds repr(C, align(8)) in lib.rs");
#endif

#ifdef WOLFSSL_AES_XTS
_Static_assert(sizeof(XtsAes) <= 3072,
    "XtsAes exceeds WC_XTS_AES_ALLOC_SIZE (3072) in lib.rs");
_Static_assert(_Alignof(XtsAes) <= 16,
    "XtsAes alignment exceeds repr(C, align(16)) in lib.rs");
#endif

#ifdef HAVE_LMS
_Static_assert(sizeof(LmsKey) <= 1024,
    "LmsKey exceeds WC_LMS_KEY_ALLOC_SIZE (1024) in lib.rs");
_Static_assert(_Alignof(LmsKey) <= 16,
    "LmsKey alignment exceeds repr(C, align(16)) in lib.rs");
#endif

#if defined(HAVE_HPKE) && defined(HAVE_ECC)
_Static_assert(sizeof(Hpke) <= 128,
    "Hpke exceeds WC_HPKE_ALLOC_SIZE (128) in lib.rs");
_Static_assert(_Alignof(Hpke) <= 8,
    "Hpke alignment exceeds repr(C, align(8)) in lib.rs");
_Static_assert(sizeof(HpkeBaseContext) <= 128,
    "HpkeBaseContext exceeds WC_HPKE_BASE_CONTEXT_ALLOC_SIZE (128) in lib.rs");
_Static_assert(_Alignof(HpkeBaseContext) <= 4,
    "HpkeBaseContext alignment exceeds repr(C, align(4)) in lib.rs");
#endif

/* Constant verification */
_Static_assert(AES_ENCRYPTION == 0,
    "AES_ENCRYPTION != 0; update AES_ENCRYPT in lib.rs");
_Static_assert(AES_DECRYPTION == 1,
    "AES_DECRYPTION != 1; update AES_DECRYPT in lib.rs");

/* NID verification: wolfSSL uses ECC_*_OID values from oid_sum.h as NIDs.
 * These are hash-based OID sums (unless WOLFSSL_OLD_OID_SUM is defined)
 * and could change between wolfSSL versions. */
#ifdef HAVE_ED25519
_Static_assert(NID_ED25519 == (int)ECC_ED25519_OID,
    "NID_ED25519 != ECC_ED25519_OID; update NID_ED25519 in lib.rs");
#endif
#ifdef HAVE_CURVE25519
_Static_assert(NID_X25519 == (int)ECC_X25519_OID,
    "NID_X25519 != ECC_X25519_OID; update NID_X25519 in lib.rs");
#endif
#ifdef HAVE_ED448
_Static_assert(NID_ED448 == (int)ECC_ED448_OID,
    "NID_ED448 != ECC_ED448_OID; update NID_ED448 in lib.rs");
#endif
#ifdef HAVE_CURVE448
_Static_assert(NID_X448 == (int)ECC_X448_OID,
    "NID_X448 != ECC_X448_OID; update NID_X448 in lib.rs");
#endif

/* ECC curve ID verification */
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
_Static_assert(ECC_SECP256R1 == 7,
    "ECC_SECP256R1 != 7; update ECC_SECP256R1 in lib.rs");
_Static_assert(ECC_SECP384R1 == 15,
    "ECC_SECP384R1 != 15; update ECC_SECP384R1 in lib.rs");
_Static_assert(ECC_SECP521R1 == 16,
    "ECC_SECP521R1 != 16; update ECC_SECP521R1 in lib.rs");
_Static_assert(ECC_SECP256K1 == 20,
    "ECC_SECP256K1 != 20; update ECC_SECP256K1 in lib.rs");
#endif

/* ================================================================
 * EVP_PKEY / EVP_PKEY_CTX field accessors for Rust
 *
 * These provide stable access to WOLFSSL_EVP_PKEY internal fields
 * without requiring Rust to know the exact struct layout. They are
 * simple getters/setters, not shim logic.
 * ================================================================ */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)

void wolfcrypt_evp_pkey_set_type(WOLFSSL_EVP_PKEY *pkey, int type) {
    pkey->type = type;
    pkey->save_type = type;
}

int wolfcrypt_evp_pkey_get_type(const WOLFSSL_EVP_PKEY *pkey) {
    return pkey->type;
}

/* Copy raw key material into an EVP_PKEY's internal buffer.
 * Returns 1 on success, 0 on failure (bad input or allocation failure).
 * All current callers pass known-good constant-sized buffers. */
int wolfcrypt_evp_pkey_set_raw(WOLFSSL_EVP_PKEY *pkey, const unsigned char *data, int sz) {
    if (pkey == NULL) return 0;

    /* Always free old buffer first to prevent leaks, even on bad input. */
    if (pkey->pkey.ptr != NULL) {
        wc_ForceZero(pkey->pkey.ptr, pkey->pkey_sz);
        XFREE(pkey->pkey.ptr, NULL, DYNAMIC_TYPE_KEY);
        pkey->pkey.ptr = NULL;
    }
    pkey->pkey_sz = 0;

    if (sz <= 0 || data == NULL) {
        return 0;
    }

    pkey->pkey.ptr = (char *)XMALLOC(sz, NULL, DYNAMIC_TYPE_KEY);
    if (pkey->pkey.ptr == NULL) {
        return 0;
    }

    XMEMCPY(pkey->pkey.ptr, data, sz);
    pkey->pkey_sz = sz;

    return 1;
}

int wolfcrypt_evp_pkey_get_pkey_sz(const WOLFSSL_EVP_PKEY *pkey) {
    return pkey->pkey_sz;
}

const unsigned char *wolfcrypt_evp_pkey_get_pkey_ptr(const WOLFSSL_EVP_PKEY *pkey) {
    return (const unsigned char *)pkey->pkey.ptr;
}

/* ================================================================
 * EVP_PKEY_CTX field accessors for Rust
 * ================================================================ */

WOLFSSL_EVP_PKEY *wolfcrypt_evp_pkey_ctx_get_pkey(WOLFSSL_EVP_PKEY_CTX *ctx) {
    return ctx ? ctx->pkey : NULL;
}

void wolfcrypt_evp_pkey_ctx_set_peer_key(WOLFSSL_EVP_PKEY_CTX *ctx, WOLFSSL_EVP_PKEY *peer) {
    if (ctx == NULL) return;
    /* Up-ref the new key BEFORE freeing the old one. If peer == ctx->peerKey
     * and the refcount is 1, freeing first would deallocate it, then up_ref
     * would dereference freed memory (use-after-free). */
    if (peer != NULL) {
        wolfSSL_EVP_PKEY_up_ref(peer);
    }
    wolfSSL_EVP_PKEY_free(ctx->peerKey);
    ctx->peerKey = peer;
}

WOLFSSL_EVP_PKEY *wolfcrypt_evp_pkey_ctx_get_peer_key(WOLFSSL_EVP_PKEY_CTX *ctx) {
    return ctx ? ctx->peerKey : NULL;
}

void wolfcrypt_evp_pkey_ctx_set_op(WOLFSSL_EVP_PKEY_CTX *ctx, int op) {
    if (ctx) ctx->op = op;
}

int wolfcrypt_evp_pkey_ctx_get_op(WOLFSSL_EVP_PKEY_CTX *ctx) {
    return ctx ? ctx->op : 0;
}

#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

/* ================================================================
 * EC key helper: fix private-key-only imports
 *
 * WORKAROUND for wolfSSL bug: d2i_ECPrivateKey does not compute
 * the public point when the optional publicKey field is absent from
 * an RFC 5915 DER encoding. OpenSSL handles this automatically.
 * wolfSSL instead sets type = ECC_PRIVATEKEY_ONLY and leaves the
 * public point uninitialized, which breaks downstream operations
 * (ECDSA sign, ECDH, key export) that expect the public key.
 *
 * This shim works around the issue by calling wc_ecc_make_pub to
 * derive the public point from the private scalar, then syncing
 * the compat layer via the internal SetECKeyExternal function.
 *
 * Remove this once wolfSSL's d2i_ECPrivateKey handles the
 * missing-public-key case itself.
 * ================================================================ */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && defined(HAVE_ECC)

/* Forward declaration of wolfSSL internal function */
WOLFSSL_LOCAL int SetECKeyExternal(WOLFSSL_EC_KEY* eckey);

WOLFSSL_EC_KEY *wolfcrypt_evp_pkey_get_ecc(const WOLFSSL_EVP_PKEY *pkey) {
    return pkey ? pkey->ecc : NULL;
}

const void *wolfcrypt_evp_pkey_get_ecc_internal(const WOLFSSL_EC_KEY *ec) {
    return ec ? ec->internal : NULL;
}

int wolfcrypt_fix_ec_privatekey_only(WOLFSSL_EC_KEY *key) {
    if (key == NULL || key->internal == NULL) return 1; /* nothing to fix */

    ecc_key *ecc = (ecc_key *)key->internal;

    if (ecc->type != ECC_PRIVATEKEY_ONLY) return 1; /* already has public key */

    int ret = wc_ecc_make_pub(ecc, NULL);
    if (ret != MP_OKAY) return 0;

    ecc->type = ECC_PRIVATEKEY;

    ret = SetECKeyExternal(key);
    if (ret == 1 && key->pub_key == NULL) {
        /* SetECKeyExternal claimed success but didn't populate the
         * public key — treat as failure rather than silently returning
         * a key with a NULL public point. */
        return 0;
    }
    return ret;
}

#endif /* (OPENSSL_EXTRA || OPENSSL_ALL) && HAVE_ECC */

/* ================================================================
 * Stub for SetErrorString (defined in internal.c)
 *
 * wolfSSL_ERR_error_string calls SetErrorString which lives in
 * internal.c — the 30k+ line TLS state machine. We don't compile
 * internal.c since this crate only needs crypto primitives, so we
 * provide a stub that returns the numeric error code as a string.
 *
 * Declared weak so that if a downstream binary does link the full
 * wolfSSL (including internal.c), the real implementation wins and
 * this stub is discarded. Without weak, that scenario would be a
 * duplicate-symbol linker error. (Cargo's `links` key prevents
 * this in normal builds, but weak is cheap insurance for non-cargo
 * or mixed build systems.)
 *
 * MSVC uses __declspec(selectany) on data but has no direct weak
 * function attribute — we omit the annotation there and rely on
 * the linker's default behavior (first definition wins via /FORCE
 * or LIB ordering). In practice the MSVC case is safe because
 * Cargo's `links = "wolfssl"` prevents duplicate linkage.
 *
 * TODO: upstream wolfSSL issue to decouple SetErrorString from
 * internal.c so crypto-only builds don't need this stub.
 * ================================================================ */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void SetErrorString(int error, char* str) {
    /* Caller always provides WOLFSSL_MAX_ERROR_SZ (80) bytes.
     * snprintf not available on all targets; manual int-to-string.
     * Maximum output: '-' + 10 digits + '\0' = 12 bytes, well within 80. */
    char *p = str;
    unsigned int n;
    if (error < 0) {
        *p++ = '-';
        n = (unsigned int)(-(error + 1)) + 1u;  /* safe negation, avoids UB on INT_MIN */
    } else {
        n = (unsigned int)error;
    }
    /* write digits in reverse */
    char buf[12];
    int i = 0;
    do { buf[i++] = '0' + (n % 10); n /= 10; } while (n > 0);
    while (i > 0) *p++ = buf[--i];
    *p = '\0';
}
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

/* ================================================================
 * AES Key Wrap with Padding (RFC 5649) shims
 *
 * wolfSSL does not yet provide RFC 5649 (padded key wrap). It has
 * AES_wrap_key / AES_unwrap_key for RFC 3394 (standard) only.
 * Replace with native wolfSSL calls when they become available.
 *
 * These shims implement RFC 5649 on top of wolfSSL's AES ECB
 * encrypt/decrypt (for the single-block case) and an inline
 * RFC 3394 unwrap (for the multi-block case, since we need to
 * recover the AIV without wolfSSL's IV validation rejecting it).
 *
 * For wrapping (multi-block), we can use wolfSSL_AES_wrap_key with
 * a custom IV (our AIV). For unwrapping (multi-block), we implement
 * the RFC 3394 unwrap loop ourselves so we can extract and validate
 * the AIV per RFC 5649 rules.
 *
 * API mirrors BoringSSL/AWS-LC:
 *   int AES_wrap_key_padded(key, out, out_len, max_out, in, in_len)
 *   int AES_unwrap_key_padded(key, out, out_len, max_out, in, in_len)
 * Returns 1 on success, 0 on failure.
 * ================================================================ */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && defined(HAVE_AES_KEYWRAP) && defined(HAVE_AES_ECB)

#include <string.h>

/* RFC 5649 Alternative Initial Value */
static const unsigned char kPaddedAIV[4] = { 0xA6, 0x59, 0x59, 0xA6 };

/* Forward declaration of multi-block unwrap helper */
static int wolfcrypt_AES_unwrap_key_padded_multiblock(
    const WOLFSSL_AES_KEY *key,
    unsigned char *out,
    size_t *out_len,
    size_t max_out,
    const unsigned char *in,
    size_t in_len);

int wolfcrypt_AES_wrap_key_padded(const WOLFSSL_AES_KEY *key,
                                  unsigned char *out,
                                  size_t *out_len,
                                  size_t max_out,
                                  const unsigned char *in,
                                  size_t in_len)
{
    /* RFC 5649 Section 3: in_len must be >= 1. */
    if (key == NULL || out == NULL || out_len == NULL || in == NULL || in_len == 0) {
        return 0;
    }

    /* Padded plaintext length: round up to next multiple of 8 */
    unsigned int padded_len = (in_len + 7u) & ~7u;
    unsigned int needed;

    if (padded_len <= 8) {
        /* Single-block case: AES-ECB of (AIV || MLI || padded_data) = 16 bytes */
        needed = 16;
    } else {
        /* Multi-block: standard RFC 3394 wrap adds 8 bytes */
        needed = padded_len + 8;
    }

    if (max_out < needed) {
        return 0;
    }

    /* Build the AIV || MLI (big-endian 32-bit length) header */
    unsigned char aiv[8];
    memcpy(aiv, kPaddedAIV, 4);
    aiv[4] = (unsigned char)((in_len >> 24) & 0xFF);
    aiv[5] = (unsigned char)((in_len >> 16) & 0xFF);
    aiv[6] = (unsigned char)((in_len >> 8)  & 0xFF);
    aiv[7] = (unsigned char)((in_len)       & 0xFF);

    if (padded_len <= 8) {
        /* RFC 5649 Section 4.1: If padded plaintext is exactly 8 bytes,
         * concatenate AIV || padded-data and encrypt with single AES-ECB. */
        unsigned char block[16];
        memcpy(block, aiv, 8);
        memcpy(block + 8, in, in_len);
        /* Zero-pad remainder */
        if (in_len < 8) {
            memset(block + 8 + in_len, 0, 8 - in_len);
        }
        wolfSSL_AES_ecb_encrypt(block, out, key, AES_ENCRYPTION);
        *out_len = 16;
    } else {
        /* RFC 5649 Section 4.1: Pad to 8-byte multiple and use RFC 3394
         * key wrap with AIV as the IV. */
        unsigned char pad_buf[256]; /* 256-byte limit: key wrap inputs are keys
                                     * (typically 16-64 bytes). Returns 0 if
                                     * padded_len exceeds this. */
        unsigned char *padded = pad_buf;
        if (padded_len > sizeof(pad_buf)) {
            /* Padded plaintext exceeds the 256-byte stack buffer.  The Rust
             * caller should reject oversized inputs before reaching here.
             * Key wrap inputs are keys (typically 16-64 bytes). */
            return 0;
        }
        memcpy(padded, in, in_len);
        if (padded_len > in_len) {
            memset(padded + in_len, 0, padded_len - in_len);
        }

        /* wolfSSL_AES_wrap_key returns the output length on success, 0 on failure.
         * The iv parameter sets the 8-byte initial value (our AIV). */
        int ret = wolfSSL_AES_wrap_key(key, aiv, out, padded, padded_len);
        if (ret <= 0) {
            return 0;
        }
        *out_len = (size_t)ret;
    }

    return 1;
}

int wolfcrypt_AES_unwrap_key_padded(const WOLFSSL_AES_KEY *key,
                                    unsigned char *out,
                                    size_t *out_len,
                                    size_t max_out,
                                    const unsigned char *in,
                                    size_t in_len)
{
    if (key == NULL || out == NULL || out_len == NULL || in == NULL) {
        return 0;
    }

    /* Minimum input is 16 bytes (one AES block) */
    if (in_len < 16 || (in_len % 8) != 0) {
        return 0;
    }

    if (in_len == 16) {
        /* Single-block case: decrypt with AES-ECB */
        unsigned char block[16];
        wolfSSL_AES_ecb_encrypt(in, block, key, AES_DECRYPTION);

        unsigned char aiv[8];
        memcpy(aiv, block, 8);
        unsigned int payload_len = 8;
        if (max_out < payload_len) {
            return 0;
        }
        memcpy(out, block + 8, 8);

        /* Validate AIV: first 4 bytes must match kPaddedAIV */
        if (memcmp(aiv, kPaddedAIV, 4) != 0) {
            return 0;
        }

        /* Extract MLI (message length indicator) as big-endian 32-bit */
        unsigned int mli = ((unsigned int)aiv[4] << 24) |
                           ((unsigned int)aiv[5] << 16) |
                           ((unsigned int)aiv[6] << 8)  |
                           ((unsigned int)aiv[7]);

        /* RFC 5649 Section 3: 0 < mli <= 8 for single-block */
        if (mli == 0 || mli > payload_len) {
            return 0;
        }

        /* Verify padding bytes are all zero */
        for (unsigned int i = mli; i < payload_len; i++) {
            if (out[i] != 0) {
                return 0;
            }
        }

        *out_len = mli;
        return 1;
    }

    /* Multi-block case: need custom unwrap to recover AIV */
    return wolfcrypt_AES_unwrap_key_padded_multiblock(key, out, out_len,
                                                      max_out, in, in_len);
}

/* RFC 3394 unwrap loop implemented using wolfSSL's AES-ECB primitive.
 *
 * We cannot use wc_AesKeyUnWrap here because it validates the recovered
 * A register against a caller-supplied IV (defaulting to 0xA6A6A6A6...).
 * For RFC 5649, the IV is the AIV (0xA65959A6 || MLI) which contains the
 * message length — a value we don't know until AFTER unwrapping. So we
 * must perform the unwrap loop ourselves, recover the A register, and
 * validate it as an AIV per RFC 5649 Section 3.
 *
 * The AES-ECB decrypt primitive comes from wolfSSL (wolfSSL_AES_ecb_encrypt). */
static int wolfcrypt_AES_unwrap_key_padded_multiblock(
    const WOLFSSL_AES_KEY *key,
    unsigned char *out,
    size_t *out_len,
    size_t max_out,
    const unsigned char *in,
    size_t in_len)
{
    unsigned int n = (unsigned int)((in_len / 8) - 1); /* number of 64-bit data blocks */
    if (n == 0) return 0;

    unsigned int padded_len = n * 8;
    if (max_out < padded_len) return 0;

    /* Working state: A holds the IV register, out holds the data blocks */
    unsigned char A[8];
    memcpy(A, in, 8);
    memcpy(out, in + 8, padded_len);

    /* RFC 3394 Section 2.2.2: Unwrap loop
     * for j = 5 to 0
     *   for i = n to 1
     *     B = AES-1(A ^ t || R[i])  where t = n*j + i
     *     A = MSB(64, B)
     *     R[i] = LSB(64, B) */
    unsigned char B[16];
    for (int j = 5; j >= 0; j--) {
        for (int i = (int)n; i >= 1; i--) {
            unsigned long long t = (unsigned long long)((unsigned long long)n * (unsigned long long)j + (unsigned long long)i);
            /* A ^= t (big-endian) */
            A[7] ^= (unsigned char)(t        & 0xFF);
            A[6] ^= (unsigned char)((t >> 8)  & 0xFF);
            A[5] ^= (unsigned char)((t >> 16) & 0xFF);
            A[4] ^= (unsigned char)((t >> 24) & 0xFF);
            A[3] ^= (unsigned char)((t >> 32) & 0xFF);
            A[2] ^= (unsigned char)((t >> 40) & 0xFF);
            A[1] ^= (unsigned char)((t >> 48) & 0xFF);
            A[0] ^= (unsigned char)((t >> 56) & 0xFF);

            /* B = AES-1(A || R[i]) */
            memcpy(B, A, 8);
            memcpy(B + 8, out + (i - 1) * 8, 8);
            wolfSSL_AES_ecb_encrypt(B, B, key, AES_DECRYPTION);
            memcpy(A, B, 8);
            memcpy(out + (i - 1) * 8, B + 8, 8);
        }
    }

    /* A now holds the recovered AIV — validate per RFC 5649 */
    if (memcmp(A, kPaddedAIV, 4) != 0) {
        return 0;
    }

    unsigned int mli = ((unsigned int)A[4] << 24) |
                       ((unsigned int)A[5] << 16) |
                       ((unsigned int)A[6] << 8)  |
                       ((unsigned int)A[7]);

    /* RFC 5649 Section 3: (n-1)*8 < mli <= n*8 */
    if (mli == 0 || mli > padded_len) {
        return 0;
    }
    if (mli <= padded_len - 8) {
        return 0;
    }

    /* Verify padding bytes are zero */
    for (unsigned int i = mli; i < padded_len; i++) {
        if (out[i] != 0) {
            return 0;
        }
    }

    *out_len = mli;
    return 1;
}

#endif /* (OPENSSL_EXTRA || OPENSSL_ALL) && HAVE_AES_KEYWRAP && HAVE_AES_ECB */

/* ================================================================
 * TLS 1.2 PRF (RFC 5246 Section 5) — thin adapter
 *
 * Delegates to wolfSSL's native wc_PRF_TLS (wolfcrypt/src/kdf.c).
 * This shim only converts the EVP_MD* type to the wc_MACAlgorithm
 * integer and concatenates seed1 || seed2 into a single seed buffer.
 * All PRF computation is performed by wolfSSL.
 *
 * Returns 1 on success, 0 on failure.
 * ================================================================ */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && !defined(NO_HMAC)

#include <wolfssl/wolfcrypt/kdf.h>
#include <string.h>

/* Map EVP_MD name to wc_MACAlgorithm value for wc_PRF_TLS */
static int evp_md_to_mac_type(const WOLFSSL_EVP_MD *md) {
    if (XSTRCMP(md, "SHA256") == 0 || XSTRCMP(md, "sha256") == 0)
        return sha256_mac; /* 4 */
    if (XSTRCMP(md, "SHA384") == 0 || XSTRCMP(md, "sha384") == 0)
        return sha384_mac; /* 5 */
    if (XSTRCMP(md, "SHA512") == 0 || XSTRCMP(md, "sha512") == 0)
        return sha512_mac; /* 6 */
    return -1; /* unsupported */
}

int CRYPTO_tls1_prf(const WOLFSSL_EVP_MD *md,
                     unsigned char *out, size_t out_len,
                     const unsigned char *secret, size_t secret_len,
                     const char *label, size_t label_len,
                     const unsigned char *seed1, size_t seed1_len,
                     const unsigned char *seed2, size_t seed2_len)
{
    if (md == NULL || out == NULL || secret == NULL || label == NULL) {
        return 0;
    }
    if (out_len == 0) {
        return 0;
    }

    int mac_type = evp_md_to_mac_type(md);
    if (mac_type < 0) {
        return 0;
    }

    /* Concatenate seed1 || seed2 into a single seed buffer */
    unsigned char seed_buf[256]; /* 256-byte limit: TLS seeds are typically
                                  * 64 bytes (client + server random). Returns
                                  * 0 if seed_len exceeds this. */
    size_t seed_len = seed1_len + seed2_len;
    if (seed_len > sizeof(seed_buf)) {
        /* Combined seed exceeds the 256-byte stack buffer.  The Rust
         * caller should reject oversized seeds before reaching here.
         * TLS seeds are typically 64 bytes (client + server random). */
        return 0;
    }
    if (seed1 != NULL && seed1_len > 0) {
        memcpy(seed_buf, seed1, seed1_len);
    }
    if (seed2 != NULL && seed2_len > 0) {
        memcpy(seed_buf + seed1_len, seed2, seed2_len);
    }

    /* Delegate to wolfSSL's native TLS PRF.
     * useAtLeastSha256=1 selects the TLS 1.2 code path. */
    int ret = wc_PRF_TLS(out, (word32)out_len,
                          secret, (word32)secret_len,
                          (const byte *)label, (word32)label_len,
                          seed_buf, (word32)seed_len,
                          1, /* useAtLeastSha256 */
                          mac_type,
                          NULL, /* heap */
                          INVALID_DEVID);

    return (ret == 0) ? 1 : 0;
}

/* ================================================================
 * KBKDF Counter Mode with HMAC (NIST SP 800-108r1 §4.1)
 *
 * wolfSSL does not yet provide an HMAC-based KBKDF. It has
 * wc_KDA_KDF_PRF_cmac (CMAC-based, SP 800-108) but not the HMAC
 * variant. This shim uses wolfSSL's HMAC primitives directly.
 * Replace with a native wolfSSL call when one becomes available.
 *
 * PRF = HMAC with the specified digest.
 * For each counter i = 1, 2, ...:
 *   K(i) = HMAC(key, [i]_4 || info)
 * where [i]_4 is the 32-bit big-endian counter.
 * Output blocks are concatenated and truncated to out_len.
 *
 * The caller constructs the FixedInfo (Label || 0x00 || Context || [L]_2)
 * and passes it as the single `info` parameter. This matches the Rust
 * API which exposes a single `info` slice.
 *
 * Returns 1 on success, 0 on failure.
 * ================================================================ */

int KBKDF_ctr_hmac(unsigned char *out, size_t out_len,
                    const WOLFSSL_EVP_MD *digest,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *info, size_t info_len)
{
    if (out == NULL || digest == NULL || key == NULL) {
        return 0;
    }
    if (out_len == 0 || key_len == 0) {
        return 0;
    }

    int md_size = wolfSSL_EVP_MD_size(digest);
    if (md_size <= 0 || md_size > 64) {
        return 0;
    }

    /* Maximum iterations: ceil(out_len / md_size).
     * NIST SP 800-108r1 limits counter to 2^32 - 1. */
    size_t n = (out_len + (size_t)md_size - 1) / (size_t)md_size;
    if (n > 0xFFFFFFFFULL) {
        return 0;
    }

    WOLFSSL_HMAC_CTX *ctx = wolfSSL_HMAC_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    int ret = 0;
    size_t done = 0;

    for (unsigned int i = 1; done < out_len; i++) {
        /* counter as 32-bit big-endian */
        unsigned char ctr[4];
        ctr[0] = (unsigned char)((i >> 24) & 0xFF);
        ctr[1] = (unsigned char)((i >> 16) & 0xFF);
        ctr[2] = (unsigned char)((i >> 8)  & 0xFF);
        ctr[3] = (unsigned char)( i        & 0xFF);

        if (wolfSSL_HMAC_Init_ex(ctx, key, (int)key_len, digest, NULL) != 1) {
            goto cleanup;
        }
        if (wolfSSL_HMAC_Update(ctx, ctr, sizeof(ctr)) != 1) {
            goto cleanup;
        }
        if (info != NULL && info_len > 0) {
            if (wolfSSL_HMAC_Update(ctx, info, (int)info_len) != 1) {
                goto cleanup;
            }
        }

        unsigned char hmac_buf[64];
        unsigned int hmac_len = 0;
        if (wolfSSL_HMAC_Final(ctx, hmac_buf, &hmac_len) != 1) {
            goto cleanup;
        }

        size_t remaining = out_len - done;
        size_t to_copy = (remaining < (size_t)hmac_len) ? remaining : (size_t)hmac_len;
        memcpy(out + done, hmac_buf, to_copy);
        done += to_copy;
    }

    ret = 1;

cleanup:
    wolfSSL_HMAC_CTX_free(ctx);
    return ret;
}

/* ================================================================
 * SSKDF with Hash (NIST SP 800-56Cr2 §4.1) — thin adapter
 *
 * Delegates to wolfSSL's native wc_KDA_KDF_onestep (wolfcrypt/src/kdf.c).
 * This shim only converts the EVP_MD* type to wc_HashType.
 * All KDF computation is performed by wolfSSL.
 *
 * Returns 1 on success, 0 on failure.
 * ================================================================ */

/* Map EVP_MD name to wc_HashType for wc_KDA_KDF_onestep */
static enum wc_HashType evp_md_to_wc_hash_type(const WOLFSSL_EVP_MD *md) {
    if (XSTRCMP(md, "SHA224") == 0 || XSTRCMP(md, "sha224") == 0)
        return WC_HASH_TYPE_SHA224;
    if (XSTRCMP(md, "SHA256") == 0 || XSTRCMP(md, "sha256") == 0)
        return WC_HASH_TYPE_SHA256;
    if (XSTRCMP(md, "SHA384") == 0 || XSTRCMP(md, "sha384") == 0)
        return WC_HASH_TYPE_SHA384;
    if (XSTRCMP(md, "SHA512") == 0 || XSTRCMP(md, "sha512") == 0)
        return WC_HASH_TYPE_SHA512;
    return WC_HASH_TYPE_NONE; /* unsupported */
}

int SSKDF_digest(unsigned char *out, size_t out_len,
                 const WOLFSSL_EVP_MD *digest,
                 const unsigned char *secret, size_t secret_len,
                 const unsigned char *info, size_t info_len)
{
    if (out == NULL || digest == NULL || secret == NULL) {
        return 0;
    }
    if (out_len == 0 || secret_len == 0) {
        return 0;
    }

    enum wc_HashType hashType = evp_md_to_wc_hash_type(digest);
    if (hashType == WC_HASH_TYPE_NONE) {
        return 0;
    }

    /* Delegate to wolfSSL's native one-step KDF (NIST SP 800-56Cr2 §4.1).
     * Parameters: z=secret, fixedInfo=info, derivedSecretSz=out_len. */
    int ret = wc_KDA_KDF_onestep(
        secret, (word32)secret_len,
        info, (word32)info_len,
        (word32)out_len,
        hashType,
        out, (word32)out_len);

    return (ret == 0) ? 1 : 0;
}

/* ================================================================
 * SSKDF with HMAC (NIST SP 800-56Cr2 §4.2)
 *
 * wolfSSL does not yet provide an HMAC-based one-step KDF.
 * wc_KDA_KDF_onestep only supports the hash-based variant (§4.1)
 * and takes no salt parameter. This shim uses wolfSSL's HMAC
 * primitives directly. Replace with a native wolfSSL call when
 * one becomes available.
 *
 * For each counter i = 1, 2, ...:
 *   K(i) = HMAC(salt, counter_BE || Z || OtherInfo)
 * where counter is 32-bit big-endian.
 *
 * If salt is NULL or empty, an all-zero salt of length equal to
 * the digest block size is used (per NIST SP 800-56Cr2 §4.2).
 *
 * Returns 1 on success, 0 on failure.
 * ================================================================ */

int SSKDF_hmac(unsigned char *out, size_t out_len,
               const WOLFSSL_EVP_MD *digest,
               const unsigned char *secret, size_t secret_len,
               const unsigned char *info, size_t info_len,
               const unsigned char *salt, size_t salt_len)
{
    if (out == NULL || digest == NULL || secret == NULL) {
        return 0;
    }
    if (out_len == 0 || secret_len == 0) {
        return 0;
    }

    int md_size = wolfSSL_EVP_MD_size(digest);
    if (md_size <= 0 || md_size > 64) {
        return 0;
    }

    /* Default salt: all-zero bytes of digest block size.
     * wolfSSL's EVP_MD_block_size provides this. */
    unsigned char default_salt[144]; /* max block size (SHA-512 = 128) + margin */
    int block_size = 0;
    if (salt == NULL || salt_len == 0) {
        block_size = wolfSSL_EVP_MD_block_size(digest);
        if (block_size <= 0 || (size_t)block_size > sizeof(default_salt)) {
            return 0;
        }
        memset(default_salt, 0, (size_t)block_size);
        salt = default_salt;
        salt_len = (size_t)block_size;
    }

    WOLFSSL_HMAC_CTX *ctx = wolfSSL_HMAC_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    int ret = 0;
    size_t done = 0;

    for (unsigned int i = 1; done < out_len; i++) {
        unsigned char ctr[4];
        ctr[0] = (unsigned char)((i >> 24) & 0xFF);
        ctr[1] = (unsigned char)((i >> 16) & 0xFF);
        ctr[2] = (unsigned char)((i >> 8)  & 0xFF);
        ctr[3] = (unsigned char)( i        & 0xFF);

        if (wolfSSL_HMAC_Init_ex(ctx, salt, (int)salt_len, digest, NULL) != 1) {
            goto cleanup;
        }
        if (wolfSSL_HMAC_Update(ctx, ctr, sizeof(ctr)) != 1) {
            goto cleanup;
        }
        if (wolfSSL_HMAC_Update(ctx, secret, (int)secret_len) != 1) {
            goto cleanup;
        }
        if (info != NULL && info_len > 0) {
            if (wolfSSL_HMAC_Update(ctx, info, (int)info_len) != 1) {
                goto cleanup;
            }
        }

        unsigned char hmac_buf[64];
        unsigned int hmac_len = 0;
        if (wolfSSL_HMAC_Final(ctx, hmac_buf, &hmac_len) != 1) {
            goto cleanup;
        }

        size_t remaining = out_len - done;
        size_t to_copy = (remaining < (size_t)hmac_len) ? remaining : (size_t)hmac_len;
        memcpy(out + done, hmac_buf, to_copy);
        done += to_copy;
    }

    ret = 1;

cleanup:
    wolfSSL_HMAC_CTX_free(ctx);
    return ret;
}

#endif /* (OPENSSL_EXTRA || OPENSSL_ALL) && !NO_HMAC */

/* ================================================================
 * Crypto Callback (WOLF_CRYPTO_CB) accessor shims
 *
 * wc_CryptoInfo is a large union whose layout depends on compile options.
 * Rather than reproducing it in Rust, we expose only the fields needed
 * through stable accessor functions.
 * ================================================================ */
#ifdef WOLF_CRYPTO_CB

int wolfcrypt_cryptocb_info_get_algo_type(const wc_CryptoInfo *info) {
    return info->algo_type;
}

/* -- RNG fields -- */
unsigned char* wolfcrypt_cryptocb_info_rng_out(const wc_CryptoInfo *info) {
    return info->rng.out;
}
unsigned int wolfcrypt_cryptocb_info_rng_sz(const wc_CryptoInfo *info) {
    return info->rng.sz;
}

/* -- Hash fields -- */
int wolfcrypt_cryptocb_info_hash_type(const wc_CryptoInfo *info) {
    return info->hash.type;
}
const unsigned char* wolfcrypt_cryptocb_info_hash_in(const wc_CryptoInfo *info) {
    return info->hash.in;
}
unsigned int wolfcrypt_cryptocb_info_hash_in_sz(const wc_CryptoInfo *info) {
    return info->hash.inSz;
}
unsigned char* wolfcrypt_cryptocb_info_hash_digest(const wc_CryptoInfo *info) {
    return info->hash.digest;
}

/* -- HMAC fields -- */
int wolfcrypt_cryptocb_info_hmac_mac_type(const wc_CryptoInfo *info) {
    return info->hmac.macType;
}
const unsigned char* wolfcrypt_cryptocb_info_hmac_in(const wc_CryptoInfo *info) {
    return info->hmac.in;
}
unsigned int wolfcrypt_cryptocb_info_hmac_in_sz(const wc_CryptoInfo *info) {
    return info->hmac.inSz;
}
unsigned char* wolfcrypt_cryptocb_info_hmac_digest(const wc_CryptoInfo *info) {
    return info->hmac.digest;
}

/* -- Cipher fields -- */
int wolfcrypt_cryptocb_info_cipher_type(const wc_CryptoInfo *info) {
    return info->cipher.type;
}
int wolfcrypt_cryptocb_info_cipher_enc(const wc_CryptoInfo *info) {
    return info->cipher.enc;
}

/* -- PK (public key) fields -- */
int wolfcrypt_cryptocb_info_pk_type(const wc_CryptoInfo *info) {
    return info->pk.type;
}

#endif /* WOLF_CRYPTO_CB */
