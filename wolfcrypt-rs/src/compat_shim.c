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
#include <wolfssl/wolfcrypt/error-crypt.h>

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
_Static_assert(sizeof(WOLFSSL_AES_KEY) <= 512,
    "WOLFSSL_AES_KEY exceeds AES_KEY_ALLOC_SIZE (512) in lib.rs");
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
/* STRING_USER means wolfSSL's XSTRCMP/XSTRLEN macros are user-defined
 * (via user_settings.h) — no need to pull in string.h for them. */
#ifndef STRING_USER
#include <string.h>
#endif

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

/* -- PK eccsign fields -- */
#ifdef HAVE_ECC
const unsigned char* wolfcrypt_cryptocb_info_pk_eccsign_in(const wc_CryptoInfo *info) {
    return info->pk.eccsign.in;
}
unsigned int wolfcrypt_cryptocb_info_pk_eccsign_inlen(const wc_CryptoInfo *info) {
    return info->pk.eccsign.inlen;
}
unsigned char* wolfcrypt_cryptocb_info_pk_eccsign_out(wc_CryptoInfo *info) {
    return info->pk.eccsign.out;
}
unsigned int* wolfcrypt_cryptocb_info_pk_eccsign_outlen(wc_CryptoInfo *info) {
    return info->pk.eccsign.outlen;
}
void* wolfcrypt_cryptocb_info_pk_eccsign_key(const wc_CryptoInfo *info) {
    return info->pk.eccsign.key;
}
void* wolfcrypt_cryptocb_info_pk_eccsign_rng(const wc_CryptoInfo *info) {
    return info->pk.eccsign.rng;
}

/* -- PK eccverify fields -- */
const unsigned char* wolfcrypt_cryptocb_info_pk_eccverify_sig(const wc_CryptoInfo *info) {
    return info->pk.eccverify.sig;
}
unsigned int wolfcrypt_cryptocb_info_pk_eccverify_siglen(const wc_CryptoInfo *info) {
    return info->pk.eccverify.siglen;
}
const unsigned char* wolfcrypt_cryptocb_info_pk_eccverify_hash(const wc_CryptoInfo *info) {
    return info->pk.eccverify.hash;
}
unsigned int wolfcrypt_cryptocb_info_pk_eccverify_hashlen(const wc_CryptoInfo *info) {
    return info->pk.eccverify.hashlen;
}
int* wolfcrypt_cryptocb_info_pk_eccverify_res(wc_CryptoInfo *info) {
    return info->pk.eccverify.res;
}
void* wolfcrypt_cryptocb_info_pk_eccverify_key(const wc_CryptoInfo *info) {
    return info->pk.eccverify.key;
}

/* -- PK ecdh and eckg fields -- */
void* wolfcrypt_cryptocb_info_pk_ecdh_private_key(const wc_CryptoInfo *info) {
    return info->pk.ecdh.private_key;
}
void* wolfcrypt_cryptocb_info_pk_ecdh_public_key(const wc_CryptoInfo *info) {
    return info->pk.ecdh.public_key;
}
unsigned char* wolfcrypt_cryptocb_info_pk_ecdh_out(wc_CryptoInfo *info) {
    return info->pk.ecdh.out;
}
unsigned int* wolfcrypt_cryptocb_info_pk_ecdh_outlen(wc_CryptoInfo *info) {
    return info->pk.ecdh.outlen;
}
void* wolfcrypt_cryptocb_info_pk_eckg_key(const wc_CryptoInfo *info) {
    return info->pk.eckg.key;
}
int wolfcrypt_cryptocb_info_pk_eckg_size(const wc_CryptoInfo *info) {
    return info->pk.eckg.size;
}
int wolfcrypt_cryptocb_info_pk_eckg_curve_id(const wc_CryptoInfo *info) {
    return info->pk.eckg.curveId;
}
void* wolfcrypt_cryptocb_info_pk_eckg_rng(const wc_CryptoInfo *info) {
    return info->pk.eckg.rng;
}
#endif /* HAVE_ECC */

/* -- Cipher AES-GCM enc/dec fields -- */
#ifdef HAVE_AESGCM
void* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_aes(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.aes;
}
unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_out(wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.out;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_in(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.in;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_enc_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.sz;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_iv(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.iv;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_enc_iv_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.ivSz;
}
unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_tag(wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.authTag;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_tag_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.authTagSz;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_in(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.authIn;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_enc_auth_in_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_enc.authInSz;
}

void* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_aes(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.aes;
}
unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_out(wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.out;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_in(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.in;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_dec_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.sz;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_iv(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.iv;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_dec_iv_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.ivSz;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_tag(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.authTag;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_tag_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.authTagSz;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_in(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.authIn;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aesgcm_dec_auth_in_sz(const wc_CryptoInfo *info) {
    return info->cipher.aesgcm_dec.authInSz;
}
#endif /* HAVE_AESGCM */

/* -- Cipher AES-CBC fields -- */
#ifdef HAVE_AES_CBC
void* wolfcrypt_cryptocb_info_cipher_aescbc_aes(const wc_CryptoInfo *info) {
    return info->cipher.aescbc.aes;
}
unsigned char* wolfcrypt_cryptocb_info_cipher_aescbc_out(wc_CryptoInfo *info) {
    return info->cipher.aescbc.out;
}
const unsigned char* wolfcrypt_cryptocb_info_cipher_aescbc_in(const wc_CryptoInfo *info) {
    return info->cipher.aescbc.in;
}
unsigned int wolfcrypt_cryptocb_info_cipher_aescbc_sz(const wc_CryptoInfo *info) {
    return info->cipher.aescbc.sz;
}
#endif /* HAVE_AES_CBC */

/* -- Aes struct field accessors (for CryptoCb hardware implementations) --
 * devKey requires WOLF_CRYPTO_CB (already guaranteed by outer #ifdef).
 * reg and keylen are always present in the Aes struct.  */
#ifndef NO_AES
unsigned int wolfcrypt_aes_keylen(const void *aes_ptr) {
    return ((const Aes*)aes_ptr)->keylen;
}
const unsigned char* wolfcrypt_aes_devkey(const void *aes_ptr) {
    return (const unsigned char*)((const Aes*)aes_ptr)->devKey;
}
const unsigned char* wolfcrypt_aes_reg(const void *aes_ptr) {
    return (const unsigned char*)((const Aes*)aes_ptr)->reg;
}
unsigned char* wolfcrypt_aes_reg_mut(void *aes_ptr) {
    return (unsigned char*)((Aes*)aes_ptr)->reg;
}
#endif /* !NO_AES */

#endif /* WOLF_CRYPTO_CB */

/* ============================================================
 * Native SHA-256 / SHA-384 heap-allocated context shims.
 *
 * These wrappers let Rust code manage SHA state without knowing
 * the layout of wc_Sha256 or wc_Sha512 (which changes between
 * wolfSSL builds and target architectures).  The context is
 * heap-allocated via XMALLOC so the Rust side only ever holds
 * an opaque *mut c_void.
 *
 * Used by wolfcrypt/src/digest.rs when OPENSSL_EXTRA is absent
 * (i.e. the cryptocb-only firmware build).
 * ============================================================ */

#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>

void* wolfcrypt_sha256_ctx_new(void) {
    wc_Sha256 *ctx = (wc_Sha256*)XMALLOC(sizeof(wc_Sha256),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha256(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha256_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha256Update((wc_Sha256*)ctx, data, len);
}

int wolfcrypt_sha256_final(void *ctx, unsigned char *hash) {
    return wc_Sha256Final((wc_Sha256*)ctx, hash);
}

void wolfcrypt_sha256_free(void *ctx) {
    wc_Sha256Free((wc_Sha256*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha256_copy(const void *src, void **dst_out) {
    wc_Sha256 *dst = (wc_Sha256*)XMALLOC(sizeof(wc_Sha256),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha256Copy((wc_Sha256*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha256_reset(void *ctx) {
    wc_Sha256Free((wc_Sha256*)ctx);
    return wc_InitSha256((wc_Sha256*)ctx);
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA384
#include <wolfssl/wolfcrypt/sha512.h>

void* wolfcrypt_sha384_ctx_new(void) {
    wc_Sha384 *ctx = (wc_Sha384*)XMALLOC(sizeof(wc_Sha384),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha384(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha384_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha384Update((wc_Sha384*)ctx, data, len);
}

int wolfcrypt_sha384_final(void *ctx, unsigned char *hash) {
    return wc_Sha384Final((wc_Sha384*)ctx, hash);
}

void wolfcrypt_sha384_free(void *ctx) {
    wc_Sha384Free((wc_Sha384*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha384_copy(const void *src, void **dst_out) {
    wc_Sha384 *dst = (wc_Sha384*)XMALLOC(sizeof(wc_Sha384),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha384Copy((wc_Sha384*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha384_reset(void *ctx) {
    wc_Sha384Free((wc_Sha384*)ctx);
    return wc_InitSha384((wc_Sha384*)ctx);
}
#endif /* WOLFSSL_SHA384 */

/* ================================================================
 * Native HMAC shims (wc_Hmac* API, no OPENSSL_EXTRA required).
 * ================================================================ */
#if !defined(NO_HMAC)

#include <wolfssl/wolfcrypt/hmac.h>

static void* wolfcrypt_hmac_new_impl(int type, const unsigned char* key, unsigned int keylen) {
    Hmac *ctx = (Hmac*)XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) return NULL;
    if (wc_HmacInit(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_HmacSetKey(ctx, type, key, keylen) != 0) {
        wc_HmacFree(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

void* wolfcrypt_hmac_sha1_new(const unsigned char* key, unsigned int keylen) {
    return wolfcrypt_hmac_new_impl(WC_SHA, key, keylen);
}

void* wolfcrypt_hmac_sha256_new(const unsigned char* key, unsigned int keylen) {
    return wolfcrypt_hmac_new_impl(WC_SHA256, key, keylen);
}

#ifdef WOLFSSL_SHA384
void* wolfcrypt_hmac_sha384_new(const unsigned char* key, unsigned int keylen) {
    return wolfcrypt_hmac_new_impl(WC_SHA384, key, keylen);
}
#endif

#ifdef WOLFSSL_SHA512
void* wolfcrypt_hmac_sha512_new(const unsigned char* key, unsigned int keylen) {
    return wolfcrypt_hmac_new_impl(WC_SHA512, key, keylen);
}
#endif

int wolfcrypt_hmac_update(void* ctx, const unsigned char* data, unsigned int len) {
    return wc_HmacUpdate((Hmac*)ctx, data, len);
}

int wolfcrypt_hmac_final(void* ctx, unsigned char* out) {
    return wc_HmacFinal((Hmac*)ctx, out);
}

void wolfcrypt_hmac_free(void* ctx) {
    wc_HmacFree((Hmac*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif /* !NO_HMAC */

#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>

void* wolfcrypt_sha1_ctx_new(void) {
    wc_Sha *ctx = (wc_Sha*)XMALLOC(sizeof(wc_Sha),
                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha1_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_ShaUpdate((wc_Sha*)ctx, data, len);
}

int wolfcrypt_sha1_final(void *ctx, unsigned char *hash) {
    return wc_ShaFinal((wc_Sha*)ctx, hash);
}

void wolfcrypt_sha1_free(void *ctx) {
    wc_ShaFree((wc_Sha*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha1_copy(const void *src, void **dst_out) {
    wc_Sha *dst = (wc_Sha*)XMALLOC(sizeof(wc_Sha),
                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_ShaCopy((wc_Sha*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha1_reset(void *ctx) {
    wc_ShaFree((wc_Sha*)ctx);
    return wc_InitSha((wc_Sha*)ctx);
}
#endif /* !NO_SHA */

#ifdef WOLFSSL_SHA224
/* wc_Sha224 is defined in sha256.h in wolfSSL */
#include <wolfssl/wolfcrypt/sha256.h>

void* wolfcrypt_sha224_ctx_new(void) {
    wc_Sha224 *ctx = (wc_Sha224*)XMALLOC(sizeof(wc_Sha224),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha224(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha224_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha224Update((wc_Sha224*)ctx, data, len);
}

int wolfcrypt_sha224_final(void *ctx, unsigned char *hash) {
    return wc_Sha224Final((wc_Sha224*)ctx, hash);
}

void wolfcrypt_sha224_free(void *ctx) {
    wc_Sha224Free((wc_Sha224*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha224_copy(const void *src, void **dst_out) {
    wc_Sha224 *dst = (wc_Sha224*)XMALLOC(sizeof(wc_Sha224),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha224Copy((wc_Sha224*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha224_reset(void *ctx) {
    wc_Sha224Free((wc_Sha224*)ctx);
    return wc_InitSha224((wc_Sha224*)ctx);
}
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>

void* wolfcrypt_sha512_ctx_new(void) {
    wc_Sha512 *ctx = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha512(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha512_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha512Update((wc_Sha512*)ctx, data, len);
}

int wolfcrypt_sha512_final(void *ctx, unsigned char *hash) {
    return wc_Sha512Final((wc_Sha512*)ctx, hash);
}

void wolfcrypt_sha512_free(void *ctx) {
    wc_Sha512Free((wc_Sha512*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha512_copy(const void *src, void **dst_out) {
    wc_Sha512 *dst = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha512Copy((wc_Sha512*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha512_reset(void *ctx) {
    wc_Sha512Free((wc_Sha512*)ctx);
    return wc_InitSha512((wc_Sha512*)ctx);
}

#if !defined(WOLFSSL_NOSHA512_256)
void* wolfcrypt_sha512_256_ctx_new(void) {
    wc_Sha512 *ctx = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha512_256(ctx) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha512_256_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha512_256Update((wc_Sha512*)ctx, data, len);
}

int wolfcrypt_sha512_256_final(void *ctx, unsigned char *hash) {
    return wc_Sha512_256Final((wc_Sha512*)ctx, hash);
}

void wolfcrypt_sha512_256_free(void *ctx) {
    wc_Sha512_256Free((wc_Sha512*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha512_256_copy(const void *src, void **dst_out) {
    wc_Sha512 *dst = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512),
                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha512_256Copy((wc_Sha512*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha512_256_reset(void *ctx) {
    wc_Sha512_256Free((wc_Sha512*)ctx);
    return wc_InitSha512_256((wc_Sha512*)ctx);
}
#endif /* !WOLFSSL_NOSHA512_256 */

#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA3
#include <wolfssl/wolfcrypt/sha3.h>

void* wolfcrypt_sha3_256_ctx_new(void) {
    wc_Sha3 *ctx = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha3_256(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha3_256_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha3_256_Update((wc_Sha3*)ctx, data, len);
}

int wolfcrypt_sha3_256_final(void *ctx, unsigned char *hash) {
    return wc_Sha3_256_Final((wc_Sha3*)ctx, hash);
}

void wolfcrypt_sha3_256_free(void *ctx) {
    wc_Sha3_256_Free((wc_Sha3*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha3_256_copy(const void *src, void **dst_out) {
    wc_Sha3 *dst = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha3_256_Copy((wc_Sha3*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha3_256_reset(void *ctx) {
    wc_Sha3_256_Free((wc_Sha3*)ctx);
    return wc_InitSha3_256((wc_Sha3*)ctx, NULL, INVALID_DEVID);
}

void* wolfcrypt_sha3_384_ctx_new(void) {
    wc_Sha3 *ctx = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha3_384(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha3_384_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha3_384_Update((wc_Sha3*)ctx, data, len);
}

int wolfcrypt_sha3_384_final(void *ctx, unsigned char *hash) {
    return wc_Sha3_384_Final((wc_Sha3*)ctx, hash);
}

void wolfcrypt_sha3_384_free(void *ctx) {
    wc_Sha3_384_Free((wc_Sha3*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha3_384_copy(const void *src, void **dst_out) {
    wc_Sha3 *dst = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha3_384_Copy((wc_Sha3*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha3_384_reset(void *ctx) {
    wc_Sha3_384_Free((wc_Sha3*)ctx);
    return wc_InitSha3_384((wc_Sha3*)ctx, NULL, INVALID_DEVID);
}

void* wolfcrypt_sha3_512_ctx_new(void) {
    wc_Sha3 *ctx = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    if (wc_InitSha3_512(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_sha3_512_update(void *ctx, const unsigned char *data, unsigned int len) {
    return wc_Sha3_512_Update((wc_Sha3*)ctx, data, len);
}

int wolfcrypt_sha3_512_final(void *ctx, unsigned char *hash) {
    return wc_Sha3_512_Final((wc_Sha3*)ctx, hash);
}

void wolfcrypt_sha3_512_free(void *ctx) {
    wc_Sha3_512_Free((wc_Sha3*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

int wolfcrypt_sha3_512_copy(const void *src, void **dst_out) {
    wc_Sha3 *dst = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3),
                                      NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!dst) return MEMORY_E;
    int rc = wc_Sha3_512_Copy((wc_Sha3*)src, dst);
    if (rc != 0) {
        XFREE(dst, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return rc;
    }
    *dst_out = dst;
    return 0;
}

int wolfcrypt_sha3_512_reset(void *ctx) {
    wc_Sha3_512_Free((wc_Sha3*)ctx);
    return wc_InitSha3_512((wc_Sha3*)ctx, NULL, INVALID_DEVID);
}
#endif /* WOLFSSL_SHA3 */

/* ================================================================
 * Native CMAC shims (wc_Cmac* API, no OPENSSL_EXTRA required).
 * ================================================================ */
#ifdef WOLFSSL_CMAC

#include <wolfssl/wolfcrypt/cmac.h>

static void* wolfcrypt_cmac_new_impl(const unsigned char* key, unsigned int key_sz) {
    Cmac *ctx = (Cmac*)XMALLOC(sizeof(Cmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) return NULL;
    if (wc_InitCmac(ctx, key, key_sz, WC_CMAC_AES, NULL) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

void* wolfcrypt_cmac_aes128_new(const unsigned char* key) {
    return wolfcrypt_cmac_new_impl(key, 16);
}

void* wolfcrypt_cmac_aes256_new(const unsigned char* key) {
    return wolfcrypt_cmac_new_impl(key, 32);
}

int wolfcrypt_cmac_update(void* ctx, const unsigned char* data, unsigned int len) {
    return wc_CmacUpdate((Cmac*)ctx, data, len);
}

int wolfcrypt_cmac_final(void* ctx, unsigned char* out, unsigned int* out_len) {
    word32 sz = *out_len;
    int rc = wc_CmacFinal((Cmac*)ctx, out, &sz);
    *out_len = (unsigned int)sz;
    return rc;
}

void wolfcrypt_cmac_free(void* ctx) {
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif /* WOLFSSL_CMAC */

/* ================================================================
 * Native 3DES shims (wc_Des3* API, no OPENSSL_EXTRA required).
 * ================================================================ */
#ifndef NO_DES3

#include <wolfssl/wolfcrypt/des3.h>

void* wolfcrypt_des3_enc_new(const unsigned char* key, const unsigned char* iv) {
    Des3 *ctx = (Des3*)XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) return NULL;
    if (wc_Des3Init(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_Des3_SetKey(ctx, key, iv, DES_ENCRYPTION) != 0) {
        wc_Des3Free(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

void* wolfcrypt_des3_dec_new(const unsigned char* key, const unsigned char* iv) {
    Des3 *ctx = (Des3*)XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) return NULL;
    if (wc_Des3Init(ctx, NULL, INVALID_DEVID) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_Des3_SetKey(ctx, key, iv, DES_DECRYPTION) != 0) {
        wc_Des3Free(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    return ctx;
}

int wolfcrypt_des3_cbc_encrypt(void* ctx, const unsigned char* in, unsigned char* out, unsigned int sz) {
    return wc_Des3_CbcEncrypt((Des3*)ctx, out, in, sz);
}

int wolfcrypt_des3_cbc_decrypt(void* ctx, const unsigned char* in, unsigned char* out, unsigned int sz) {
    return wc_Des3_CbcDecrypt((Des3*)ctx, out, in, sz);
}

void wolfcrypt_des3_free(void* ctx) {
    wc_Des3Free((Des3*)ctx);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif /* !NO_DES3 */

/* ================================================================
 * Native DH shims (wc_Dh* API, no OPENSSL_EXTRA required).
 *
 * WC_FFDHE_2048 = 256, WC_FFDHE_3072 = 257, WC_FFDHE_4096 = 258
 * (values from wolfssl/wolfcrypt/dh.h)
 * ================================================================ */
#ifndef NO_DH

#include <wolfssl/wolfcrypt/dh.h>

typedef struct {
    DhKey  key;
    WC_RNG rng;
    byte   priv[512];
    word32 privSz;
    byte   pub[512];
    word32 pubSz;
    word32 groupSz;
} wolfcrypt_dh_ctx;

void* wolfcrypt_dh_new(int name, unsigned int group_sz) {
    wolfcrypt_dh_ctx *ctx = (wolfcrypt_dh_ctx*)XMALLOC(sizeof(*ctx),
                                                        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    XMEMSET(ctx, 0, sizeof(*ctx));

    if (wc_InitRng(&ctx->rng) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_InitDhKey(&ctx->key) != 0) {
        wc_FreeRng(&ctx->rng);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_DhSetNamedKey(&ctx->key, name) != 0) {
        wc_FreeDhKey(&ctx->key);
        wc_FreeRng(&ctx->rng);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    ctx->groupSz = group_sz;
    return ctx;
}

int wolfcrypt_dh_generate_keypair(void* handle) {
    wolfcrypt_dh_ctx *ctx = (wolfcrypt_dh_ctx*)handle;
    ctx->privSz = (word32)sizeof(ctx->priv);
    ctx->pubSz  = (word32)sizeof(ctx->pub);
    return wc_DhGenerateKeyPair(&ctx->key, &ctx->rng,
                                ctx->priv, &ctx->privSz,
                                ctx->pub,  &ctx->pubSz);
}

int wolfcrypt_dh_public_key(void* handle, unsigned char* out, unsigned int* out_len) {
    wolfcrypt_dh_ctx *ctx = (wolfcrypt_dh_ctx*)handle;
    if (*out_len < ctx->groupSz) {
        *out_len = ctx->groupSz;
        return BUFFER_E;
    }
    /* Left-pad with zeros to reach a fixed groupSz-byte output. */
    if (ctx->pubSz < ctx->groupSz) {
        word32 pad = ctx->groupSz - ctx->pubSz;
        XMEMSET(out, 0, pad);
        XMEMCPY(out + pad, ctx->pub, ctx->pubSz);
    } else {
        XMEMCPY(out, ctx->pub, ctx->pubSz);
    }
    *out_len = ctx->groupSz;
    return 0;
}

int wolfcrypt_dh_agree(void* handle, const unsigned char* peer_pub,
                       unsigned int peer_pub_sz, unsigned char* secret,
                       unsigned int* secret_sz) {
    wolfcrypt_dh_ctx *ctx = (wolfcrypt_dh_ctx*)handle;
    byte tmp[512];
    word32 sz = (word32)sizeof(tmp);

    int rc = wc_DhAgree(&ctx->key, tmp, &sz,
                        ctx->priv, ctx->privSz,
                        peer_pub, peer_pub_sz);
    if (rc != 0) {
        wc_ForceZero(tmp, sizeof(tmp));
        return rc;
    }

    if (*secret_sz < ctx->groupSz) {
        wc_ForceZero(tmp, sizeof(tmp));
        *secret_sz = ctx->groupSz;
        return BUFFER_E;
    }

    /* Left-pad with zeros to groupSz bytes (matches DH_compute_key_padded). */
    if (sz < ctx->groupSz) {
        word32 pad = ctx->groupSz - sz;
        XMEMSET(secret, 0, pad);
        XMEMCPY(secret + pad, tmp, sz);
    } else {
        XMEMCPY(secret, tmp, sz);
    }
    *secret_sz = ctx->groupSz;
    wc_ForceZero(tmp, sizeof(tmp));
    return 0;
}

void wolfcrypt_dh_free(void* handle) {
    wolfcrypt_dh_ctx *ctx = (wolfcrypt_dh_ctx*)handle;
    wc_ForceZero(ctx->priv, sizeof(ctx->priv));
    wc_FreeDhKey(&ctx->key);
    wc_FreeRng(&ctx->rng);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif /* !NO_DH */

/* ----------------------------------------------------------------- */
/* RSA key lifecycle shims — no OPENSSL_EXTRA required               */
/* ----------------------------------------------------------------- */
#ifndef NO_RSA

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>

/* Maximum DigestInfo DER size: SEQUENCE { SEQUENCE{OID,NULL} OCTET-STRING{hash} }
 * SHA-512 (64 bytes) + ~20 bytes ASN.1 overhead = 83 bytes; 128 is safe. */
#define WOLFCRYPT_MAX_DIGEST_INFO_SZ 128

/* Map our stable hash-bit-width codes (256/384/512) to wolfSSL enum values.
 * Using enum names avoids coupling Rust to wolfSSL's internal integer values,
 * which differ between FIPS and non-FIPS builds. */
static enum wc_HashType wolfcrypt_rsa_hash_wc_type(int hash_bits)
{
    switch (hash_bits) {
#ifndef NO_SHA
        case 160: return WC_HASH_TYPE_SHA;
#endif
        case 256: return WC_HASH_TYPE_SHA256;
        case 384: return WC_HASH_TYPE_SHA384;
        case 512: return WC_HASH_TYPE_SHA512;
        default:  return WC_HASH_TYPE_NONE;
    }
}

/* Map hash_bits to the corresponding MGF1 constant (WC_MGF1SHA*).
 * Returns -1 for unsupported hash sizes. */
static int wolfcrypt_rsa_hash_mgf(int hash_bits)
{
    switch (hash_bits) {
        case 256: return WC_MGF1SHA256;
        case 384: return WC_MGF1SHA384;
        case 512: return WC_MGF1SHA512;
        default:  return -1;
    }
}

typedef struct {
    RsaKey key;
    WC_RNG rng;
} wolfcrypt_rsa_ctx;

void* wolfcrypt_rsa_new(void) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)XMALLOC(sizeof(*ctx),
                                                          NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!ctx) return NULL;
    XMEMSET(ctx, 0, sizeof(*ctx));

    if (wc_InitRsaKey(&ctx->key, NULL) != 0) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    if (wc_InitRng(&ctx->rng) != 0) {
        wc_FreeRsaKey(&ctx->key);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
#ifndef WC_NO_RNG
    /* Associate the RNG so that wolfCrypt internal RNG calls work. */
    wc_RsaSetRNG(&ctx->key, &ctx->rng);
#endif
    return ctx;
}

void wolfcrypt_rsa_free(void* handle) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    if (!ctx) return;
    wc_FreeRsaKey(&ctx->key);
    wc_FreeRng(&ctx->rng);
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

#ifdef WOLFSSL_KEY_GEN
int wolfcrypt_rsa_generate(void* handle, int bits) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    return wc_MakeRsaKey(&ctx->key, bits, WC_RSA_EXPONENT, &ctx->rng);
}
#else
int wolfcrypt_rsa_generate(void* handle, int bits) {
    (void)handle; (void)bits;
    return NOT_COMPILED_IN;
}
#endif /* WOLFSSL_KEY_GEN */

int wolfcrypt_rsa_import_private_pkcs1(void* handle, const byte* der, word32 der_len) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    word32 idx = 0;
    int rc = wc_RsaPrivateKeyDecode(der, &idx, &ctx->key, der_len);
    if (rc != 0) return rc;
#ifndef WC_NO_RNG
    /* Re-attach RNG after import so randomised operations (PSS, OAEP) work. */
    wc_RsaSetRNG(&ctx->key, &ctx->rng);
#endif
    return 0;
}

int wolfcrypt_rsa_import_public_spki(void* handle, const byte* der, word32 der_len) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    word32 idx = 0;
    /* wc_RsaPublicKeyDecode accepts SubjectPublicKeyInfo (SPKI) DER. */
    return wc_RsaPublicKeyDecode(der, &idx, &ctx->key, der_len);
}

/* wolfcrypt_rsa_export_* require WOLFSSL_KEY_TO_DER in user_settings.h. */
#ifdef WOLFSSL_KEY_TO_DER

int wolfcrypt_rsa_export_private_pkcs1(void* handle, byte* out, word32* out_len) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    /* wc_RsaKeyToDer: pass out=NULL to query required size.
     * Returns bytes written (>0) on success, negative error code on failure. */
    int rc = wc_RsaKeyToDer(&ctx->key, out, out ? *out_len : 0);
    if (rc < 0) return rc;
    *out_len = (word32)rc;
    return 0;
}

int wolfcrypt_rsa_export_public_spki(void* handle, byte* out, word32* out_len) {
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    /* wc_RsaKeyToPublicDer outputs SubjectPublicKeyInfo (SPKI) DER
     * (with_header implicitly = 1). */
    int rc = wc_RsaKeyToPublicDer(&ctx->key, out, out ? *out_len : 0);
    if (rc < 0) return rc;
    *out_len = (word32)rc;
    return 0;
}

#else /* !WOLFSSL_KEY_TO_DER */

int wolfcrypt_rsa_export_private_pkcs1(void* handle, byte* out, word32* out_len) {
    (void)handle; (void)out; (void)out_len;
    return NOT_COMPILED_IN;
}

int wolfcrypt_rsa_export_public_spki(void* handle, byte* out, word32* out_len) {
    (void)handle; (void)out; (void)out_len;
    return NOT_COMPILED_IN;
}

#endif /* WOLFSSL_KEY_TO_DER */

int wolfcrypt_rsa_key_size_bytes(void* handle) {
    const wolfcrypt_rsa_ctx *ctx = (const wolfcrypt_rsa_ctx*)handle;
    return wc_RsaEncryptSize(&ctx->key);
}

/* Encrypt `pt_len` bytes from `pt` using OAEP with SHA-256/MGF1-SHA256.
 * `out` must point to a buffer of at least wolfcrypt_rsa_key_size_bytes(handle)
 * bytes. On success returns the ciphertext length (== key size in bytes). */
int wolfcrypt_rsa_oaep_encrypt_sha256(void* handle,
                                      const byte* pt, word32 pt_len,
                                      byte* out,    word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    return wc_RsaPublicEncrypt_ex(pt, pt_len, out, out_buf_len, &ctx->key,
                                  &ctx->rng, WC_RSA_OAEP_PAD,
                                  WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                  NULL, 0);
}

/* Decrypt `ct_len` bytes from `ct` using OAEP with SHA-256/MGF1-SHA256.
 * `out` must point to a buffer of at least wolfcrypt_rsa_key_size_bytes(handle)
 * bytes. On success returns the plaintext length (>0). */
int wolfcrypt_rsa_oaep_decrypt_sha256(void* handle,
                                      const byte* ct, word32 ct_len,
                                      byte* out,    word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    return wc_RsaPrivateDecrypt_ex(ct, ct_len, out, out_buf_len, &ctx->key,
                                   WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
                                   WC_MGF1SHA256, NULL, 0);
}

/* Encrypt `in_len` bytes from `in` using PKCS#1v1.5 padding (RSA public-key op).
 * `out` must be at least wolfcrypt_rsa_key_size_bytes(handle) bytes.
 * Returns ciphertext length (== key modulus size) on success, negative on error.
 * Follows the same convention as wolfcrypt_rsa_oaep_encrypt_sha256. */
int wolfcrypt_rsa_pkcs1v15_encrypt(void* handle,
                                    const byte* in, word32 in_len,
                                    byte* out, word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    return wc_RsaPublicEncrypt(in, in_len, out, out_buf_len,
                               &ctx->key, &ctx->rng);
}

/* Decrypt `in_len` bytes from `in` using PKCS#1v1.5 padding (RSA private-key op).
 * `out` must be at least wolfcrypt_rsa_key_size_bytes(handle) bytes.
 * Returns plaintext length (> 0) on success, 0 or negative on error.
 * Callers must check rc <= 0 for failure (matches EVP_PKEY_decrypt semantics).
 * NOTE: wolfSSL built with WOLFSSL_RSA_DECRYPT_TO_0_LEN returns 0 for both
 * invalid padding and valid empty plaintext; callers treat 0 as failure. */
int wolfcrypt_rsa_pkcs1v15_decrypt(void* handle,
                                    const byte* in, word32 in_len,
                                    byte* out, word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    return wc_RsaPrivateDecrypt(in, in_len, out, out_buf_len, &ctx->key);
}

/* Encrypt `in_len` bytes from `in` using OAEP padding with explicit hash.
 * hash_bits selects the OAEP hash and MGF1 hash: 256, 384, or 512.
 * `out` must be at least wolfcrypt_rsa_key_size_bytes(handle) bytes.
 * Returns ciphertext length on success, negative on error. */
int wolfcrypt_rsa_oaep_encrypt(void* handle, int hash_bits,
                                const byte* in, word32 in_len,
                                byte* out, word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    int mgf = wolfcrypt_rsa_hash_mgf(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE || mgf < 0) return BAD_FUNC_ARG;
    return wc_RsaPublicEncrypt_ex(in, in_len, out, out_buf_len, &ctx->key,
                                  &ctx->rng, WC_RSA_OAEP_PAD,
                                  hash_type, mgf, NULL, 0);
}

/* Decrypt `in_len` bytes from `in` using OAEP padding with explicit hash.
 * hash_bits selects the OAEP hash and MGF1 hash: 256, 384, or 512.
 * `out` must be at least wolfcrypt_rsa_key_size_bytes(handle) bytes.
 * Returns plaintext length (>= 0) on success, negative on error.
 * Callers must check rc <= 0 for failure. */
int wolfcrypt_rsa_oaep_decrypt(void* handle, int hash_bits,
                                const byte* in, word32 in_len,
                                byte* out, word32 out_buf_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    int mgf = wolfcrypt_rsa_hash_mgf(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE || mgf < 0) return BAD_FUNC_ARG;
    return wc_RsaPrivateDecrypt_ex(in, in_len, out, out_buf_len, &ctx->key,
                                   WC_RSA_OAEP_PAD, hash_type, mgf, NULL, 0);
}

/* Sign `msg_len` bytes from `msg` using RSA-PKCS#1v1.5.
 *
 * hash_bits: 256, 384, or 512 — selects SHA-256/384/512 as the hash.
 * sig must point to a buffer of at least wolfcrypt_rsa_key_size_bytes() bytes.
 * On success, *sig_len is set to the signature length and returns 0.
 * On error returns a negative wolfCrypt error code. */
int wolfcrypt_rsa_pkcs1v15_sign(void* handle,
                                 int hash_bits,
                                 const byte* msg, word32 msg_len,
                                 byte* sig, word32* sig_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type;
    byte hash[WC_MAX_DIGEST_SIZE];
    byte digest_info[WOLFCRYPT_MAX_DIGEST_INFO_SZ];
    word32 hash_len;
    word32 encoded_len;
    int oid;
    int rc;

    hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE)
        return BAD_FUNC_ARG;

    rc = wc_HashGetDigestSize(hash_type);
    if (rc <= 0) return BAD_FUNC_ARG;
    hash_len = (word32)rc;

    oid = wc_HashGetOID(hash_type);
    if (oid < 0) return oid;

    /* Hash the message. */
    rc = wc_Hash(hash_type, msg, msg_len, hash, hash_len);
    if (rc != 0) return rc;

    /* Build DigestInfo DER: SEQUENCE { AlgorithmIdentifier OCTET-STRING{hash} }
     * wc_EncodeSignature(out, digest, digest_len, hashOID) writes the full
     * DER to `out`, which must be at least WOLFCRYPT_MAX_DIGEST_INFO_SZ bytes. */
    encoded_len = wc_EncodeSignature(digest_info, hash, hash_len, oid);
    if (encoded_len == 0) return BAD_FUNC_ARG;

    /* RSA-sign the DigestInfo with PKCS#1v1.5 padding. */
    rc = wc_RsaSSL_Sign(digest_info, encoded_len, sig, *sig_len,
                        &ctx->key, &ctx->rng);
    if (rc < 0) return rc;
    *sig_len = (word32)rc;
    return 0;
}

/* Verify an RSA-PKCS#1v1.5 signature.
 *
 * hash_bits: 256, 384, or 512.
 * Returns 0 if signature is valid, SIG_VERIFY_E if invalid,
 * or another negative wolfCrypt error code on failure.
 *
 * wc_RsaSSL_VerifyInline modifies the signature buffer in-place, so
 * a local copy of sig is made to avoid clobbering the caller's buffer. */
int wolfcrypt_rsa_pkcs1v15_verify(void* handle,
                                   int hash_bits,
                                   const byte* msg, word32 msg_len,
                                   const byte* sig, word32 sig_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type;
    byte hash[WC_MAX_DIGEST_SIZE];
    byte expected_di[WOLFCRYPT_MAX_DIGEST_INFO_SZ];
    /* SP math max key = 4096 bits = 512 bytes. */
    byte sig_copy[512];
    byte *decrypted;
    word32 hash_len;
    word32 expected_len;
    int oid;
    int rc;

    if (sig_len > sizeof(sig_copy)) return BAD_FUNC_ARG;

    hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE) return BAD_FUNC_ARG;

    rc = wc_HashGetDigestSize(hash_type);
    if (rc <= 0) return BAD_FUNC_ARG;
    hash_len = (word32)rc;

    oid = wc_HashGetOID(hash_type);
    if (oid < 0) return oid;

    /* Hash the message to build the expected DigestInfo. */
    rc = wc_Hash(hash_type, msg, msg_len, hash, hash_len);
    if (rc != 0) return rc;

    expected_len = wc_EncodeSignature(expected_di, hash, hash_len, oid);
    if (expected_len == 0) return BAD_FUNC_ARG;

    /* RSA-decrypt the signature inline (modifies sig_copy in-place,
     * sets decrypted to point into sig_copy at the decrypted DigestInfo). */
    XMEMCPY(sig_copy, sig, sig_len);
    rc = wc_RsaSSL_VerifyInline(sig_copy, sig_len, &decrypted, &ctx->key);
    if (rc < 0) return rc;

    /* Constant-time comparison of decrypted DigestInfo with expected. */
    if ((word32)rc != expected_len ||
            XMEMCMP(decrypted, expected_di, expected_len) != 0) {
        return SIG_VERIFY_E;
    }
    return 0;
}

#ifdef WC_RSA_PSS

/* Sign `msg_len` bytes from `msg` using RSA-PSS.
 *
 * hash_bits: 256, 384, or 512.
 * Salt length is set to WC_RSA_PSS_SALTLEN_DIGEST (-1), meaning the salt
 * equals the hash output length. This matches OpenSSL RSA_PSS_SALTLEN_DIGEST.
 * sig must point to a buffer of at least wolfcrypt_rsa_key_size_bytes() bytes.
 * On success, *sig_len is set to the signature length and returns 0.
 * PSS signing is randomised: each call produces a different signature. */
int wolfcrypt_rsa_pss_sign(void* handle,
                            int hash_bits,
                            const byte* msg, word32 msg_len,
                            byte* sig, word32* sig_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type;
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 hash_len;
    int mgf;
    int rc;

    hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE) return BAD_FUNC_ARG;

    rc = wc_HashGetDigestSize(hash_type);
    if (rc <= 0) return BAD_FUNC_ARG;
    hash_len = (word32)rc;

    mgf = wolfcrypt_rsa_hash_mgf(hash_bits);
    if (mgf < 0) return BAD_FUNC_ARG;

    /* Hash the message. */
    rc = wc_Hash(hash_type, msg, msg_len, hash, hash_len);
    if (rc != 0) return rc;

    /* Sign the hash with PSS padding. wc_RsaPSS_Sign_ex expects the
     * pre-hashed message as `in`. Salt = WC_RSA_PSS_SALTLEN_DIGEST = hash_len. */
    rc = wc_RsaPSS_Sign_ex(hash, hash_len, sig, *sig_len,
                           hash_type, mgf, WC_RSA_PSS_SALTLEN_DIGEST,
                           &ctx->key, &ctx->rng);
    if (rc < 0) return rc;
    *sig_len = (word32)rc;
    return 0;
}

/* Verify an RSA-PSS signature.
 *
 * hash_bits: 256, 384, or 512.
 * Returns 0 if signature is valid, negative wolfCrypt error code otherwise.
 *
 * wc_RsaPSS_VerifyCheck computes the PSS decryption internally and checks
 * the padding against the provided message digest. It assumes salt length
 * equals the hash length, matching our signing convention. */
int wolfcrypt_rsa_pss_verify(void* handle,
                              int hash_bits,
                              const byte* msg, word32 msg_len,
                              const byte* sig, word32 sig_len)
{
    wolfcrypt_rsa_ctx *ctx = (wolfcrypt_rsa_ctx*)handle;
    enum wc_HashType hash_type;
    byte hash[WC_MAX_DIGEST_SIZE];
    /* wc_RsaPSS_VerifyCheck needs a writable output buffer for the PSS block. */
    byte decrypted[512];
    word32 hash_len;
    int mgf;
    int rc;

    if (sig_len > sizeof(decrypted)) return BAD_FUNC_ARG;

    hash_type = wolfcrypt_rsa_hash_wc_type(hash_bits);
    if (hash_type == WC_HASH_TYPE_NONE) return BAD_FUNC_ARG;

    rc = wc_HashGetDigestSize(hash_type);
    if (rc <= 0) return BAD_FUNC_ARG;
    hash_len = (word32)rc;

    mgf = wolfcrypt_rsa_hash_mgf(hash_bits);
    if (mgf < 0) return BAD_FUNC_ARG;

    /* Hash the message to obtain the digest for comparison. */
    rc = wc_Hash(hash_type, msg, msg_len, hash, hash_len);
    if (rc != 0) return rc;

    /* wc_RsaPSS_VerifyCheck: RSA-decrypt the signature, strip PSS padding,
     * and compare the embedded hash against `hash`.
     * NOTE: on success this returns the decrypted block size (positive), NOT 0.
     * Normalize to 0 = success, negative = error. */
    rc = wc_RsaPSS_VerifyCheck(sig, sig_len, decrypted, sizeof(decrypted),
                                hash, hash_len, hash_type, mgf, &ctx->key);
    if (rc < 0) return rc;
    return 0;
}

#endif /* WC_RSA_PSS */

#endif /* !NO_RSA */
