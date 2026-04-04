/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT */

/* user_settings_cryptocb_pure.h
 *
 * wolfSSL absolute-minimum configuration: CryptoCb callback routing only.
 *
 * Intended for builds where ALL cryptographic operations are dispatched to
 * hardware via the wolfSSL CryptoCb mechanism AND no higher-level wolfSSL
 * APIs (EVP, HKDF, ASN, TLS extensions) are needed.  This is the minimal
 * configuration for a firmware image that uses wolfSSL purely as a routing
 * layer between callers and a hardware crypto backend.
 *
 * Compared to user_settings_cryptocb_only.h, this removes:
 *   - OPENSSL_EXTRA / HAVE_TLS_EXTENSIONS / HAVE_SNI  (no EVP/OpenSSL compat)
 *   - HAVE_HKDF / WC_KDF_NIST_SP_800_56C              (no key derivation)
 *   - WOLFSSL_ASN_TEMPLATE                             (no ASN.1 parser)
 *   - WOLFSSL_SHA224                                   (not dispatched)
 *
 * C source reduction vs cryptocb-only:
 *   Removed: asn.c, coding.c, cpuid.c, signature.c, wc_encrypt.c, ssl.c,
 *            evp.c (no OPENSSL_EXTRA), kdf.c (no HAVE_HKDF).
 *
 * Activate via the `cryptocb-pure` Cargo feature in wolfssl-src.
 */

#ifndef WOLFSSL_USER_SETTINGS_CRYPTOCB_PURE_H
#define WOLFSSL_USER_SETTINGS_CRYPTOCB_PURE_H

/* ================================================================
 * CryptoCb configuration — the whole point of this file
 * ================================================================ */

/* Enable the CryptoCb callback infrastructure. */
#define WOLF_CRYPTO_CB

/* Disable software ECC and RSA implementations.
 * These flags exclude the SP math code paths from ecc.c and rsa.c so that
 * sp_int.c / sp_c32.c / sp_c64.c / wolfmath.c are not referenced. */
#define WOLF_CRYPTO_CB_ONLY_ECC
#define WOLF_CRYPTO_CB_ONLY_RSA

/* ================================================================
 * Bare-metal platform settings
 * ================================================================ */

#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_MAIN_DRIVER

/* Custom memory allocation — firmware provides its own malloc/free. */
#define XMALLOC_USER

/* RNG entropy from the Caliptra hardware TRNG (iTRNG / CSRNG).
 *
 * The Caliptra hardware implements an AES-256-CTR-DRBG (SP 800-90A) in
 * silicon.  FIPS 140-3 / SP 800-90C requires using the hardware DRBG
 * directly rather than stacking a second software DRBG on top of it.
 *
 * CUSTOM_RAND_GENERATE_BLOCK bypasses wolfSSL's HASH-DRBG entirely:
 * wc_RNG_GenerateBlock() calls caliptra_generate_random_block() directly.
 * caliptra_generate_random_block() is implemented in caliptra_seed.c
 * (forwarded from hw_rng.rs via the Caliptra ITRNG driver). */
int caliptra_generate_random_block(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_BLOCK caliptra_generate_random_block

/* No libc headers — provide everything via builtins and inline macros. */
#define NO_STDLIB_H
#define STRING_USER
#define XMEMCPY(d,s,n)  __builtin_memcpy((d),(s),(n))
#define XMEMSET(d,v,n)  __builtin_memset((d),(v),(n))
#define XMEMCMP(a,b,n)  __builtin_memcmp((a),(b),(n))
#define XMEMMOVE(d,s,n) __builtin_memmove((d),(s),(n))
#define XSTRLEN(s)       __builtin_strlen(s)
#define XSTRNCPY(d,s,n) __builtin_strncpy((d),(s),(n))
#define XSTRNCMP(a,b,n) __builtin_strncmp((a),(b),(n))
#define XSTRCMP(a,b)    __builtin_strcmp((a),(b))
#include <stddef.h>
#include <stdint.h>
typedef long time_t;

/* compat_shim.c calls memcpy/memset/memcmp directly (not via XMEMCPY macros).
 * Map them to compiler builtins so there is no dependency on libc string.h. */
#define memcpy  __builtin_memcpy
#define memset  __builtin_memset
#define memcmp  __builtin_memcmp
#define memmove __builtin_memmove

#define XSNPRINTF(buf,sz,...) 0
#define XSTRTOK(s,d,c) ((char*)0)
#define XATOI(s) 0
#define XSTRSTR(h,n)         wolfssl_strstr((h),(n))
#define XSTRNCASECMP(a,b,n)  wolfssl_strncasecmp((a),(b),(n))

const char *wolfssl_strstr(const char *h, const char *n);
int wolfssl_strncasecmp(const char *a, const char *b, size_t n);

#define WOLFSSL_IP4 2
#define WOLFSSL_IP6 10
#define XINET_PTON(af,src,dst) 0

#define CTYPE_USER
#define XTOUPPER(c)  (((c) >= 'a' && (c) <= 'z') ? ((c) - 'a' + 'A') : (c))
#define XISALPHA(c)  (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#define XISDIGIT(c)  ((c) >= '0' && (c) <= '9')
#define XISALNUM(c)  (XISALPHA(c) || XISDIGIT(c))
#define XISASCII(c)  ((c) >= 0 && (c) <= 127)
#define XISSPACE(c)  ((c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r')
#define XTOLOWER(c)  (((c) >= 'A' && (c) <= 'Z') ? ((c) - 'A' + 'a') : (c))
#define XSTRNCAT(d,s,n)   wolfssl_strncat((d),(s),(n))
#define XSTRNSTR(h,n,l)   wolfssl_strnstr((h),(n),(l))
#define XSTRCASECMP(a,b)  wolfssl_strcasecmp((a),(b))
#define XSTRCAT(d,s)      wolfssl_strncat((d),(s),0x7FFFFFFF)
#define XSTRCHR(s,c)      wolfssl_strchr((s),(c))

char *wolfssl_strncat(char *d, const char *s, size_t n);
const char *wolfssl_strnstr(const char *h, const char *n, size_t len);
int wolfssl_strcasecmp(const char *a, const char *b);
char *wolfssl_strchr(const char *s, int c);

#define WOLFSSL_NO_ASSERT_H
#define NO_STDIO_FILESYSTEM
#define WOLFSSL_NO_LOGGING
/* logging.h has an unconditional #else { #include <stdio.h> } fallback for
 * printf.  WOLFSSL_USER_LOG short-circuits it so no libc headers are pulled
 * in on bare-metal. */
#define WOLFSSL_USER_LOG
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_ASN_TIME
#define USER_TIME
#ifndef XTIME
#define XTIME(t) (0)
#endif
#ifndef XGMTIME
#define XGMTIME(c, t) (NULL)
#endif
#define NO_WOLFSSL_STUB

/* ASN.1: use the older sequential parser instead of the template engine.
 * wolfSSL auto-enables WOLFSSL_ASN_TEMPLATE in settings.h unless
 * WOLFSSL_ASN_ORIGINAL is explicitly defined. */
#define WOLFSSL_ASN_ORIGINAL

/* ================================================================
 * Algorithm type definitions
 *
 * These defines preserve the struct layouts used inside wc_CryptoInfo,
 * which is the struct passed to the CryptoCb callback.  Only the types
 * that wolfcrypt-dpe-hw actually dispatches are included.  SP math
 * (WOLFSSL_SP_MATH_ALL etc.) is intentionally absent.
 * ================================================================ */

/* ECC type definitions (ecc_key struct, wc_EccInfo in wc_CryptoInfo). */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT

/* AES-GCM type definitions (wc_Aes struct, wc_AesInfo/aesgcm_enc/aesgcm_dec
 * sub-structs in wc_CryptoInfo cipher union, wc_CryptoCb_AesAuthEnc/Dec).
 * Required by hw_aes.rs cipher callback dispatch. */
#define HAVE_AESGCM

/* SHA-384/512 type definitions (wc_Sha384/wc_Sha512 structs, wc_HashInfo).
 * SHA-224 is intentionally absent — it is not dispatched by wolfcrypt-dpe-hw. */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* ================================================================
 * Disabled algorithms
 * ================================================================ */

#define NO_RSA
#define NO_DH
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_SHA      /* SHA-1 unused in DPE; all hashing is SHA-256/384 */
#define NO_RC4
#define NO_PSK
#define NO_PWDBASED
#define NO_DSA
#define NO_OLD_TLS
#define NO_SESSION_CACHE
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_MEMORY
#define NO_SIG_WRAPPER
#define NO_CODING   /* base64 encode/decode unused in DPE */
/* BIO uses vsnprintf from stdio.h which is unavailable on bare-metal. */
#define NO_BIO

#endif /* WOLFSSL_USER_SETTINGS_CRYPTOCB_PURE_H */
