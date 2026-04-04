/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT */

/* user_settings_cryptocb_only.h
 *
 * wolfSSL minimal configuration: CryptoCb callback infrastructure only.
 *
 * Intended for use when ALL cryptographic operations are dispatched to
 * hardware (e.g. Caliptra accelerators) via the wolfSSL CryptoCb mechanism.
 * Software implementations of SHA, AES, ECC, and all big-integer math are
 * excluded.  Operations without a registered CryptoCb handler fail with
 * CRYPTOCB_UNAVAILABLE rather than falling back to software.
 *
 * This produces the smallest wolfSSL library that still supports the full
 * CryptoCb protocol — the type definitions, callback dispatch glue, DRBG
 * structure, and HKDF are kept; SP math (sp_int.c, sp_c32.c, sp_c64.c),
 * wolfmath.c, and all algorithm implementations are excluded.
 *
 * Platform stubs are sized for RISC-V bare-metal (no libc, no filesystem).
 * Activate via the `cryptocb-only` Cargo feature in wolfssl-src.
 */

#ifndef WOLFSSL_USER_SETTINGS_CRYPTOCB_ONLY_H
#define WOLFSSL_USER_SETTINGS_CRYPTOCB_ONLY_H

/* ================================================================
 * CryptoCb configuration — the whole point of this file
 * ================================================================ */

/* Enable the CryptoCb callback infrastructure. */
#define WOLF_CRYPTO_CB

/* Disable software ECC and RSA implementations.
 * This wolfSSL version provides per-algorithm CryptoCb-only guards rather
 * than a single WOLF_CRYPTO_CB_ONLY.  With these two defines, the software
 * math paths inside ecc.c and rsa.c are excluded from compilation, which
 * means those files no longer reference sp_int / wolfmath symbols even when
 * WOLFSSL_SP_MATH_ALL is absent.  SHA, AES, and HMAC lack _ONLY variants in
 * this version; their software implementations are small and are compiled in
 * but will never execute when CryptoCb handles everything. */
#define WOLF_CRYPTO_CB_ONLY_ECC
#define WOLF_CRYPTO_CB_ONLY_RSA

/* ================================================================
 * Bare-metal platform settings
 * (same as user_settings_riscv.h — required for riscv32 targets)
 * ================================================================ */

#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_MAIN_DRIVER

/* Session cache not needed on bare-metal. */
#define NO_SESSION_CACHE

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
 * printf.  WOLFSSL_USER_LOG short-circuits it ("user provides their own
 * logging headers") so no libc headers are pulled in on bare-metal. */
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

/* ================================================================
 * Algorithm type definitions
 *
 * These defines preserve the struct layouts used inside wc_CryptoInfo,
 * which is the struct passed to the CryptoCb callback.  The software
 * implementations of these algorithms are excluded by WOLF_CRYPTO_CB_ONLY;
 * only the type definitions and CryptoCb dispatch glue are compiled in.
 *
 * SP math (WOLFSSL_SP_MATH_ALL, WOLFSSL_SP_384, SP_INT_BITS, etc.) is
 * intentionally absent — it is not needed when all operations go through
 * CryptoCb, and omitting it excludes sp_int.c / sp_c32.c / sp_c64.c /
 * wolfmath.c from the build, which are the largest contributors to code size.
 * ================================================================ */

/* ECC type definitions (ecc_key struct, wc_EccInfo in wc_CryptoInfo). */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT

/* SHA type definitions (wc_Sha256/384/512 structs, wc_HashInfo). */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* HKDF — pure HMAC-based key derivation; HMAC itself goes through CryptoCb. */
#define HAVE_HKDF
/* One-step KDA KDF (NIST SP 800-56Cr2 §4.1) — used by compat_shim.c's
 * SSKDF_digest wrapper and potentially by wolfcrypt-dpe for DICE. */
#define WC_KDF_NIST_SP_800_56C

/* ASN.1: use the older sequential parser instead of the template engine.
 * wolfSSL auto-enables WOLFSSL_ASN_TEMPLATE in settings.h unless
 * WOLFSSL_ASN_ORIGINAL is explicitly defined.  WOLFSSL_ASN_ORIGINAL selects
 * the sequential parser (GetSequence/GetInt) which is sufficient for the
 * ECDSA DER sig encode/decode we actually need and excludes the larger
 * GetASN_Items/SetASN_Items/SizeASN_Items template infrastructure. */
#define WOLFSSL_ASN_ORIGINAL

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
/* BIO (ssl.c amalgamation includes bio.c when OPENSSL_EXTRA && !NO_BIO).
 * bio.c uses vsnprintf from stdio.h which is unavailable on bare-metal. */
#define NO_BIO

#endif /* WOLFSSL_USER_SETTINGS_CRYPTOCB_ONLY_H */
