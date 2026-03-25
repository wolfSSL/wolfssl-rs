/* user_settings_riscv.h
 *
 * wolfSSL configuration for Caliptra RISC-V bare-metal firmware.
 * Minimal footprint: only the crypto primitives needed by wolfcrypt-dpe.
 *
 * Selected via -DWOLFSSL_USER_SETTINGS_RISCV (see wolfssl-src build.rs).
 */

#ifndef WOLFSSL_USER_SETTINGS_RISCV_H
#define WOLFSSL_USER_SETTINGS_RISCV_H

/* ================================================================
 * Bare-metal platform settings
 * ================================================================ */

/* Single-threaded — no pthreads, no mutexes */
#define SINGLE_THREADED

/* No OS features */
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_MAIN_DRIVER

/* OpenSSL compat — required by wolfcrypt-rs Rust bindings (EVP API).
 * We include only OPENSSL_EXTRA (not OPENSSL_ALL) to minimize code. */
#define OPENSSL_EXTRA

/* TLS extensions needed by OPENSSL_EXTRA struct layout */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI

/* Disable TLS protocol features we don't need */
#define NO_SESSION_CACHE

/* Custom memory allocation hooks — we provide our own malloc/free */
#define XMALLOC_USER

/* Custom RNG seed — firmware provides entropy from hardware TRNG.
 * caliptra_generate_seed() is implemented in the firmware. */
#define HAVE_HASHDRBG
int caliptra_generate_seed(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED caliptra_generate_seed

/* No libc headers */
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
/* Provide NULL, size_t, and basic types without stdlib.h */
#include <stddef.h>
#include <stdint.h>
typedef long time_t;

/* Stub remaining libc functions needed by OPENSSL_EXTRA code */
#define XSNPRINTF(buf,sz,...) 0
#define XSTRTOK(s,d,c) ((char*)0)
#define XATOI(s) 0
#define XSTRSTR(h,n) wolfssl_strstr((h),(n))
#define XSTRNCASECMP(a,b,n) wolfssl_strncasecmp((a),(b),(n))

const char *wolfssl_strstr(const char *h, const char *n);
int wolfssl_strncasecmp(const char *a, const char *b, size_t n);

/* Stub X.509 network helpers */
#define WOLFSSL_IP4 2
#define WOLFSSL_IP6 10
#define XINET_PTON(af,src,dst) 0

/* No ctype.h — provide inline ctype macros */
#define CTYPE_USER
#define XTOUPPER(c) (((c) >= 'a' && (c) <= 'z') ? ((c) - 'a' + 'A') : (c))
#define XISALPHA(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#define XISDIGIT(c) ((c) >= '0' && (c) <= '9')
#define XISALNUM(c) (XISALPHA(c) || XISDIGIT(c))
#define XISASCII(c) ((c) >= 0 && (c) <= 127)
#define XISSPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r')
#define XTOLOWER(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) - 'A' + 'a') : (c))
#define XSTRNCAT(d,s,n) wolfssl_strncat((d),(s),(n))
#define XSTRNSTR(h,n,l) wolfssl_strnstr((h),(n),(l))
#define XSTRCASECMP(a,b) wolfssl_strcasecmp((a),(b))
#define XSTRCAT(d,s) wolfssl_strncat((d),(s),0x7FFFFFFF)
#define XSTRCHR(s,c) wolfssl_strchr((s),(c))

/* Forward declare bare-metal string helpers (implemented in user_settings_riscv_helpers.c) */
char *wolfssl_strncat(char *d, const char *s, size_t n);
const char *wolfssl_strnstr(const char *h, const char *n, size_t len);
int wolfssl_strcasecmp(const char *a, const char *b);
char *wolfssl_strchr(const char *s, int c);

/* No assert.h, no stdio.h */
#define WOLFSSL_NO_ASSERT_H
#define NO_STDIO_FILESYSTEM
#define WOLFSSL_NO_LOGGING     /* suppress all debug logging */

/* No signals, no stdout, no time */
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_ASN_TIME
#define USER_TIME              /* prevent time.h includes */
#ifndef XTIME
#define XTIME(t) (0)           /* stub time() */
#endif
#ifndef XGMTIME
#define XGMTIME(c, t) (NULL)   /* stub gmtime() */
#endif
#define NO_WOLFSSL_STUB

/* ================================================================
 * Crypto algorithms — only what wolfcrypt-dpe needs
 * ================================================================ */

/* ECC P-384 (primary) and P-256 (secondary) */
#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define HAVE_ECC_CHECK_PUBKEY_ORDER
#define WOLFSSL_VALIDATE_ECC_KEYGEN
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_SP_384
#define USE_ECC_B_PARAM

/* SHA-384 / SHA-256 */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA224

/* HMAC and HKDF */
#define HAVE_HKDF

/* SP math — no dynamic allocation for big integers */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_SMALL   /* optimize for size over speed */
#define SP_INT_BITS 768    /* enough for P-384 */

/* ASN template parsing (needed for ECC key import/export) */
#define WOLFSSL_ASN_TEMPLATE

/* ================================================================
 * Disable everything we don't need
 * ================================================================ */

#define NO_RSA
#define NO_DH
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_PSK
#define NO_PWDBASED
#define NO_DSA
#define NO_OLD_TLS
#define NO_SESSION_CACHE
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_MEMORY     /* we handle allocation ourselves */
#define NO_SIG_WRAPPER

/* Key generation support (needed for ECC key derivation) */
#define WOLFSSL_KEY_GEN

#endif /* WOLFSSL_USER_SETTINGS_RISCV_H */
