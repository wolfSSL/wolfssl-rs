/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT */

/* user_settings.h
 *
 * wolfSSL configuration for wolfcrypt-rs Rust crate.
 * This file is included via -DWOLFSSL_USER_SETTINGS.
 *
 * FIPS 140-3 builds: build.rs passes -DHAVE_FIPS to the C compiler,
 * which activates the #include below pulling in user_settings_fips.h.
 * build.rs also parses user_settings_fips.h directly (flat #define scan)
 * so FIPS defines are visible to the Rust cfg system.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Threading: mutex protection for RNG and internal state.
 * The wolfcrypt-ring-compat API surface is expected to be thread-safe.
 * On Windows, wolfSSL auto-detects USE_WINDOWS_API and uses
 * native critical sections; on Unix we explicitly select pthreads. */
#ifndef _WIN32
#define WOLFSSL_PTHREADS
#endif

/* ================================================================
 * FIPS 140-3 configuration (activated by Cargo `fips` feature)
 * ================================================================ */
#ifdef HAVE_FIPS
#include "user_settings_fips.h"
#endif

/* OpenSSL compatibility */
#define OPENSSL_EXTRA
#define OPENSSL_ALL
#define WOLFSSL_OPENSSL_ALL
/* Have i2d_ECDSA_SIG allocate its output buffer (like OpenSSL) when *out is NULL */
#define WOLFSSL_I2D_ECDSA_SIG_ALLOC

/* CMAC support (requires AES_DIRECT + OPENSSL_EXTRA) */
#define WOLFSSL_CMAC

/* AES support */
#define WOLFSSL_AES_128
#define WOLFSSL_AES_192
#define WOLFSSL_AES_256
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define HAVE_AESCCM
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define HAVE_AES_KEYWRAP

/* ChaCha20-Poly1305 */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* KDF support */
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_HAVE_PRF
#define WC_KDF_NIST_SP_800_56C

/* Elliptic curve support */
#define HAVE_ECC
#define HAVE_COMP_KEY
#define HAVE_SUPPORTED_CURVES
#define HAVE_ECC_KOBLITZ
#define WOLFSSL_CUSTOM_CURVES
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define HAVE_ECC_CHECK_PUBKEY_ORDER
#define USE_ECC_B_PARAM
#define WOLFSSL_VALIDATE_ECC_KEYGEN
#define WOLFSSL_VALIDATE_ECC_IMPORT
/* NOTE: These validation defines protect import/keygen paths.
 * ECDH shared secret (wc_ecc_shared_secret_ex) does NOT call
 * wc_ecc_check_key on the peer point — wolfSSL limitation. */
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521

/* Ed25519 / X25519 */
#define HAVE_ED25519
#define HAVE_CURVE25519

/* Ed448 / X448 (requires SHA-3/SHAKE256) */
#define HAVE_ED448
#define HAVE_CURVE448
#define WOLFSSL_SHA3

/* SHA support */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* Key/cert generation */
#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLFSSL_SEP

/* RSA options */
#define WC_RSA_BLINDING
#define WC_RSA_NO_PADDING
#define WC_RSA_PSS
/* Allow wc_RsaPrivateDecrypt_ex to return 0 bytes for valid empty OAEP plaintext
 * instead of RSA_BUFFER_E. Required for Wycheproof OAEP zero-length test vectors. */
#define WOLFSSL_RSA_DECRYPT_TO_0_LEN

/* TLS extensions and SNI — required by OPENSSL_ALL for struct layout
 * in ssl.c even though we don't compile the TLS protocol files. */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI

/* DH: enable FFDHE named groups (RFC 7919) for DH_new_by_nid */
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096

/* DER loading */
#define WOLFSSL_DER_LOAD

/* Use SP math (single precision) - the modern default */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_4096
#define SP_INT_BITS 8192

/* Ensure we have a good random source */
#define HAVE_HASHDRBG

/* Needed for ASN/certificate parsing */
#define WOLFSSL_ASN_TEMPLATE

/* Enable base64 encode/decode */
#define WOLFSSL_BASE64_ENCODE

/* SHAKE needed for Ed448 / SHA-3 */
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* ML-DSA (Dilithium) post-quantum signatures */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM

/* ML-KEM (FIPS 203) post-quantum KEM support.
 * WOLFSSL_HAVE_MLKEM enables the overall ML-KEM module.
 * WOLFSSL_WC_MLKEM selects wolfCrypt's native implementation (not liboqs). */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM

#endif /* WOLFSSL_USER_SETTINGS_H */
