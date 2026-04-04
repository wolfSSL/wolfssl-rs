/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Master include file for bindgen. Every wolfSSL header that should
 * produce Rust bindings must be listed here.
 */

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve448.h"
#include "wolfssl/wolfcrypt/ed448.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/pwdbased.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/coding.h"
#include "wolfssl/wolfcrypt/signature.h"
#include "wolfssl/wolfcrypt/logging.h"
#include "wolfssl/wolfcrypt/dh.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/mlkem.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
