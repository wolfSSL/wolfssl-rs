/* Copyright wolfSSL, Inc.
 * SPDX-License-Identifier: MIT */

/* Simple link test: call a wolfCrypt function to verify the library linked. */
#include <wolfssl/wolfcrypt/error-crypt.h>

const char *testing_get_error_string(int error) {
    return wc_GetErrorString(error);
}
