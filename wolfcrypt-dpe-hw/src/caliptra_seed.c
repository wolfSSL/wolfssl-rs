/*
 * wolfcrypt-dpe-hw/src/caliptra_seed.c
 *
 * Implements `caliptra_generate_random_block` for wolfSSL random generation.
 * Compiled only for riscv32imc-unknown-none-elf with the `caliptra-2x` feature.
 *
 * wolfSSL calls this function directly for random bytes because
 * `user_settings_cryptocb_only.h` defines:
 *   #define CUSTOM_RAND_GENERATE_BLOCK caliptra_generate_random_block
 *
 * This bypasses wolfSSL's software HASH-DRBG entirely.  The Caliptra hardware
 * implements an AES-256-CTR-DRBG (SP 800-90A) in silicon; FIPS 140-3 /
 * SP 800-90C requires using the hardware DRBG directly rather than stacking a
 * second software DRBG on top of it.
 *
 * This shim delegates to `caliptra_hw_generate_seed` (Rust, in hw_rng.rs)
 * which calls the Caliptra ITRNG via caliptra-drivers `Trng::generate()`.
 *
 * Firmware must call `wolfcrypt_dpe_hw::hw_rng::register_trng(trng)` before
 * any call to `wc_RNG_GenerateBlock()` so that `caliptra_hw_generate_seed`
 * has a live Trng instance.
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

/* Forward declaration of the Rust implementation in hw_rng.rs. */
extern int caliptra_hw_generate_seed(unsigned char *output, unsigned int sz);

/*
 * caliptra_generate_random_block — direct hardware DRBG output for wolfSSL.
 *
 * Called by wc_RNG_GenerateBlock() via CUSTOM_RAND_GENERATE_BLOCK.
 * No software DRBG state is involved; bytes come straight from the
 * Caliptra iTRNG / CSRNG hardware.
 *
 * @output: Destination buffer for random bytes.
 * @sz:     Number of bytes requested.
 *
 * Returns 0 on success, non-zero on error (ITRNG unavailable or failure).
 */
int caliptra_generate_random_block(unsigned char *output, unsigned int sz)
{
    return caliptra_hw_generate_seed(output, sz);
}
