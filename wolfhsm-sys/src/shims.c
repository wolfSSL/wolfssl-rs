/* wolfhsm_shims.c — C shims for wolfhsm-sys.
 *
 * These functions stack-allocate wolfcrypt key structs (which are opaque /
 * zero-sized from Rust's perspective), set the HSM key-ID, perform the
 * operation via the wolfHSM client API, free the struct, and return.
 *
 * All key types use shims because wolfhsm-sys bindgen covers only wh_/WH_-prefixed
 * types; wolfcrypt structs (ecc_key, ed25519_key, RsaKey, etc.) are zero-sized
 * opaque types from Rust's perspective, so they must be stack-allocated here.
 */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include <stdint.h>
#include <stddef.h>

/* ── ECC P-256 shims ─────────────────────────────────────────────────────── */

int wolfhsm_ecc_sign(whClientContext* ctx, uint16_t keyId,
                     const uint8_t* hash, uint16_t hash_len,
                     uint8_t* sig, uint16_t* sig_len)
{
    ecc_key key;
    int rc;
    rc = wc_ecc_init(&key);
    if (rc != 0) return rc;
    wh_Client_EccSetKeyId(&key, keyId);
    rc = wh_Client_EccSign(ctx, &key, hash, hash_len, sig, sig_len);
    wc_ecc_free(&key);
    return rc;
}

int wolfhsm_ecc_verify(whClientContext* ctx, uint16_t keyId,
                       const uint8_t* hash, uint16_t hash_len,
                       const uint8_t* sig, uint16_t sig_len, int* result)
{
    ecc_key key;
    int rc;
    rc = wc_ecc_init(&key);
    if (rc != 0) return rc;
    wh_Client_EccSetKeyId(&key, keyId);
    rc = wh_Client_EccVerify(ctx, &key,
                             sig, sig_len,
                             hash, hash_len, result);
    wc_ecc_free(&key);
    return rc;
}

int wolfhsm_ecc_export_public_der(whClientContext* ctx, uint16_t keyId,
                                  uint8_t* out, uint32_t* out_len)
{
    /* Export the key material, then encode as DER SubjectPublicKeyInfo. */
    ecc_key key;
    int rc;
    rc = wc_ecc_init(&key);
    if (rc != 0) return rc;
    rc = wh_Client_EccExportKey(ctx, keyId, &key, 0, NULL);
    if (rc == 0) {
        word32 derLen = (word32)*out_len;
        rc = wc_EccPublicKeyToDer(&key, out, derLen, 1 /* with AlgId */);
        if (rc > 0) { *out_len = (uint32_t)rc; rc = 0; }
    }
    wc_ecc_free(&key);
    return rc;
}

int wolfhsm_ecc_shared_secret(whClientContext* ctx, uint16_t priv_key_id,
                              const uint8_t* peer_der, uint32_t peer_der_len,
                              uint8_t* out, uint32_t* out_len)
{
    ecc_key priv_key;
    ecc_key pub_key;
    int rc;
    rc = wc_ecc_init(&priv_key);
    if (rc != 0) return rc;
    rc = wc_ecc_init(&pub_key);
    if (rc != 0) { wc_ecc_free(&priv_key); return rc; }
    wh_Client_EccSetKeyId(&priv_key, priv_key_id);
    /* Import peer public key from DER SubjectPublicKeyInfo. */
    word32 idx = 0;
    rc = wc_EccPublicKeyDecode(peer_der, &idx, &pub_key, peer_der_len);
    if (rc == 0) {
        if (*out_len > 0xFFFFu) { rc = WH_ERROR_BADARGS; }
        else {
            uint16_t out_sz = (uint16_t)*out_len;
            rc = wh_Client_EccSharedSecret(ctx, &priv_key, &pub_key, out, &out_sz);
            if (rc == 0) *out_len = out_sz;
        }
    }
    wc_ecc_free(&pub_key);
    wc_ecc_free(&priv_key);
    return rc;
}

int wolfhsm_ecc_make_key(whClientContext* ctx, int curve_id,
                         uint16_t* out_key_id)
{
    /* size=32 for P-256; curve_id should be ECC_SECP256R1 */
    whKeyId key_id = WH_KEYID_ERASED;
    whNvmFlags flags = 0;
    int rc = wh_Client_EccMakeCacheKey(ctx, 32, curve_id,
                                       &key_id, flags, 0, NULL);
    if (rc == 0) *out_key_id = (uint16_t)key_id;
    return rc;
}

/* ── Curve25519 shims ────────────────────────────────────────────────────── */

int wolfhsm_curve25519_make_key(whClientContext* ctx, uint16_t* out_key_id)
{
    whKeyId key_id = WH_KEYID_ERASED;
    whNvmFlags flags = 0;
    int rc = wh_Client_Curve25519MakeCacheKey(ctx, CURVE25519_KEYSIZE,
                                              &key_id, flags, NULL, 0);
    if (rc == 0) *out_key_id = (uint16_t)key_id;
    return rc;
}

int wolfhsm_curve25519_shared_secret(whClientContext* ctx,
                                     uint16_t priv_key_id,
                                     const uint8_t* peer_pub, uint32_t peer_len,
                                     uint8_t* out, uint32_t* out_len)
{
    curve25519_key priv;
    curve25519_key pub;
    int rc;
    rc = wc_curve25519_init(&priv);
    if (rc != 0) return rc;
    rc = wc_curve25519_init(&pub);
    if (rc != 0) { wc_curve25519_free(&priv); return rc; }
    wh_Client_Curve25519SetKeyId(&priv, priv_key_id);
    /* Import peer public key (32-byte little-endian). */
    rc = wc_curve25519_import_public_ex(peer_pub, peer_len, &pub,
                                        EC25519_LITTLE_ENDIAN);
    if (rc == 0) {
        if (*out_len > 0xFFFFu) { rc = WH_ERROR_BADARGS; }
        else {
            uint16_t out_sz = (uint16_t)*out_len;
            rc = wh_Client_Curve25519SharedSecret(ctx, &priv, &pub,
                                                  EC25519_LITTLE_ENDIAN,
                                                  out, &out_sz);
            if (rc == 0) *out_len = out_sz;
        }
    }
    wc_curve25519_free(&pub);
    wc_curve25519_free(&priv);
    return rc;
}

/* ── RSA shims ───────────────────────────────────────────────────────────── */

int wolfhsm_rsa_sign(whClientContext* ctx, uint16_t keyId, int rsa_type,
                     const uint8_t* in, uint32_t in_len,
                     uint8_t* out, uint32_t* out_len)
{
    RsaKey key;
    int rc;
    rc = wc_InitRsaKey(&key, NULL);
    if (rc != 0) return rc;
    wh_Client_RsaSetKeyId(&key, keyId);
    if (in_len > 0xFFFFu || *out_len > 0xFFFFu) {
        wc_FreeRsaKey(&key);
        return WH_ERROR_BADARGS;
    }
    uint16_t out_sz = (uint16_t)*out_len;
    rc = wh_Client_RsaFunction(ctx, &key, rsa_type,
                               in, (uint16_t)in_len, out, &out_sz);
    if (rc == 0) *out_len = out_sz;
    wc_FreeRsaKey(&key);
    return rc;
}

int wolfhsm_rsa_get_size(whClientContext* ctx, uint16_t keyId, int* out_size)
{
    RsaKey key;
    int rc;
    rc = wc_InitRsaKey(&key, NULL);
    if (rc != 0) return rc;
    wh_Client_RsaSetKeyId(&key, keyId);
    rc = wh_Client_RsaGetSize(ctx, &key, out_size);
    wc_FreeRsaKey(&key);
    return rc;
}

int wolfhsm_rsa_make_key(whClientContext* ctx, int bits, long e,
                         uint16_t* out_key_id)
{
    whKeyId key_id = WH_KEYID_ERASED;
    whNvmFlags flags = 0;
    int rc = wh_Client_RsaMakeCacheKey(ctx, (uint32_t)bits, (uint32_t)e,
                                       &key_id, flags, 0, NULL);
    if (rc == 0) *out_key_id = (uint16_t)key_id;
    return rc;
}

int wolfhsm_rsa_export_public_der(whClientContext* ctx, uint16_t keyId,
                                  uint8_t* out, uint32_t* out_len)
{
    RsaKey key;
    int rc;
    rc = wc_InitRsaKey(&key, NULL);
    if (rc != 0) return rc;
    rc = wh_Client_RsaExportKey(ctx, keyId, &key, 0, NULL);
    if (rc == 0) {
        int der_len = wc_RsaKeyToPublicDer(&key, out, (word32)*out_len);
        if (der_len > 0) { *out_len = (uint32_t)der_len; rc = 0; }
        else rc = der_len;
    }
    wc_FreeRsaKey(&key);
    return rc;
}

/* ── ML-DSA shims ────────────────────────────────────────────────────────── */

int wolfhsm_mldsa_sign(whClientContext* ctx, uint16_t keyId, int level,
                       const uint8_t* msg, uint32_t msg_len,
                       uint8_t* sig, uint32_t* sig_len)
{
    MlDsaKey key;
    int rc;
    rc = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (rc != 0) return rc;
    rc = wc_MlDsaKey_SetParams(&key, level);
    if (rc == 0) {
        wh_Client_MlDsaSetKeyId(&key, keyId);
        rc = wh_Client_MlDsaSign(ctx, msg, msg_len, sig, sig_len, &key,
                                  NULL, 0, 0);
    }
    wc_MlDsaKey_Free(&key);
    return rc;
}

int wolfhsm_mldsa_verify(whClientContext* ctx, uint16_t keyId, int level,
                         const uint8_t* sig, uint32_t sig_len,
                         const uint8_t* msg, uint32_t msg_len, int* result)
{
    MlDsaKey key;
    int rc;
    rc = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (rc != 0) return rc;
    rc = wc_MlDsaKey_SetParams(&key, level);
    if (rc == 0) {
        wh_Client_MlDsaSetKeyId(&key, keyId);
        rc = wh_Client_MlDsaVerify(ctx, sig, sig_len, msg, msg_len,
                                    result, &key, NULL, 0, 0);
    }
    wc_MlDsaKey_Free(&key);
    return rc;
}

int wolfhsm_mldsa_make_key(whClientContext* ctx, int level,
                           uint16_t* out_key_id)
{
    /* size=0 lets wolfHSM choose the correct size for the level */
    whKeyId key_id = WH_KEYID_ERASED;
    whNvmFlags flags = 0;
    int rc = wh_Client_MlDsaMakeCacheKey(ctx, 0, level,
                                         &key_id, flags, 0, NULL);
    if (rc == 0) *out_key_id = (uint16_t)key_id;
    return rc;
}

/* ── AES-GCM shims ───────────────────────────────────────────────────────── */

int wolfhsm_aes_gcm_encrypt(whClientContext* ctx, uint16_t keyId,
                             const uint8_t* iv, uint32_t iv_len,
                             const uint8_t* aad, uint32_t aad_len,
                             const uint8_t* in, uint32_t in_len,
                             uint8_t* out, uint8_t* tag, uint32_t tag_len)
{
    Aes aes;
    int rc;
    /* AES-GCM without capturing the auth tag silently loses authentication. */
    if (tag == NULL) return WH_ERROR_BADARGS;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) return rc;
    wh_Client_AesSetKeyId(&aes, keyId);
    rc = wh_Client_AesGcm(ctx, &aes, 1 /* enc */,
                           in, in_len,
                           iv, iv_len,
                           aad, aad_len,
                           NULL, tag, tag_len,
                           out);
    wc_AesFree(&aes);
    return rc;
}

int wolfhsm_aes_gcm_decrypt(whClientContext* ctx, uint16_t keyId,
                             const uint8_t* iv, uint32_t iv_len,
                             const uint8_t* aad, uint32_t aad_len,
                             const uint8_t* in, uint32_t in_len,
                             uint8_t* out,
                             const uint8_t* tag, uint32_t tag_len)
{
    Aes aes;
    int rc;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) return rc;
    wh_Client_AesSetKeyId(&aes, keyId);
    rc = wh_Client_AesGcm(ctx, &aes, 0 /* dec */,
                           in, in_len,
                           iv, iv_len,
                           aad, aad_len,
                           tag, NULL, tag_len,
                           out);
    wc_AesFree(&aes);
    return rc;
}

/* ── SHA-256 one-shot shim ───────────────────────────────────────────────── */

int wolfhsm_sha256(whClientContext* ctx,
                   const uint8_t* in, uint32_t in_len, uint8_t* out)
{
    wc_Sha256 sha;
    int rc;
    rc = wc_InitSha256(&sha);
    if (rc != 0) return rc;
    rc = wh_Client_Sha256(ctx, &sha, in, in_len, out);
    wc_Sha256Free(&sha);
    return rc;
}

/* ── Ed25519 shims ───────────────────────────────────────────────────────── */

int wolfhsm_ed25519_make_key(whClientContext* ctx, uint16_t* out_key_id)
{
    whKeyId key_id = WH_KEYID_ERASED;
    whNvmFlags flags = 0;
    int rc = wh_Client_Ed25519MakeCacheKey(ctx, &key_id, flags, 0, NULL);
    if (rc == 0) *out_key_id = (uint16_t)key_id;
    return rc;
}

int wolfhsm_ed25519_sign(whClientContext* ctx, uint16_t key_id,
                          const uint8_t* msg, uint32_t msg_len,
                          uint8_t* sig, uint32_t* sig_len)
{
    ed25519_key key;
    int rc;
    rc = wc_ed25519_init(&key);
    if (rc != 0) return rc;
    wh_Client_Ed25519SetKeyId(&key, key_id);
    rc = wh_Client_Ed25519Sign(ctx, &key, msg, msg_len,
                                0, NULL, 0,
                                sig, sig_len);
    wc_ed25519_free(&key);
    return rc;
}

int wolfhsm_ed25519_verify(whClientContext* ctx, uint16_t key_id,
                            const uint8_t* sig, uint32_t sig_len,
                            const uint8_t* msg, uint32_t msg_len, int* result)
{
    ed25519_key key;
    int rc;
    rc = wc_ed25519_init(&key);
    if (rc != 0) return rc;
    wh_Client_Ed25519SetKeyId(&key, key_id);
    rc = wh_Client_Ed25519Verify(ctx, &key,
                                  sig, sig_len,
                                  msg, msg_len,
                                  0, NULL, 0, result);
    wc_ed25519_free(&key);
    return rc;
}

/* Export the 32-byte Ed25519 public key. */
int wolfhsm_ed25519_export_public(whClientContext* ctx, uint16_t key_id, uint8_t* out)
{
    ed25519_key key;
    int rc;
    word32 outLen = ED25519_PUB_KEY_SIZE;
    rc = wc_ed25519_init(&key);
    if (rc != 0) return rc;
    rc = wh_Client_Ed25519ExportKey(ctx, key_id, &key, 0, NULL);
    if (rc == 0)
        rc = wc_ed25519_export_public(&key, out, &outLen);
    if (rc == 0 && outLen != ED25519_PUB_KEY_SIZE)
        rc = WH_ERROR_BADARGS;
    wc_ed25519_free(&key);
    return rc;
}

/* Export the 32-byte Curve25519 public key (little-endian). */
int wolfhsm_curve25519_export_public(whClientContext* ctx, uint16_t key_id, uint8_t* out)
{
    curve25519_key key;
    int rc;
    word32 outLen = CURVE25519_KEYSIZE;
    rc = wc_curve25519_init(&key);
    if (rc != 0) return rc;
    rc = wh_Client_Curve25519ExportKey(ctx, key_id, &key, 0, NULL);
    if (rc == 0)
        rc = wc_curve25519_export_public_ex(&key, out, &outLen, EC25519_LITTLE_ENDIAN);
    if (rc == 0 && outLen != CURVE25519_KEYSIZE)
        rc = WH_ERROR_BADARGS;
    wc_curve25519_free(&key);
    return rc;
}

/* ── CMAC shim ───────────────────────────────────────────────────────────── */

int wolfhsm_cmac(whClientContext* ctx, uint16_t keyId,
                 const uint8_t* in, uint32_t in_len,
                 uint8_t* out, uint32_t* out_len)
{
    Cmac cmac;
    int rc;
    /* Init with NULL key/0 length so the struct is properly zeroed; the
     * actual key is referenced by keyId in the HSM cache. */
    rc = wc_InitCmac(&cmac, NULL, 0, WC_CMAC_AES, NULL);
    if (rc != 0) return rc;
    wh_Client_CmacSetKeyId(&cmac, keyId);
    rc = wh_Client_Cmac(ctx, &cmac, WC_CMAC_AES,
                        NULL, 0,   /* key/keyLen: 0 because key is cached by ID */
                        in, in_len,
                        out, out_len);
    /* Zero and release internal AES key schedule from the stack. */
    wc_CmacFree(&cmac);
    return rc;
}
