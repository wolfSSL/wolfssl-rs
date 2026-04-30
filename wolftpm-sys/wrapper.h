/* wolftpm-sys bindgen wrapper — includes wolfTPM client API headers */
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

/*
 * Raw-bytes transport shim — implemented in src/wolftpm_rs_shim.c.
 * Sends a TPM2 command byte buffer and returns the TPM2 response bytes.
 * Returns TPM_RC_SUCCESS (0) on success, non-zero on error.
 */
int wolftpm_rs_transact(
    WOLFTPM2_DEV* dev,
    const BYTE*   cmd,
    int           cmd_sz,
    BYTE*         rsp,
    int           rsp_buf_sz,
    int*          rsp_sz_out);
