/*
 * wolftpm_rs_shim.c — raw-bytes transact shim for Rust bindings.
 *
 * Exposes a single function, wolftpm_rs_transact(), that sends a raw
 * TPM2 command byte buffer and returns the raw response bytes.  All
 * platform dispatch (WOLFTPM_LINUX_DEV / WOLFTPM_SWTPM / TIS ioCb)
 * is handled transparently via the same INTERNAL_SEND_COMMAND macro
 * used by the rest of wolfTPM.
 *
 * This file must be compiled as part of wolftpm-sys, alongside the
 * wolfTPM static library, so that INTERNAL_SEND_COMMAND resolves to
 * the correct transport at link time.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <user_settings.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_wrap.h>
#include <assert.h>
#include <string.h>

/* Resolve INTERNAL_SEND_COMMAND the same way tpm2.c does.
 * Transport selection mirrors the #ifdef chain in wolfTPM's tpm2.c.
 * If wolfTPM adds a new named transport (e.g. WOLFTPM_WINAPI), a new
 * #elif branch must be added here to keep parity.  The final #else is
 * the TIS / ioCb path, which is wolfTPM's correct default for bare-metal
 * and embedded targets; it is NOT a silent fall-through for unknown
 * transports — it is the intended default when no named transport is set.
 */
#ifdef WOLFTPM_LINUX_DEV
#include <wolftpm/tpm2_linux.h>
#define RS_SEND_COMMAND TPM2_LINUX_SendCommand
#elif defined(WOLFTPM_LINUX_DEV_AUTODETECT)
#include <wolftpm/tpm2_linux.h>
#define RS_SEND_COMMAND TPM2_LINUX_AUTODETECT_SendCommand
#elif defined(WOLFTPM_SWTPM)
#include <wolftpm/tpm2_swtpm.h>
#define RS_SEND_COMMAND TPM2_SWTPM_SendCommand
#else
/* TIS / ioCb path: correct default for embedded and custom transports.
 * wolfTPM2_Init must have been called with an appropriate ioCb (or NULL
 * for raw TIS register access).  If neither applies, wolfTPM will return
 * an error from RS_SEND_COMMAND; no silent data loss occurs. */
#include <wolftpm/tpm2_tis.h>
#define RS_SEND_COMMAND TPM2_TIS_SendCommand
#endif

/* Compile-time guard: if TPM2_CTX / WOLFTPM2_DEV changes layout, ensure we
 * notice.  The shim accesses dev->ctx.cmdBuf directly (see INTERNAL FIELD
 * ACCESS comment on wolftpm_rs_transact below); any shrinkage indicates an
 * incompatible wolfTPM version.  TPM2_CTX is defined in wolftpm/tpm2.h and
 * WOLFTPM2_DEV wraps it in wolftpm/tpm2_wrap.h. */
_Static_assert(sizeof(TPM2_CTX) > sizeof(void*),
    "TPM2_CTX appears undersized — check wolfTPM version compatibility");
_Static_assert(sizeof(WOLFTPM2_DEV) >= sizeof(TPM2_CTX),
    "WOLFTPM2_DEV appears undersized — check wolfTPM version compatibility");

/*
 * wolftpm_rs_transact - send a raw TPM2 command and receive the response.
 *
 * Parameters:
 *   dev        - fully initialised WOLFTPM2_DEV (from wolfTPM2_Init).
 *   cmd        - TPM2 command bytes (caller owns, read-only).
 *   cmd_sz     - length of cmd in bytes.
 *   rsp        - output buffer for TPM2 response bytes.
 *   rsp_buf_sz - capacity of rsp in bytes.
 *   rsp_sz_out - on success, set to the number of response bytes written
 *                into rsp.  Unchanged on error.
 *
 * Returns 0 (TPM_RC_SUCCESS) on success, or a non-zero TPM_RC / wolfTPM
 * error code on failure.
 *
 * Thread safety: the caller must not share dev across threads without
 * external synchronisation.  wolfTPM2_Init is not thread-safe by itself.
 */
int wolftpm_rs_transact(
    WOLFTPM2_DEV* dev,
    const byte*   cmd,
    int           cmd_sz,
    byte*         rsp,
    int           rsp_buf_sz,
    int*          rsp_sz_out)
{
    TPM2_Packet packet;
    int         rc;
    int         resp_len;

    /* INTERNAL FIELD ACCESS: dev->ctx.cmdBuf is not part of wolfTPM's public API.
     * This field is used because wolfTPM does not expose a public raw-bytes
     * transact function.  Tested against wolfTPM commit fbbf6fe / version 4.0.0.
     * If wolfTPM restructures WOLFTPM2_CTX, this function will fail to compile
     * (missing field or size mismatch caught by the _Static_assert above), which
     * is the correct failure mode.
     * See: wolftpm-sys/build.rs for the wolfTPM version warning. */

    if (dev == NULL || cmd == NULL || rsp == NULL || rsp_sz_out == NULL)
        return BAD_FUNC_ARG;
    if (cmd_sz <= 0 || cmd_sz > (int)sizeof(dev->ctx.cmdBuf))
        return BAD_FUNC_ARG;
    if (rsp_buf_sz <= 0 || rsp_buf_sz > (int)sizeof(dev->ctx.cmdBuf))
        return BAD_FUNC_ARG;

    /* Copy command into the context's internal buffer */
    XMEMCPY(dev->ctx.cmdBuf, cmd, cmd_sz);

    /* Set up a TPM2_Packet pointing at that buffer */
    packet.buf  = dev->ctx.cmdBuf;
    packet.pos  = cmd_sz;          /* bytes to send */
    packet.size = (int)sizeof(dev->ctx.cmdBuf); /* receive capacity */

    /* Dispatch via the platform send function */
    rc = RS_SEND_COMMAND(&dev->ctx, &packet);
    if (rc != 0)
        return rc;

    /*
     * Parse the response size from the TPM2 header:
     *   bytes 0-1 : tag (big-endian u16)
     *   bytes 2-5 : totalSize (big-endian u32)
     *   bytes 6-9 : responseCode (big-endian u32)
     * After RS_SEND_COMMAND returns success the response occupies
     * cmdBuf[0..resp_len].  packet.pos is still the command size;
     * we derive resp_len from the header bytes directly.
     * cmdBuf is always at least TPM2_HEADER_SIZE (=10) bytes large.
     */
    /* Big-endian u32 at offset 2 */
    resp_len = (int)(
        ((unsigned int)(unsigned char)dev->ctx.cmdBuf[2] << 24) |
        ((unsigned int)(unsigned char)dev->ctx.cmdBuf[3] << 16) |
        ((unsigned int)(unsigned char)dev->ctx.cmdBuf[4] <<  8) |
        ((unsigned int)(unsigned char)dev->ctx.cmdBuf[5]      )
    );

    /* resp_len must be at least a header and fit within cmdBuf */
    if (resp_len < TPM2_HEADER_SIZE || resp_len > packet.size)
        return TPM_RC_FAILURE;
    if (resp_len > rsp_buf_sz)
        return TPM_RC_SIZE; /* caller's buffer too small */

    XMEMCPY(rsp, dev->ctx.cmdBuf, (size_t)resp_len);
    *rsp_sz_out = resp_len;
    return TPM_RC_SUCCESS;
}
