use std::ffi::CString;
use std::pin::Pin;

use wolfhsm_sys::{
    posixTransportShm_Cleanup, posixTransportShm_ClientInit, posixTransportShm_RecvResponse,
    posixTransportShm_SendRequest, posixTransportShmClientContext, posixTransportShmConfig,
    posixTransportTcp_CleanupConnect, posixTransportTcp_InitConnect, posixTransportTcp_RecvResponse,
    posixTransportTcp_SendRequest, posixTransportTcpClientContext, posixTransportTcpConfig,
    posixTransportUds_CleanupConnect, posixTransportUds_InitConnect, posixTransportUds_RecvResponse,
    posixTransportUds_SendRequest, posixTransportUdsClientContext, posixTransportUdsConfig,
    wh_Client_Cleanup, wh_Client_CommInfo, wh_Client_Echo, wh_Client_Init, whClientConfig,
    whClientContext, whCommClientConfig, whTransportClientCb,
};

use crate::error::WolfHsmError;
use crate::transport::Transport;

// ── Per-transport heap allocation ─────────────────────────────────────────────
//
// Each variant bundles the C context struct, config struct, vtable, and any
// CString needed for string pointers — all in one allocation so their addresses
// are stable for the lifetime of the Client.

struct TcpInner {
    transport_ctx: posixTransportTcpClientContext,
    transport_cfg: posixTransportTcpConfig,
    transport_cb: whTransportClientCb,
    /// Stable allocation for `posixTransportTcpConfig::server_ip_string`.
    _ip: CString,
}

struct UdsInner {
    transport_ctx: posixTransportUdsClientContext,
    transport_cfg: posixTransportUdsConfig,
    transport_cb: whTransportClientCb,
    /// Stable allocation for `posixTransportUdsConfig::server_path`.
    _path: CString,
}

struct ShmInner {
    transport_ctx: posixTransportShmClientContext,
    transport_cfg: posixTransportShmConfig,
    transport_cb: whTransportClientCb,
    /// Stable allocation for `posixTransportShmConfig::name`.
    _name: CString,
}

enum TransportInner {
    Tcp(Box<TcpInner>),
    Uds(Box<UdsInner>),
    Shm(Box<ShmInner>),
}

impl TransportInner {
    /// Return raw pointers into the transport structs suitable for filling
    /// `whCommClientConfig`.  The returned pointers are valid for the lifetime
    /// of `self`.
    fn comm_pointers(
        &mut self,
    ) -> (
        *const whTransportClientCb,
        *mut core::ffi::c_void,
        *const core::ffi::c_void,
    ) {
        match self {
            TransportInner::Tcp(inner) => (
                &inner.transport_cb as *const _,
                &mut inner.transport_ctx as *mut _ as *mut core::ffi::c_void,
                &inner.transport_cfg as *const _ as *const core::ffi::c_void,
            ),
            TransportInner::Uds(inner) => (
                &inner.transport_cb as *const _,
                &mut inner.transport_ctx as *mut _ as *mut core::ffi::c_void,
                &inner.transport_cfg as *const _ as *const core::ffi::c_void,
            ),
            TransportInner::Shm(inner) => (
                &inner.transport_cb as *const _,
                &mut inner.transport_ctx as *mut _ as *mut core::ffi::c_void,
                &inner.transport_cfg as *const _ as *const core::ffi::c_void,
            ),
        }
    }
}

// ── ClientInner ───────────────────────────────────────────────────────────────
//
// All C state in one heap allocation.  The order of fields matters: `comm_cfg`
// must outlive `client_ctx` (it is referenced by pointer during Cleanup), and
// `transport` must outlive `comm_cfg` (its fields are referenced by pointer
// from `comm_cfg`).
//
// Rust drops struct fields in declaration order (first declared = first
// dropped).  We exploit this: Drop for Client calls wh_Client_Cleanup (which
// uses comm_cfg) before any fields are dropped, then the implicit field drops
// run in order: client_ctx → comm_cfg → transport.  Because wh_Client_Cleanup
// has already run, comm_cfg is no longer in use when transport is dropped.

struct ClientInner {
    client_ctx: whClientContext,
    comm_cfg: whCommClientConfig,
    transport: TransportInner,
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Information returned by the wolfHSM server in response to a CommInfo request.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub version: u8,
    pub build: u8,
    pub comm_data_len: u32,
    pub nvm_object_count: u32,
    pub keycache_count: u32,
    pub keycache_bufsize: u32,
    pub keycache_bigcount: u32,
    pub keycache_bigbufsize: u32,
    pub customcb_count: u32,
    pub dmaaddr_count: u32,
    pub debug_state: u32,
    pub boot_state: u32,
    pub lifecycle_state: u32,
    pub nvm_state: u32,
}

/// A connected wolfHSM client.
///
/// The internal wolfCrypt CryptoCb registration stores the address of the C
/// context, so the allocation must not move after `wh_Client_Init`.  This is
/// ensured by heap-allocating everything inside a `Pin<Box<ClientInner>>`.
///
/// `Client` is `Send` (can be moved to another thread) but not `Sync`
/// (whCommClient is not thread-safe).  It deliberately does not implement
/// `Clone`.
pub struct Client {
    /// Pinned heap allocation containing all C state.  Never moved after init.
    inner: Pin<Box<ClientInner>>,
}

// SAFETY: The C context is not thread-safe for concurrent access, but it is
// safe to send ownership to another thread (no thread-local state).
unsafe impl Send for Client {}

impl Client {
    /// Connect to a wolfHSM server using the given transport.
    ///
    /// Initialises the C client context via `wh_Client_Init`.  The internal C
    /// structs are heap-allocated and pinned so their addresses remain stable
    /// for the lifetime of the `Client`.
    pub fn connect(transport: Transport) -> Result<Self, WolfHsmError> {
        // Build the transport-specific inner state.
        let transport_inner = match transport {
            Transport::Tcp { ip, port } => {
                let ip_cstr =
                    CString::new(ip).map_err(|_| WolfHsmError::Ffi { code: -1, func: "CString::new(ip)" })?;

                let transport_cb = whTransportClientCb {
                    Init: Some(posixTransportTcp_InitConnect),
                    Send: Some(posixTransportTcp_SendRequest),
                    Recv: Some(posixTransportTcp_RecvResponse),
                    Cleanup: Some(posixTransportTcp_CleanupConnect),
                };

                // SAFETY: zero-initialising a C POD struct is correct.
                let transport_ctx: posixTransportTcpClientContext =
                    unsafe { core::mem::zeroed() };
                let transport_cfg = posixTransportTcpConfig {
                    server_ip_string: ip_cstr.as_ptr() as *mut _,
                    server_port: port as i16,
                };

                TransportInner::Tcp(Box::new(TcpInner {
                    transport_ctx,
                    transport_cfg,
                    transport_cb,
                    _ip: ip_cstr,
                }))
            }

            Transport::Uds { path } => {
                let path_cstr = CString::new(path)
                    .map_err(|_| WolfHsmError::Ffi { code: -1, func: "CString::new(path)" })?;

                let transport_cb = whTransportClientCb {
                    Init: Some(posixTransportUds_InitConnect),
                    Send: Some(posixTransportUds_SendRequest),
                    Recv: Some(posixTransportUds_RecvResponse),
                    Cleanup: Some(posixTransportUds_CleanupConnect),
                };

                let transport_ctx: posixTransportUdsClientContext =
                    unsafe { core::mem::zeroed() };
                let transport_cfg = posixTransportUdsConfig {
                    server_path: path_cstr.as_ptr(),
                };

                TransportInner::Uds(Box::new(UdsInner {
                    transport_ctx,
                    transport_cfg,
                    transport_cb,
                    _path: path_cstr,
                }))
            }

            Transport::Shm { name, req_size, resp_size } => {
                let name_cstr = CString::new(name)
                    .map_err(|_| WolfHsmError::Ffi { code: -1, func: "CString::new(name)" })?;

                let transport_cb = whTransportClientCb {
                    Init: Some(posixTransportShm_ClientInit),
                    Send: Some(posixTransportShm_SendRequest),
                    Recv: Some(posixTransportShm_RecvResponse),
                    Cleanup: Some(posixTransportShm_Cleanup),
                };

                let transport_ctx: posixTransportShmClientContext =
                    unsafe { core::mem::zeroed() };
                let transport_cfg = posixTransportShmConfig {
                    name: name_cstr.as_ptr() as *mut _,
                    dma_size: 0,
                    req_size,
                    resp_size,
                };

                TransportInner::Shm(Box::new(ShmInner {
                    transport_ctx,
                    transport_cfg,
                    transport_cb,
                    _name: name_cstr,
                }))
            }
        };

        // Build the ClientInner with a zeroed comm_cfg and client_ctx for now.
        // We fill in comm_cfg after boxing so that the addresses are stable.
        // SAFETY: zero-initialising C POD structs is correct.
        let mut inner: Pin<Box<ClientInner>> = Box::pin(ClientInner {
            client_ctx: unsafe { core::mem::zeroed() },
            comm_cfg: unsafe { core::mem::zeroed() },
            transport: transport_inner,
        });

        // SAFETY: We need mutable access to the pinned data to fill pointers.
        // We never move any fields out of `inner`.
        let inner_mut = unsafe { inner.as_mut().get_unchecked_mut() };

        // Obtain stable pointers into the (already heap-allocated) transport
        // structs, then wire them into comm_cfg.
        let (cb_ptr, ctx_ptr, cfg_ptr) = inner_mut.transport.comm_pointers();
        inner_mut.comm_cfg.transport_cb = cb_ptr;
        inner_mut.comm_cfg.transport_context = ctx_ptr;
        inner_mut.comm_cfg.transport_config = cfg_ptr;
        inner_mut.comm_cfg.connect_cb = None;
        inner_mut.comm_cfg.client_id = 1;

        // Build the whClientConfig pointing to our stable comm_cfg.
        let client_cfg = whClientConfig {
            comm: &mut inner_mut.comm_cfg as *mut _,
        };

        // Call wh_Client_Init.
        // SAFETY: client_ctx and client_cfg are valid C structs at stable addresses.
        let rc = unsafe { wh_Client_Init(&mut inner_mut.client_ctx, &client_cfg) };
        WolfHsmError::check(rc, "wh_Client_Init")?;

        Ok(Client { inner })
    }

    /// Send data to the server and receive an echoed response.
    ///
    /// The server reflects `data` back.  `buf` must be at least as large as
    /// `data`.  Returns the number of bytes written into `buf`.
    pub fn echo(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, WolfHsmError> {
        let snd_len = u16::try_from(data.len())
            .map_err(|_| WolfHsmError::Ffi { code: -1, func: "wh_Client_Echo: data too large" })?;
        let mut rcv_len: u16 = u16::try_from(buf.len())
            .unwrap_or(u16::MAX);

        // SAFETY: pointers are valid for the duration of this call.
        let rc = unsafe {
            wh_Client_Echo(
                self.ctx_ptr(),
                snd_len,
                data.as_ptr() as *const core::ffi::c_void,
                &mut rcv_len,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
            )
        };
        WolfHsmError::check(rc, "wh_Client_Echo")?;
        Ok(rcv_len as usize)
    }

    /// Query the server for its configuration and state information.
    pub fn info(&mut self) -> Result<ServerInfo, WolfHsmError> {
        let mut version: u8 = 0;
        let mut build: u8 = 0;
        let mut comm_data_len: u32 = 0;
        let mut nvm_object_count: u32 = 0;
        let mut keycache_count: u32 = 0;
        let mut keycache_bufsize: u32 = 0;
        let mut keycache_bigcount: u32 = 0;
        let mut keycache_bigbufsize: u32 = 0;
        let mut customcb_count: u32 = 0;
        let mut dmaaddr_count: u32 = 0;
        let mut debug_state: u32 = 0;
        let mut boot_state: u32 = 0;
        let mut lifecycle_state: u32 = 0;
        let mut nvm_state: u32 = 0;

        // SAFETY: all output pointers are valid stack allocations.
        let rc = unsafe {
            wh_Client_CommInfo(
                self.ctx_ptr(),
                &mut version,
                &mut build,
                &mut comm_data_len,
                &mut nvm_object_count,
                &mut keycache_count,
                &mut keycache_bufsize,
                &mut keycache_bigcount,
                &mut keycache_bigbufsize,
                &mut customcb_count,
                &mut dmaaddr_count,
                &mut debug_state,
                &mut boot_state,
                &mut lifecycle_state,
                &mut nvm_state,
            )
        };
        WolfHsmError::check(rc, "wh_Client_CommInfo")?;

        Ok(ServerInfo {
            version,
            build,
            comm_data_len,
            nvm_object_count,
            keycache_count,
            keycache_bufsize,
            keycache_bigcount,
            keycache_bigbufsize,
            customcb_count,
            dmaaddr_count,
            debug_state,
            boot_state,
            lifecycle_state,
            nvm_state,
        })
    }

    /// Return a raw mutable pointer to the `whClientContext` for use in FFI
    /// calls from other modules in this crate.
    ///
    /// # Safety
    ///
    /// The pointer is valid only while `self` is alive and not moved.  Callers
    /// must not store the pointer beyond the lifetime of `self`.
    pub(crate) fn ctx_ptr(&mut self) -> *mut whClientContext {
        // SAFETY: We only expose a pointer, we never move through it.
        unsafe { &mut self.inner.as_mut().get_unchecked_mut().client_ctx }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: wh_Client_Cleanup is called exactly once here, on a context
        // that was successfully initialised by wh_Client_Init in connect().
        // Drop for Client runs before the inner Box fields are dropped, so
        // comm_cfg and transport are still alive during this call.
        let rc = unsafe { wh_Client_Cleanup(self.ctx_ptr()) };
        // Log but do not panic — panicking in Drop is unsound.
        if rc != 0 {
            eprintln!("wh_Client_Cleanup failed: {rc}");
        }
    }
}
