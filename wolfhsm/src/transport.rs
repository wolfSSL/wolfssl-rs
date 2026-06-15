/// Transport configuration for connecting to a wolfHSM server.
///
/// This enum selects which POSIX transport backend to use and carries the
/// Rust-owned configuration data for that transport.  When a client
/// connection is established the data here is converted into the
/// corresponding C config struct (`posixTransportTcpConfig`, etc.) and
/// pinned for the lifetime of the connection.
///
/// # Transport variants
///
/// | Variant | wolfHSM C type           | Underlying mechanism        |
/// |---------|-------------------------|-----------------------------|
/// | `Tcp`   | `posixTransportTcpConfig` | TCP/IP socket               |
/// | `Uds`   | `posixTransportUdsConfig` | Unix Domain Socket          |
/// | `Shm`   | `posixTransportShmConfig` | POSIX shared memory (`shm_open`) |
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Transport {
    /// TCP/IP connection to a wolfHSM server.
    Tcp {
        /// Server IP address or hostname (e.g. `"127.0.0.1"`).
        ip: String,
        /// Server TCP port number (1–32767).
        ///
        /// The underlying POSIX transport stores the port as a C `i16`; ports above
        /// 32767 are rejected at connection time with [`crate::Error::InvalidInput`].
        port: u16,
    },

    /// Unix Domain Socket connection to a wolfHSM server on the same host.
    Uds {
        /// Filesystem path to the UDS socket file
        /// (e.g. `"/run/wolfhsm/wolfhsm.sock"`).
        /// Must be at most `POSIX_TRANSPORT_UDS_PATH_MAX` (107) bytes.
        path: String,
    },

    /// POSIX shared-memory transport (same host, zero-copy).
    Shm {
        /// POSIX shared memory object name (must start with `'/'`,
        /// e.g. `"/wolfhsm"`).  At most `NAME_MAX` bytes.
        name: String,
        /// Maximum size of a single client request packet in bytes.
        req_size: u16,
        /// Maximum size of a single server response packet in bytes.
        resp_size: u16,
    },
}
