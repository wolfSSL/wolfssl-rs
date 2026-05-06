use wolfcrypt_sys::*;

use crate::error::Result;
use crate::error::TlsError;

/// TLS protocol version to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Side {
    Client,
    Server,
}

/// Resolve a user-supplied version list into a wolfSSL method pointer.
///
/// `None` means "use default (TLS 1.2+)".
///
/// # Safety
/// wolfSSL_Init must have been called.
pub(crate) unsafe fn resolve_method(
    side: Side,
    versions: Option<&[ProtocolVersion]>,
) -> Result<*mut WOLFSSL_METHOD> {
    let (ptr, func): (*mut WOLFSSL_METHOD, &'static str) = match (versions, side) {
        (Some([ProtocolVersion::Tls12]), Side::Client) => unsafe {
            (wolfTLSv1_2_client_method(), "wolfTLSv1_2_client_method")
        },
        (Some([ProtocolVersion::Tls12]), Side::Server) => unsafe {
            (wolfTLSv1_2_server_method(), "wolfTLSv1_2_server_method")
        },
        (Some([ProtocolVersion::Tls13]), Side::Client) => unsafe {
            (wolfTLSv1_3_client_method(), "wolfTLSv1_3_client_method")
        },
        (Some([ProtocolVersion::Tls13]), Side::Server) => unsafe {
            (wolfTLSv1_3_server_method(), "wolfTLSv1_3_server_method")
        },

        // "v23" is an OpenSSL legacy name retained by wolfSSL — it means
        // "negotiate the highest mutually supported version". We enforce a
        // TLS 1.2 floor via wolfSSL_CTX_SetMinVersion in the build() methods.
        (None, Side::Client)
        | (Some([ProtocolVersion::Tls12, ProtocolVersion::Tls13]), Side::Client)
        | (Some([ProtocolVersion::Tls13, ProtocolVersion::Tls12]), Side::Client) => unsafe {
            (wolfSSLv23_client_method(), "wolfSSLv23_client_method")
        },
        (None, Side::Server)
        | (Some([ProtocolVersion::Tls12, ProtocolVersion::Tls13]), Side::Server)
        | (Some([ProtocolVersion::Tls13, ProtocolVersion::Tls12]), Side::Server) => unsafe {
            (wolfSSLv23_server_method(), "wolfSSLv23_server_method")
        },

        (Some(_), _) => {
            return Err(TlsError::InvalidConfig(
                "protocol_versions must be [Tls12], [Tls13], or [Tls12, Tls13]",
            ));
        }
    };

    if ptr.is_null() {
        return Err(TlsError::AllocFailed { func });
    }

    Ok(ptr)
}
