// TLS 1.2 specific integration test.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use wolfssl_tokio::{TlsAcceptor, TlsClientConfig, TlsConnector, TlsServerConfig};
use wolfssl_tokio::{Certificate, PrivateKey, ProtocolVersion, RootCertStore};

const CA_CERT_PEM: &[u8] = include_bytes!("../../wolfcrypt-tls/tests/certs/ca_cert.pem");
const SERVER_CERT_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_cert.pem");
const SERVER_KEY_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_key.pem");

#[tokio::test]
async fn tls12_handshake_and_data_exchange() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let (c, s) = tokio::join!(
        async {
            let mut roots = RootCertStore::new();
            roots.add_pem(CA_CERT_PEM);
            let cfg = Arc::new(
                TlsClientConfig::builder()
                    .with_protocol_versions([ProtocolVersion::Tls12])
                    .with_root_certificates(roots)
                    .with_no_client_auth()
                    .build()
                    .unwrap(),
            );
        let mut tls = TlsConnector::from(cfg).connect("localhost", client_io).unwrap().await?;
        // Verify the negotiated protocol is actually TLS 1.2, not a fallback.
        assert_eq!(
            tls.negotiated_version(),
            Some(ProtocolVersion::Tls12),
            "expected TLS 1.2 to be negotiated"
        );
        tls.write_all(b"tls12-client").await?;
        tls.flush().await?;
        let mut buf = [0u8; 12];
        tls.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"tls12-client");
            Ok::<_, Box<dyn core::error::Error + Send + Sync>>(())
        },
        async {
            let cfg = Arc::new(
                TlsServerConfig::builder()
                    .with_protocol_versions([ProtocolVersion::Tls12])
                    .with_certificate_chain(
                        Certificate::from_pem(SERVER_CERT_PEM),
                        PrivateKey::from_pem(SERVER_KEY_PEM),
                    )
                    .with_no_client_auth()
                    .build()
                    .unwrap(),
            );
            let mut tls = TlsAcceptor::from(cfg).accept(server_io).unwrap().await?;
            let mut buf = [0u8; 12];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, Box<dyn core::error::Error + Send + Sync>>(())
        }
    );

    c.expect("TLS 1.2 client failed");
    s.expect("TLS 1.2 server failed");
}
