// TLS 1.3 specific integration test.

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
async fn tls13_handshake_and_data_exchange() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let (c, s) = tokio::join!(
        async {
            let mut roots = RootCertStore::new();
            roots.add_pem(CA_CERT_PEM);
            let cfg = Arc::new(
                TlsClientConfig::builder()
                    .with_protocol_versions([ProtocolVersion::Tls13])
                    .with_root_certificates(roots)
                    .with_no_client_auth()
                    .build()
                    .unwrap(),
            );
        let mut tls = TlsConnector::from(cfg).connect("localhost", client_io).unwrap().await?;
        assert_eq!(
            tls.negotiated_version(),
            Some(ProtocolVersion::Tls13),
            "expected TLS 1.3 to be negotiated"
        );
        tls.write_all(b"tls13-client").await?;
        tls.flush().await?;
        let mut buf = [0u8; 12];
        tls.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"tls13-client");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        },
        async {
            let cfg = Arc::new(
                TlsServerConfig::builder()
                    .with_protocol_versions([ProtocolVersion::Tls13])
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
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
    );

    c.expect("TLS 1.3 client failed");
    s.expect("TLS 1.3 server failed");
}
