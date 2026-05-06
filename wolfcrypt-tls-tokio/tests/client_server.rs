// Integration test: TLS handshake and data exchange over tokio::io::duplex.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use wolfssl_tokio::{TlsAcceptor, TlsClientConfig, TlsConnector, TlsServerConfig};
use wolfssl_tokio::{Certificate, PrivateKey, RootCertStore};

const CA_CERT_PEM: &[u8] = include_bytes!("../../wolfcrypt-tls/tests/certs/ca_cert.pem");
const SERVER_CERT_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_cert.pem");
const SERVER_KEY_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_key.pem");

fn client_config() -> Arc<TlsClientConfig> {
    let mut roots = RootCertStore::new();
    roots.add_pem(CA_CERT_PEM);
    Arc::new(
        TlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
            .build()
            .expect("client config"),
    )
}

fn server_config() -> Arc<TlsServerConfig> {
    Arc::new(
        TlsServerConfig::builder()
            .with_certificate_chain(
                Certificate::from_pem(SERVER_CERT_PEM),
                PrivateKey::from_pem(SERVER_KEY_PEM),
            )
            .with_no_client_auth()
            .build()
            .expect("server config"),
    )
}

#[tokio::test]
async fn loopback_handshake_and_echo() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    let (client_result, server_result) = tokio::join!(
        async {
            let connector = TlsConnector::from(client_config());
            let mut tls = connector.connect("localhost", client_io)
                .expect("connect init")
                .await?;
            tls.write_all(b"hello from client").await?;
            tls.flush().await?;
            let mut buf = vec![0u8; 17];
            tls.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"hello from client", "echo mismatch");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        },
        async {
            let acceptor = TlsAcceptor::from(server_config());
            let mut tls = acceptor.accept(server_io)
                .expect("accept init")
                .await?;
            let mut buf = vec![0u8; 17];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
    );

    client_result.expect("client failed");
    server_result.expect("server failed");
}
