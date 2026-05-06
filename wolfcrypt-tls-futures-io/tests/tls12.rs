// TLS 1.2 integration test using smol + async_io.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use async_io::Async;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::future;


use wolfssl_futures_io::{TlsAcceptor, TlsClientConfig, TlsConnector, TlsServerConfig};
use wolfssl_futures_io::{Certificate, PrivateKey, ProtocolVersion, RootCertStore};

const CA_CERT_PEM: &[u8] = include_bytes!("../../wolfcrypt-tls/tests/certs/ca_cert.pem");
const SERVER_CERT_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_cert.pem");
const SERVER_KEY_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_key.pem");

#[test]
fn tls12_handshake_and_data_exchange() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        future::try_join(
            async {
                let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await?;
                let mut roots = RootCertStore::new();
                roots.add_pem(CA_CERT_PEM);
                let cfg = Arc::new(
                    TlsClientConfig::builder()
                        .with_protocol_versions(&[ProtocolVersion::Tls12])
                        .with_root_certificates(roots)
                        .with_no_client_auth()
                        .build()
                        .unwrap(),
                );
                let mut tls = TlsConnector::from(cfg)
                    .connect("localhost", stream)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                tls.write_all(b"tls12").await?;
                tls.flush().await?;
                let mut buf = [0u8; 5];
                tls.read_exact(&mut buf).await?;
                assert_eq!(&buf, b"tls12");
                Ok::<_, std::io::Error>(())
            },
            async {
                let (stream, _) = listener.accept().await?;
                let cfg = Arc::new(
                    TlsServerConfig::builder()
                        .with_protocol_versions(&[ProtocolVersion::Tls12])
                        .with_certificate_chain(
                            Certificate::from_pem(SERVER_CERT_PEM),
                            PrivateKey::from_pem(SERVER_KEY_PEM),
                        )
                        .with_no_client_auth()
                        .build()
                        .unwrap(),
                );
                let mut tls = TlsAcceptor::from(cfg)
                    .accept(stream)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let mut buf = [0u8; 5];
                tls.read_exact(&mut buf).await?;
                tls.write_all(&buf).await?;
                tls.flush().await?;
                Ok::<_, std::io::Error>(())
            },
        )
        .await
        .unwrap();
    });
}
