// Integration test: TLS handshake and data exchange using smol + async_io.
//
// Uses a real loopback TcpStream pair via async_io::Async<TcpStream>.
// Both halves run concurrently via smol::block_on + futures::future::try_join.

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use async_io::Async;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::future;


use wolfssl_futures_io::{TlsAcceptor, TlsClientConfig, TlsConnector, TlsServerConfig};
use wolfssl_futures_io::{Certificate, PrivateKey, RootCertStore};

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

#[test]
fn loopback_handshake_and_echo() {
    smol::block_on(async {
        // Bind a loopback listener.
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        let (client_result, server_result) = future::try_join(
            async {
                let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await?;
                let connector = TlsConnector::from(client_config());
                let mut tls = connector
                    .connect("localhost", stream)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                tls.write_all(b"hello from client").await?;
                tls.flush().await?;
                let mut buf = vec![0u8; 17];
                tls.read_exact(&mut buf).await?;
                assert_eq!(&buf, b"hello from client");
                Ok::<_, std::io::Error>(())
            },
            async {
                let (stream, _addr) = listener.accept().await?;
                let acceptor = TlsAcceptor::from(server_config());
                let mut tls = acceptor
                    .accept(stream)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let mut buf = vec![0u8; 17];
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
