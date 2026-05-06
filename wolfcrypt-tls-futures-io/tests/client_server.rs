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
use wolfssl_futures_io::{Certificate, PrivateKey, RootCertStore, ProtocolVersion};

const CA_CERT_PEM: &[u8] = include_bytes!("../../wolfcrypt-tls/tests/certs/ca_cert.pem");
const SERVER_CERT_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_cert.pem");
const SERVER_KEY_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/server_key.pem");
const CLIENT_CERT_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/client_cert.pem");
const CLIENT_KEY_PEM: &[u8] =
    include_bytes!("../../wolfcrypt-tls/tests/certs/client_key.pem");

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

        let (_client_result, _server_result) = future::try_join(
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

/// Drop a `Connect` future before it completes to verify that no UB or panic
/// occurs when a partially-constructed `TlsStream` is dropped mid-handshake.
#[test]
fn connect_future_drop_before_completion() {
    smol::block_on(async {
        // Bind a listener but never accept — client will stall after ClientHello.
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await.unwrap();
        let connector = TlsConnector::from(client_config());
        let _connect_fut = connector.connect("localhost", stream).expect("connect init");
        // _connect_fut is dropped here without polling — no panic or UB.
    });
}

/// Drop an `Accept` future before it completes (no client connects).
#[test]
fn accept_future_drop_before_completion() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        // Pre-connect a client so the server accept() gets a stream.
        let _client_stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await.unwrap();
        let (server_stream, _addr) = listener.accept().await.unwrap();

        let acceptor = TlsAcceptor::from(server_config());
        let _accept_fut = acceptor.accept(server_stream).expect("accept init");
        // _accept_fut dropped here without polling — no panic or UB.
    });
}

/// mTLS: client and server both present certificates; handshake should succeed.
#[test]
fn mtls_both_sides_authenticated() {
    use futures_util::future;
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        // Server config requiring client cert.
        let mut ca_store = RootCertStore::new();
        ca_store.add_pem(CA_CERT_PEM);
        let srv_cfg = Arc::new(
            TlsServerConfig::builder()
                .with_protocol_versions(&[ProtocolVersion::Tls12])
                .with_certificate_chain(
                    Certificate::from_pem(SERVER_CERT_PEM),
                    PrivateKey::from_pem(SERVER_KEY_PEM),
                )
                .with_client_auth(ca_store)
                .build()
                .expect("mTLS server config"),
        );

        // Client config with client cert.
        let mut roots = RootCertStore::new();
        roots.add_pem(CA_CERT_PEM);
        let cli_cfg = Arc::new(
            TlsClientConfig::builder()
                .with_protocol_versions(&[ProtocolVersion::Tls12])
                .with_root_certificates(roots)
                .with_client_auth(
                    Certificate::from_pem(CLIENT_CERT_PEM),
                    PrivateKey::from_pem(CLIENT_KEY_PEM),
                )
                .build()
                .expect("mTLS client config"),
        );

        let to_io = |e: wolfssl_futures_io::Error| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        };

        let (c, s) = future::try_join(
            async {
                let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await?;
                let mut tls = TlsConnector::from(cli_cfg)
                    .connect("localhost", stream)
                    .map_err(|e| to_io(e))?
                    .await
                    .map_err(|e| to_io(e))?;
                tls.write_all(b"mtls-ping").await?;
                tls.flush().await?;
                let mut buf = vec![0u8; 9];
                tls.read_exact(&mut buf).await?;
                assert_eq!(&buf, b"mtls-ping");
                Ok::<_, std::io::Error>(())
            },
            async {
                let (stream, _) = listener.accept().await?;
                let mut tls = TlsAcceptor::from(srv_cfg)
                    .accept(stream)
                    .map_err(|e| to_io(e))?
                    .await
                    .map_err(|e| to_io(e))?;
                let mut buf = vec![0u8; 9];
                tls.read_exact(&mut buf).await?;
                tls.write_all(&buf).await?;
                tls.flush().await?;
                Ok::<_, std::io::Error>(())
            },
        )
        .await
        .unwrap();
        let _ = (c, s);
    });
}

/// mTLS: server requires client cert but client presents none — handshake should fail.
#[test]
fn mtls_rejection_client_without_cert() {
    smol::block_on(async {
        let listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 0)).unwrap();
        let port = listener.get_ref().local_addr().unwrap().port();

        let mut ca_store = RootCertStore::new();
        ca_store.add_pem(CA_CERT_PEM);
        let srv_cfg = Arc::new(
            TlsServerConfig::builder()
                .with_protocol_versions(&[ProtocolVersion::Tls12])
                .with_certificate_chain(
                    Certificate::from_pem(SERVER_CERT_PEM),
                    PrivateKey::from_pem(SERVER_KEY_PEM),
                )
                .with_client_auth(ca_store)
                .build()
                .expect("mTLS server config"),
        );

        let mut roots = RootCertStore::new();
        roots.add_pem(CA_CERT_PEM);
        let cli_cfg = Arc::new(
            TlsClientConfig::builder()
                .with_protocol_versions(&[ProtocolVersion::Tls12])
                .with_root_certificates(roots)
                .with_no_client_auth()
                .build()
                .expect("client config no cert"),
        );

        let to_io = |e: wolfssl_futures_io::Error| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        };

        let client_fut = async {
            let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], port)).await?;
            TlsConnector::from(cli_cfg)
                .connect("localhost", stream)
                .map_err(|e| to_io(e))?
                .await
                .map_err(|e| to_io(e))?;
            Ok::<_, std::io::Error>(())
        };

        let server_fut = async {
            let (stream, _) = listener.accept().await?;
            TlsAcceptor::from(srv_cfg)
                .accept(stream)
                .map_err(|e| to_io(e))?
                .await
                .map_err(|e| to_io(e))?;
            Ok::<_, std::io::Error>(())
        };

        let (c, s) = futures_util::future::join(client_fut, server_fut).await;
        // Both sides must fail — server sends fatal alert, client receives it.
        assert!(c.is_err(), "client should fail when server requires cert");
        assert!(s.is_err(), "server should reject client with no cert");
    });
}
