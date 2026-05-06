// Integration test: TLS handshake and data exchange over tokio::io::duplex.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use wolfssl_tokio::{TlsAcceptor, TlsClientConfig, TlsConnector, TlsServerConfig};
use wolfssl_tokio::{Certificate, PrivateKey, RootCertStore, ProtocolVersion};

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

/// Drop a `Connect` future before it completes to verify that no UB or panic
/// occurs when a partially-constructed `TlsStream` is dropped mid-handshake.
/// This exercises the `TlsStream::Drop` path on a session where wolfSSL_connect
/// has not yet succeeded.
#[tokio::test]
async fn connect_future_drop_before_completion() {
    let (client_io, _server_io) = tokio::io::duplex(65536);

    let connector = TlsConnector::from(client_config());
    // Allocate the Connect future (wolfSSL session created) but drop it
    // immediately without polling, triggering TlsStream::Drop.
    let _connect_fut = connector.connect("localhost", client_io).expect("connect init");
    // Drop happens here — should not panic or cause UB.
}

/// Drop an `Accept` future before it completes (no client connected).
#[tokio::test]
async fn accept_future_drop_before_completion() {
    let (_client_io, server_io) = tokio::io::duplex(65536);

    let acceptor = TlsAcceptor::from(server_config());
    let _accept_fut = acceptor.accept(server_io).expect("accept init");
    // Drop happens here — should not panic or cause UB.
}

/// mTLS: client and server both present certificates; handshake should succeed.
#[tokio::test]
async fn mtls_both_sides_authenticated() {
    let (client_io, server_io) = tokio::io::duplex(65536);

    // Server requires client cert.
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

    // Client provides its own cert.
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

    let (client_result, server_result) = tokio::join!(
        async {
            let mut tls = TlsConnector::from(cli_cfg)
                .connect("localhost", client_io)
                .expect("connect init")
                .await?;
            tls.write_all(b"mtls-ping").await?;
            tls.flush().await?;
            let mut buf = vec![0u8; 9];
            tls.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"mtls-ping");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        },
        async {
            let mut tls = TlsAcceptor::from(srv_cfg)
                .accept(server_io)
                .expect("accept init")
                .await?;
            let mut buf = vec![0u8; 9];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
    );

    client_result.expect("mTLS client failed");
    server_result.expect("mTLS server failed");
}

/// mTLS: server requires client cert but client provides none — handshake should fail.
#[tokio::test]
async fn mtls_rejection_client_without_cert() {
    let (client_io, server_io) = tokio::io::duplex(65536);

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
            .expect("client config"),
    );

    let (client_result, server_result) = tokio::join!(
        TlsConnector::from(cli_cfg)
            .connect("localhost", client_io)
            .expect("connect init"),
        TlsAcceptor::from(srv_cfg)
            .accept(server_io)
            .expect("accept init"),
    );

    // Both sides must fail — the server sends a fatal alert rejecting the client,
    // which causes the server to error and the client to receive the alert and
    // also error.
    assert!(client_result.is_err(), "client should fail when server requires cert");
    assert!(server_result.is_err(), "server should reject client with no cert");
}
