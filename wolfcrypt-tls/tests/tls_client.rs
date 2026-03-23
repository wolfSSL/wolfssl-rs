mod support;

use std::io::{Read, Write};
use std::net::TcpStream;

use wolfssl::{ProtocolVersion, RootCertStore, TlsClient, TlsClientConfig};

use support::{start_echo_server, server_config, CA_CERT_PEM};

#[test]
fn client_connects_to_localhost_server() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .expect("client config build failed");

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(config, "localhost", stream).expect("TLS handshake failed");

    tls.write_all(b"hello").expect("write failed");
    let mut response = vec![0u8; 5];
    tls.read_exact(&mut response).expect("read failed");
    assert_eq!(&response, b"hello");

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn client_rejects_self_signed_cert_without_ca() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    // Empty root store: no CAs are trusted, so the server's cert should be rejected.
    let root_store = RootCertStore::new();

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .expect("client config build should succeed (empty store is valid)");

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let result = TlsClient::new(config, "localhost", stream);

    assert!(result.is_err(), "connection should fail without trusted CA");
    match result.unwrap_err() {
        wolfssl::TlsError::CertificateVerification(_) => {} // expected
        wolfssl::TlsError::Ffi { code, func } => {
            // wolfSSL may report this as a generic handshake error
            eprintln!("got Ffi error: {func} code={code} (acceptable)");
        }
        other => panic!("unexpected error type: {other}"),
    }

    // Server thread may have failed too, that's fine.
    let _ = server_handle.join();
}

#[test]
fn client_accepts_cert_when_ca_in_root_store() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(config, "localhost", stream)
        .expect("handshake should succeed with CA in store");

    tls.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn large_data_transfer() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(config, "localhost", stream).unwrap();

    // Send 1MB of patterned data.
    let send_data: Vec<u8> = (0..1_000_000).map(|i| (i % 251) as u8).collect();
    tls.write_all(&send_data).unwrap();

    // Read back the echoed data.
    let mut recv_data = vec![0u8; send_data.len()];
    tls.read_exact(&mut recv_data)
        .expect("failed to read 1MB back");

    // Compare byte-by-byte.
    assert_eq!(send_data.len(), recv_data.len(), "length mismatch");
    assert!(
        send_data == recv_data,
        "data mismatch: sent and received bytes differ"
    );

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn tls_client_implements_read_write() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(config, "localhost", stream).unwrap();

    // Use write_all (from Write trait) and read_exact (from Read trait)
    // to verify the trait implementations work with generic I/O code.
    let msg = b"generic io test data 12345";
    tls.write_all(msg).unwrap();

    let mut buf = vec![0u8; msg.len()];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, msg);

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn connection_uses_modern_tls() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_protocol_versions(&[ProtocolVersion::Tls13])
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(config, "localhost", stream)
        .expect("TLS 1.3 handshake should succeed");

    // Verify we can exchange data.
    tls.write_all(b"tls13").unwrap();
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"tls13");

    drop(tls);
    server_handle.join().unwrap();
}

/// Verify that an absurdly long server name is rejected at config time,
/// not silently truncated to u16. This guards against regressing the
/// `server_name.len() > u16::MAX` check back to an unchecked `as u16` cast.
#[test]
fn rejects_oversized_server_name() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let config = TlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    // A server name longer than u16::MAX (65535) should be rejected.
    let huge_name = "a".repeat(65536);
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let result = TlsClient::new(config, &huge_name, stream);

    match result {
        Err(wolfssl::TlsError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("SNI"),
                "error should mention SNI, got: {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig, got: {other}"),
        Ok(_) => panic!("should have rejected oversized server name"),
    }

    // Server may be waiting; drop it.
    let _ = server_handle.join();
}
