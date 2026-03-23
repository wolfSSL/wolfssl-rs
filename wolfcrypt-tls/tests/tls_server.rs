mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use wolfssl::{
    Certificate, PrivateKey, RootCertStore, TlsAcceptor, TlsClient, TlsClientConfig,
    TlsServerConfig,
};

use support::{
    client_config, server_config, start_echo_server, CA_CERT_PEM, SERVER_CERT_PEM, SERVER_KEY_PEM,
};

#[test]
fn full_client_server_round_trip() {
    let (port, server_handle) = start_echo_server(server_config(false), 1);

    let cfg = client_config(false);
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls = TlsClient::new(cfg, "localhost", stream).expect("handshake failed");

    let msg = b"round-trip test message 9876543210";
    tls.write_all(msg).unwrap();
    let mut buf = vec![0u8; msg.len()];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, msg);

    let msg2 = b"second message ABCDEF";
    tls.write_all(msg2).unwrap();
    let mut buf2 = vec![0u8; msg2.len()];
    tls.read_exact(&mut buf2).unwrap();
    assert_eq!(&buf2, msg2);

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn mtls_both_sides_authenticated() {
    let (port, server_handle) = start_echo_server(server_config(true), 1);

    let cfg = client_config(true);
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let mut tls =
        TlsClient::new(cfg, "localhost", stream).expect("mTLS handshake should succeed");

    let msg = b"mutual auth verified data 0xDEADBEEF";
    tls.write_all(msg).unwrap();
    let mut buf = vec![0u8; msg.len()];
    tls.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, msg);

    drop(tls);
    server_handle.join().unwrap();
}

#[test]
fn mtls_rejection_client_without_cert() {
    // Use TLS 1.2 to ensure client cert request happens during handshake,
    // not post-handshake as in TLS 1.3.
    let cert = Certificate::from_pem(SERVER_CERT_PEM);
    let key = PrivateKey::from_pem(SERVER_KEY_PEM);
    let mut ca_store = RootCertStore::new();
    ca_store.add_pem(CA_CERT_PEM);
    let srv_config = TlsServerConfig::builder()
        .with_protocol_versions(&[wolfssl::ProtocolVersion::Tls12])
        .with_certificate_chain(cert, key)
        .with_client_auth(ca_store)
        .build()
        .unwrap();

    let (port, server_handle) = start_echo_server(srv_config, 1);

    // Client WITHOUT client cert — server requires it.
    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);
    let cfg = TlsClientConfig::builder()
        .with_protocol_versions(&[wolfssl::ProtocolVersion::Tls12])
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .build()
        .unwrap();

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let result = TlsClient::new(cfg, "localhost", stream);

    // The handshake should fail, or if it appears to succeed due to timing,
    // the first I/O operation must fail.
    match result {
        Err(_) => {} // handshake failed as expected
        Ok(mut tls) => {
            // If handshake appeared to succeed, I/O must fail because
            // the server rejected the connection.
            let write_result = tls.write_all(b"test");
            let mut buf = [0u8; 4];
            let read_result = tls.read_exact(&mut buf);
            assert!(
                write_result.is_err() || read_result.is_err(),
                "I/O must fail when server rejected client without cert"
            );
        }
    }

    let _ = server_handle.join();
}

#[test]
fn multiple_sequential_connections() {
    let (port, server_handle) = start_echo_server(server_config(false), 3);

    for i in 0..3 {
        let cfg = client_config(false);
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let mut tls = TlsClient::new(cfg, "localhost", stream).expect("handshake failed");

        let msg = format!("sequential connection {i} unique data");
        tls.write_all(msg.as_bytes()).unwrap();
        let mut buf = vec![0u8; msg.len()];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(buf, msg.as_bytes(), "data mismatch on connection {i}");

        drop(tls);
    }

    server_handle.join().unwrap();
}

#[test]
fn concurrent_connections() {
    // Server accepts connections and handles each in a thread.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = server_config(false);

    let server_handle = thread::spawn(move || {
        let acceptor = TlsAcceptor::new(config);
        let mut handlers = Vec::new();

        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            match acceptor.accept(stream) {
                Ok(mut tls) => {
                    let h = thread::spawn(move || {
                        let mut buf = [0u8; 256];
                        match tls.read(&mut buf) {
                            Ok(n) if n > 0 => {
                                tls.write_all(&buf[..n]).ok();
                            }
                            _ => {}
                        }
                    });
                    handlers.push(h);
                }
                Err(e) => eprintln!("server accept error: {e}"),
            }
        }

        for h in handlers {
            h.join().unwrap();
        }
    });

    // Connect 3 clients in parallel.
    let mut client_handles = Vec::new();
    for i in 0..3 {
        let h = thread::spawn(move || {
            let cfg = client_config(false);
            let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            let mut tls = TlsClient::new(cfg, "localhost", stream).expect("handshake failed");

            let msg = format!("concurrent client {i} unique payload");
            tls.write_all(msg.as_bytes()).unwrap();
            let mut buf = vec![0u8; msg.len()];
            tls.read_exact(&mut buf).unwrap();
            assert_eq!(
                buf,
                msg.as_bytes(),
                "data mismatch for concurrent client {i}"
            );
        });
        client_handles.push(h);
    }

    for h in client_handles {
        h.join().unwrap();
    }
    server_handle.join().unwrap();
}
