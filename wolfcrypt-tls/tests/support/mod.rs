use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use wolfssl::{
    Certificate, PrivateKey, RootCertStore, TlsAcceptor, TlsClientConfig, TlsServerConfig,
};

pub const CA_CERT_PEM: &[u8] = include_bytes!("../certs/ca_cert.pem");
pub const SERVER_CERT_PEM: &[u8] = include_bytes!("../certs/server_cert.pem");
pub const SERVER_KEY_PEM: &[u8] = include_bytes!("../certs/server_key.pem");
pub const CLIENT_CERT_PEM: &[u8] = include_bytes!("../certs/client_cert.pem");
pub const CLIENT_KEY_PEM: &[u8] = include_bytes!("../certs/client_key.pem");

pub fn server_config(require_client_auth: bool) -> TlsServerConfig {
    let cert = Certificate::from_pem(SERVER_CERT_PEM);
    let key = PrivateKey::from_pem(SERVER_KEY_PEM);

    let mut builder = TlsServerConfig::builder().with_certificate_chain(cert, key);

    if require_client_auth {
        let mut ca_store = RootCertStore::new();
        ca_store.add_pem(CA_CERT_PEM);
        builder = builder.with_client_auth(ca_store);
    } else {
        builder = builder.with_no_client_auth();
    }

    builder.build().expect("server config build failed")
}

pub fn client_config(client_auth: bool) -> TlsClientConfig {
    let mut root_store = RootCertStore::new();
    root_store.add_pem(CA_CERT_PEM);

    let mut builder = TlsClientConfig::builder().with_root_certificates(root_store);

    if client_auth {
        let cert = Certificate::from_pem(CLIENT_CERT_PEM);
        let key = PrivateKey::from_pem(CLIENT_KEY_PEM);
        builder = builder.with_client_auth(cert, key);
    } else {
        builder = builder.with_no_client_auth();
    }

    builder.build().expect("client config build failed")
}

/// Start an echo server that accepts `max_connections` connections sequentially.
pub fn start_echo_server(
    config: TlsServerConfig,
    max_connections: usize,
) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        let acceptor = TlsAcceptor::new(config);
        for _ in 0..max_connections {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            match acceptor.accept(stream) {
                Ok(mut tls) => {
                    let mut buf = vec![0u8; 1024 * 1024 + 64];
                    loop {
                        match tls.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    eprintln!("server accept error: {e}");
                }
            }
        }
    });

    (port, handle)
}
