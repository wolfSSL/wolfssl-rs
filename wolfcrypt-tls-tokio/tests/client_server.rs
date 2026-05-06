// Integration test: loopback TLS handshake over tokio::io::duplex.
//
// Uses tokio::io::duplex to create a paired in-memory AsyncRead+AsyncWrite,
// then drives a full TLS handshake between a TlsConnector and TlsAcceptor.

#[tokio::test]
#[ignore = "not yet implemented"]
async fn loopback_handshake() {
    todo!("build client/server configs, duplex pair, handshake, exchange data")
}
