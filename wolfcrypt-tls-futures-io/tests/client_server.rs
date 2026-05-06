// Integration test: loopback TLS handshake using smol as the executor
// and futures-io compatible in-process IO.

#[test]
#[ignore = "not yet implemented"]
fn loopback_handshake() {
    // smol::block_on(async {
    //   build client/server configs, create in-process duplex IO,
    //   handshake, exchange data, assert round-trip
    // })
    todo!("build client/server configs, in-process IO, handshake, exchange data")
}
