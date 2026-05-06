# wolfcrypt-tls

Safe Rust TLS client and server backed by [wolfSSL](https://wolfssl.com).
Published as the `wolfssl` crate (`lib.name = "wolfssl"`).

## Why

wolfSSL is a FIPS 140-3 validated TLS library used in billions of embedded
and server deployments. This crate wraps it in an idiomatic Rust API:

- **FIPS 140-3** — TLS with a validated crypto backend, required by some
  regulated environments (commercial license;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **Small footprint** — one dependency chain, no OpenSSL; works on embedded
  targets and servers alike
- **Transport-agnostic** — any `Read + Write` type is a valid transport;
  `TcpStream`, `UnixStream`, in-memory pipes, and custom types all work
  without adaptation

## Usage

```toml
[dependencies]
wolfcrypt-tls = "0.2"
```

### TLS client

```rust
use wolfssl::{TlsClientConfig, TlsClient, RootCertStore};
use std::io::{Read, Write};
use std::net::TcpStream;

let mut roots = RootCertStore::new();
roots.add_pem(include_bytes!("ca.pem"));

let config = TlsClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth()
    .build()?;

let stream = TcpStream::connect("example.com:443")?;
let mut tls = TlsClient::new(config, "example.com", stream)?;
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
let mut buf = [0u8; 4096];
let n = tls.read(&mut buf)?;
```

### TLS server

```rust
use wolfssl::{TlsServerConfig, TlsAcceptor, Certificate, PrivateKey};
use std::net::TcpListener;

let config = TlsServerConfig::builder()
    .with_certificate_chain(
        Certificate::from_pem(include_bytes!("server.pem")),
        PrivateKey::from_pem(include_bytes!("server-key.pem")),
    )
    .with_no_client_auth()
    .build()?;

let acceptor = TlsAcceptor::new(config);
let listener = TcpListener::bind("0.0.0.0:443")?;

for stream in listener.incoming() {
    let mut tls = acceptor.accept(stream?)?;
    // tls: TlsServer<TcpStream> — implements Read + Write
}
```

### Mutual TLS (mTLS)

```rust
// Server — require a client certificate
let config = TlsServerConfig::builder()
    .with_certificate_chain(cert, key)
    .with_client_auth(client_ca_store)
    .build()?;

// Client — present a certificate
let config = TlsClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth(client_cert, client_key)
    .build()?;
```

### Protocol version pinning

```rust
use wolfssl::ProtocolVersion;

let config = TlsClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth()
    .with_protocol_versions(&[ProtocolVersion::Tls13])
    .build()?;
```

## How it works

```text
wolfssl-src      Compiles wolfSSL C source (cc crate)
      │
wolfcrypt-sys    bindgen FFI bindings
      │
wolfcrypt-tls    TlsClient / TlsServer / TlsAcceptor  ← this crate
                 lib.name = "wolfssl"
```

`TlsClientConfig` and `TlsServerConfig` wrap `WOLFSSL_CTX` in an `Arc`-backed
RAII type. `TlsClient` and `TlsServer` wrap `WOLFSSL` session pointers and
implement `Read + Write`. The transport is wired through wolfSSL's custom IO
callback mechanism (`wolfSSL_SSLSetIORecv` / `wolfSSL_SSLSetIOSend`) rather
than a file descriptor, which is what makes any `Read + Write` type work as a
transport.

For async use, the config types expose `new_session_with_io`, a typed session
builder that wires the callbacks and returns an owned `*mut WOLFSSL`.
`wolfcrypt-tls-tokio` and `wolfcrypt-tls-futures-io` build their async layers
on top of this without duplicating any cert/key loading logic.

| Feature    | Description |
|------------|-------------|
| `vendored` | Compile wolfSSL from source (requires `WOLFSSL_SRC` or pkg-config) |
| `fips`     | Enable the wolfSSL FIPS 140-3 code path (commercial license required) |

## References

- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [wolfcrypt-tls-tokio](../wolfcrypt-tls-tokio) — tokio async layer
- [wolfcrypt-tls-futures-io](../wolfcrypt-tls-futures-io) — futures-io async layer
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial — see [LICENSE](LICENSE).

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
