# wolfcrypt-tls

Safe Rust TLS client and server backed by [wolfSSL](https://wolfssl.com).
Published as the `wolfssl` crate (`lib.name = "wolfssl"`).

## Why

wolfSSL is a FIPS 140-3 validated TLS library used in billions of embedded and
server deployments. `wolfcrypt-tls` gives you:

- **FIPS 140-3** — TLS with a validated crypto backend for regulated
  environments (commercial license required;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **Small footprint** — designed for embedded targets alongside full server
  deployments; a single dependency chain, no OpenSSL
- **Familiar Rust API** — `TlsClient`/`TlsServer` types that wrap standard
  `std::io::Read + Write` streams
- **Async-ready** — config types expose raw `WOLFSSL_CTX` and `WOLFSSL`
  pointers and a session builder with custom IO callbacks, so async runtimes
  (e.g. `wolfcrypt-tls-tokio`) can build on top without duplicating
  cert/key loading logic

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
// Server: require client certificates
let config = TlsServerConfig::builder()
    .with_certificate_chain(cert, key)
    .with_client_auth(client_ca_store)
    .build()?;

// Client: present a certificate
let config = TlsClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth(client_cert, client_key)
    .build()?;
```

### Protocol version control

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
wolfssl-src      Compiles wolfSSL C source via the cc crate
      │
wolfcrypt-sys    bindgen FFI bindings to wolfSSL
      │
wolfcrypt-tls    Safe TlsClient / TlsServer API (this crate)
                 Exported as lib.name = "wolfssl"
```

`TlsClientConfig` and `TlsServerConfig` wrap `WOLFSSL_CTX` in an
`Arc`-backed RAII type. `TlsClient` and `TlsServer` wrap `WOLFSSL` session
objects and implement `Read + Write`. The underlying transport is plugged in
via wolfSSL's custom IO callback mechanism (`wolfSSL_SSLSetIORecv` /
`wolfSSL_SSLSetIOSend`); any type implementing `Read + Write` satisfies the
[`IOCallbacks`] trait automatically.

For async runtimes, the config types expose `new_ssl_with_io_callbacks` — a
session builder that wires hand-rolled `extern "C"` recv/send callbacks and
returns an owned `*mut WOLFSSL`. See `wolfcrypt-tls-tokio` for the tokio
async layer built on this API.

## Features

| Feature | Description |
|---------|-------------|
| `vendored` | Compile wolfSSL from source (requires `WOLFSSL_SRC` or pkg-config) |
| `fips` | Enable the wolfSSL FIPS 140-3 code path |

FIPS 140-3 validated builds require a wolfSSL commercial license and the
validated source tree. [Contact wolfSSL](https://www.wolfssl.com/license/)
for a commercial FIPS license. See the
[workspace README](https://github.com/wolfSSL/wolfssl-rs) for details.

## Status

- TLS 1.2 and TLS 1.3
- Client and server, including mutual TLS (mTLS)
- Blocking I/O over any `Read + Write` transport
- Async IO callback API for building async adapters
- Unix and Windows socket support

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial — see [LICENSE](LICENSE).

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
