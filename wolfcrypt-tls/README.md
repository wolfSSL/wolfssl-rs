# wolfcrypt-tls

Safe Rust TLS client and server backed by [wolfSSL](https://wolfssl.com). Exported as the `wolfssl` crate.

## Usage

```toml
[dependencies]
wolfcrypt-tls = "0.1"
```

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
```

Server-side uses `TlsServerConfig` and `TlsServer` symmetrically.

## Features

| Feature | Description |
|---------|-------------|
| `vendored` | Compile wolfSSL from source (requires `WOLFSSL_SRC` or pkg-config) |
| `fips` | Enable the wolfSSL FIPS 140-3 code path |

FIPS 140-3 validated builds require a wolfSSL commercial license and the validated source tree. See the [workspace README](https://github.com/wolfSSL/wolfssl-rs) for details.

## Status

- TLS 1.2 and TLS 1.3
- Blocking I/O (async support planned)
- Unix and Windows socket support

## License

MIT
