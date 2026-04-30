# wolfcrypt-tls

Safe Rust TLS client and server backed by [wolfSSL](https://wolfssl.com).
Exported as the `wolfssl` crate.

## Why

wolfSSL is a FIPS 140-3 validated TLS library used in billions of embedded and
server deployments.  `wolfcrypt-tls` gives you:

- **FIPS 140-3** — TLS with a validated crypto backend for regulated
  environments (commercial license required;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **Small footprint** — designed for embedded targets alongside full server
  deployments; a single dependency chain, no OpenSSL
- **Familiar Rust API** — `TlsClient`/`TlsServer` types that wrap standard
  `std::io::Read + Write` streams

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

## How it works

```text
wolfssl-src      Compiles wolfSSL C source via the cc crate
      │
wolfcrypt-sys    bindgen FFI bindings to wolfSSL
      │
wolfcrypt-rs     Typed Rust wrapper
      │
wolfcrypt-tls    Safe TlsClient / TlsServer API (this crate)
                 Exported as lib.name = "wolfssl"
```

The crate wraps `WOLFSSL_CTX` and `WOLFSSL` session objects in RAII types and
maps wolfSSL return codes to `Result`.  I/O is delegated to the caller's stream
via wolfSSL's custom I/O callbacks, so any `Read + Write` type works as the
underlying transport.

## Features

| Feature | Description |
|---------|-------------|
| `vendored` | Compile wolfSSL from source (requires `WOLFSSL_SRC` or pkg-config) |
| `fips` | Enable the wolfSSL FIPS 140-3 code path |

FIPS 140-3 validated builds require a wolfSSL commercial license and the
validated source tree.  [Contact wolfSSL](https://www.wolfssl.com/license/)
for a commercial FIPS license.  See the
[workspace README](https://github.com/wolfSSL/wolfssl-rs) for details.

## Status

- TLS 1.2 and TLS 1.3
- Blocking I/O (async support planned)
- Unix and Windows socket support

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

MIT — see [LICENSE](LICENSE).

The [MIT License](https://opensource.org/licenses/MIT) applies to the Rust
source code in this crate.  The underlying wolfSSL C library is licensed under
GPL-2.0-or-later with a commercial option available from
[wolfSSL Inc.](https://www.wolfssl.com/license/)
