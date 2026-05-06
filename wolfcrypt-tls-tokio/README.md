# wolfcrypt-tls-tokio

Async TLS for [tokio](https://tokio.rs) backed by [wolfSSL](https://wolfssl.com).
`TlsStream<IO>` implements `tokio::io::AsyncRead + AsyncWrite`.

## Why

The same reasons to choose `wolfcrypt-tls` for blocking I/O apply here — FIPS
140-3 validation, small footprint, no OpenSSL — but for async Rust with tokio:

- **FIPS 140-3** — the only async tokio TLS crate backed by a FIPS-validated
  crypto module (commercial license;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **tokio-rustls-compatible API** — `TlsConnector` / `TlsAcceptor` /
  `TlsStream<IO>` have the same shapes; swap the import and adjust the config
  builder
- **No `spawn_blocking`** — wolfSSL runs inline in the async task over
  in-memory buffers; one connection does not consume one OS thread

## Usage

```toml
[dependencies]
wolfcrypt-tls-tokio = "0.1"
tokio = { version = "1", features = ["full"] }
```

### TLS client

```rust
use std::sync::Arc;
use tokio::net::TcpStream;
use wolfssl_tokio::{TlsConnector, TlsClientConfig, RootCertStore};

let mut roots = RootCertStore::new();
roots.add_pem(include_bytes!("ca.pem"));

let config = Arc::new(
    TlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
        .build()?,
);

let stream = TcpStream::connect("example.com:443").await?;
let mut tls = TlsConnector::from(config).connect("example.com", stream)?.await?;
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
```

`connect()` returns `Result<Connect<IO>>`; the `?` checks for config errors and
the `.await?` drives the handshake to completion.

### TLS server

```rust
use std::sync::Arc;
use tokio::net::TcpListener;
use wolfssl_tokio::{TlsAcceptor, TlsServerConfig, Certificate, PrivateKey};

let config = Arc::new(
    TlsServerConfig::builder()
        .with_certificate_chain(
            Certificate::from_pem(include_bytes!("server.pem")),
            PrivateKey::from_pem(include_bytes!("server-key.pem")),
        )
        .with_no_client_auth()
        .build()?,
);

let acceptor = TlsAcceptor::from(config);
let listener = TcpListener::bind("0.0.0.0:443").await?;

loop {
    let (stream, _addr) = listener.accept().await?;
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
        let mut tls = acceptor.accept(stream)?.await?;
        // tls: TlsStream<TcpStream> — AsyncRead + AsyncWrite
        Ok::<_, wolfssl_tokio::Error>(())
    });
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

## How it works

```text
wolfssl-src            Compiles wolfSSL C source
      │
wolfcrypt-sys          bindgen FFI bindings
      │
wolfcrypt-tls          Config types, cert/key loading  (lib.name = "wolfssl")
      │
wolfcrypt-tls-tokio    TlsConnector / TlsAcceptor / TlsStream  ← this crate
      │
tokio                  AsyncRead, AsyncWrite, TcpStream
```

Instead of `wolfSSL_set_fd`, the crate drives wolfSSL through custom IO
callbacks over two in-memory byte buffers (`net_in` / `net_out`):

```text
                    ┌───────────────────────────────────┐
                    │         TlsStream<IO>              │
 poll_read  ◄───────┤  read_buf (decrypted plaintext)    │
 poll_write ───────►│  wolfSSL session                   │
                    │    recv_cb ◄── net_in              │
                    │    send_cb ──► net_out             │
 network IO ◄───────┤  flush net_out / fill net_in ─────►│  network IO
   (cipher)         └───────────────────────────────────┘   (cipher)
```

The callbacks are synchronous and never block. All real async network I/O
happens in `poll_read` / `poll_write` around the wolfSSL calls — the same
architecture as `tokio-rustls`.

Config types (`TlsClientConfig`, `TlsServerConfig`, `Certificate`,
`PrivateKey`, `RootCertStore`, `ProtocolVersion`) are re-exported from
`wolfcrypt-tls`. The `wolfcrypt-tls-futures-io` crate provides the same
session logic for the `futures::io` trait family (smol, async-std).

| Feature    | Description |
|------------|-------------|
| `vendored` | Compile wolfSSL from source (passes through to `wolfcrypt-tls`) |
| `fips`     | Enable the wolfSSL FIPS 140-3 code path (commercial license required) |

## References

- [wolfSSL documentation](https://www.wolfssl.com/documentation/)
- [wolfcrypt-tls](../wolfcrypt-tls) — blocking API and config types
- [wolfcrypt-tls-futures-io](../wolfcrypt-tls-futures-io) — futures::io variant
- [workspace README](https://github.com/wolfSSL/wolfssl-rs)

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial — see [LICENSE](LICENSE).

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
