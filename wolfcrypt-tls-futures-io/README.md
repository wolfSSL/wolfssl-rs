# wolfcrypt-tls-futures-io

Async TLS for [smol](https://github.com/smol-rs/smol), [async-std](https://async.rs),
and any other runtime using [futures::io](https://docs.rs/futures-io), backed by
[wolfSSL](https://wolfssl.com).

`TlsStream<IO>` implements `futures::io::AsyncRead + AsyncWrite` over any
compatible async transport. The API mirrors `futures-rustls` so existing code
can drop in with minimal changes.

For tokio users, use [`wolfcrypt-tls-tokio`](../wolfcrypt-tls-tokio) instead.
If you need to bridge between the two trait families, `tokio-util`'s `Compat`
wrapper works well.

## Why

wolfSSL is a FIPS 140-3 validated TLS library. `wolfcrypt-tls-futures-io` brings
that to async Rust outside the tokio ecosystem:

- **FIPS 140-3** — TLS with a validated crypto backend for regulated environments
  (commercial license required;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **futures-rustls compatible API** — same connector/acceptor/stream shapes
- **Pure async IO** — uses wolfSSL custom IO callbacks, not `wolfSSL_set_fd`;
  works over any `futures::io::AsyncRead + AsyncWrite + Unpin` transport
- **No spawn_blocking** — the wolfSSL state machine runs inline in the async
  task; no OS thread is consumed per connection

## Usage

```toml
[dependencies]
wolfcrypt-tls-futures-io = "0.1"
smol = "2"          # or async-std, async-executor, etc.
```

### TLS client

```rust
use std::sync::Arc;
use async_io::Async;
use std::net::TcpStream;
use wolfssl_futures_io::{TlsConnector, TlsClientConfig, RootCertStore};

let mut roots = RootCertStore::new();
roots.add_pem(include_bytes!("ca.pem"));

let config = Arc::new(
    TlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
        .build()?,
);

let stream = Async::<TcpStream>::connect("example.com:443").await?;
let connector = TlsConnector::from(config);
let mut tls = connector.connect("example.com", stream)?.await?;
// tls: TlsStream<Async<TcpStream>> — implements AsyncRead + AsyncWrite

tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
```

`connect()` returns `Result<Connect<IO>>`, where `Connect<IO>` is the
handshake future. The `?` after `connect()` checks for config errors; the
subsequent `.await?` drives the handshake to completion.

### TLS server

```rust
use std::sync::Arc;
use async_io::Async;
use std::net::{TcpListener, TcpStream};
use wolfssl_futures_io::{TlsAcceptor, TlsServerConfig, Certificate, PrivateKey};

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
let listener = Async::<TcpListener>::bind("0.0.0.0:443")?;

loop {
    let (stream, _addr) = listener.accept().await?;
    let acceptor = acceptor.clone();
    smol::spawn(async move {
        let mut tls = acceptor.accept(stream)?.await?;
        // tls: TlsStream<Async<TcpStream>> — implements AsyncRead + AsyncWrite
        Ok::<_, wolfssl_futures_io::Error>(())
    }).detach();
}
```

### Mutual TLS (mTLS)

```rust
use wolfssl_futures_io::{RootCertStore, Certificate, PrivateKey};

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

### Inspecting the negotiated version

```rust
use wolfssl_futures_io::ProtocolVersion;

if let Some(version) = tls.negotiated_version() {
    match version {
        ProtocolVersion::Tls12 => println!("TLS 1.2"),
        ProtocolVersion::Tls13 => println!("TLS 1.3"),
        _ => {}
    }
}
```

## How it works

```text
wolfssl-src                 Compiles wolfSSL C source
      │
wolfcrypt-sys               bindgen FFI bindings
      │
wolfcrypt-tls               Config types, cert/key loading  (lib name: wolfssl)
      │
wolfcrypt-tls-futures-io    Async IO bridge + TlsStream      (this crate)
      │
futures-io                  AsyncRead, AsyncWrite
```

Instead of `wolfSSL_set_fd`, this crate uses wolfSSL's **custom IO callback**
mechanism. Two callbacks (`recv_cb`, `send_cb`) operate on in-memory byte
buffers (`net_in` / `net_out`) rather than a file descriptor:

```text
                    ┌─────────────────────────────────────┐
                    │           TlsStream<IO>              │
 poll_read  ◄───────┤  read_buf  (decrypted plaintext)     │
 poll_write ───────►│  wolfSSL session                     │
                    │    recv_cb ◄── net_in                │
                    │    send_cb ──► net_out               │
 network IO ◄───────┤  flush net_out   fill net_in ───────►│  network IO
  (cipher)          │                             (cipher) │
                    └─────────────────────────────────────┘
```

The callbacks operate synchronously on the in-memory buffers and never block.
All real async network I/O happens in `poll_read` / `poll_write` around the
wolfSSL calls. This is the same architecture used by `futures-rustls`.

### Difference from `wolfcrypt-tls-tokio`

The only difference between the two async crates is the IO trait family:

| Crate                      | IO traits                               |
|----------------------------|-----------------------------------------|
| `wolfcrypt-tls-tokio`      | `tokio::io::AsyncRead + AsyncWrite`     |
| `wolfcrypt-tls-futures-io` | `futures::io::AsyncRead + AsyncWrite`   |

The handshake logic, buffer architecture, and wolfSSL wiring are identical.
Both crates re-export the same config types from `wolfcrypt-tls`.

If you need to use a `wolfcrypt-tls-futures-io` `TlsStream` with tokio (or
vice versa), wrap the underlying IO type with `tokio_util::compat::TokioAsyncReadCompatExt`.

## Relationship to `wolfcrypt-tls`

Config types (`TlsClientConfig`, `TlsServerConfig`, `Certificate`,
`PrivateKey`, `RootCertStore`, `ProtocolVersion`) are re-exported from
`wolfcrypt-tls`. There is no duplication of cert/key loading logic. All three
crates can coexist in the same binary.

## Features

| Feature    | Description |
|------------|-------------|
| `vendored` | Compile wolfSSL from source (passes through to `wolfcrypt-tls`) |
| `fips`     | Enable the wolfSSL FIPS 140-3 code path |

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial — see [LICENSE](LICENSE).

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
