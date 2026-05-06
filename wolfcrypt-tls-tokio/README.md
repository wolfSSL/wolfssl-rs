# wolfcrypt-tls-tokio

Async TLS for [tokio](https://tokio.rs) backed by [wolfSSL](https://wolfssl.com).

`TlsStream<IO>` implements `tokio::io::AsyncRead + AsyncWrite` over any async
transport. The API mirrors `tokio-rustls` so existing code can drop in with
minimal changes.

> **Status**: in active development. The crate is published to reserve the
> namespace. The async engine is not yet complete — do not use in production.
> Track progress in the [issue tracker](https://github.com/wolfSSL/wolfssl-rs).

## Why

wolfSSL is a FIPS 140-3 validated TLS library. `wolfcrypt-tls-tokio` brings
that to async Rust:

- **FIPS 140-3** — the only async Rust TLS crate backed by a validated crypto
  module, for regulated environments (commercial license required;
  [contact wolfSSL](https://www.wolfssl.com/license/))
- **tokio-rustls compatible API** — same connector/acceptor/stream shapes;
  swap the import and adjust the config builder
- **Pure async IO** — uses wolfSSL custom IO callbacks, not `wolfSSL_set_fd`;
  works over any `AsyncRead + AsyncWrite + Unpin` transport including
  `tokio::io::duplex`, Unix domain sockets, and plain TCP
- **No spawn_blocking** — the async bridge is zero-thread-overhead; one
  `TlsStream` does not consume one OS thread

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
let connector = TlsConnector::from(config);
let mut tls = connector.connect("example.com", stream).await?;
// tls: TlsStream<TcpStream> — implements AsyncRead + AsyncWrite

tokio::io::AsyncWriteExt::write_all(
    &mut tls,
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
).await?;
```

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
        let mut tls = acceptor.accept(stream).await?;
        // tls: TlsStream<TcpStream> — implements AsyncRead + AsyncWrite
        Ok::<_, Box<dyn std::error::Error>>(())
    });
}
```

### tokio::io::split

Because `TlsStream<IO>` implements both `AsyncRead` and `AsyncWrite`, it works
with `tokio::io::split` out of the box:

```rust
let (mut reader, mut writer) = tokio::io::split(tls);
```

## How it works

```text
wolfssl-src            Compiles wolfSSL C source
      │
wolfcrypt-sys          bindgen FFI bindings
      │
wolfcrypt-tls          Config types, cert/key loading (lib name: wolfssl)
      │
wolfcrypt-tls-tokio    Async IO bridge + TlsStream + connector/acceptor (this crate)
      │
tokio                  AsyncRead, AsyncWrite, TcpStream
```

Instead of `wolfSSL_set_fd`, this crate uses wolfSSL's **custom IO callback**
mechanism. Two `extern "C"` callbacks (`recv_cb`, `send_cb`) operate on
in-memory byte buffers rather than a file descriptor:

```text
                    ┌────────────────────────────────────┐
                    │          TlsStream<IO>             │
caller              │                                    │
AsyncRead  ◄────────┤  read_buf      write_buf  ────────►│  AsyncWrite
           (plain)  │                           (plain)  │
                    │        WOLFSSL session              │
                    │  recv_cb ◄── net_in                 │
                    │  send_cb ──► net_out                │
                    │                                    │
network IO ◄────────┤  flush net_out    fill net_in ─────►│  network IO
           (cipher) │                             (cipher)│
                    └────────────────────────────────────┘
```

The callbacks never block and never return `WANT_READ`/`WANT_WRITE` — they
succeed immediately against the in-memory buffers. All real async network I/O
happens in `poll_read`/`poll_write` before and after calling into wolfSSL.
This is the same approach used by `tokio-rustls`.

## Relationship to `wolfcrypt-tls`

Config types (`TlsClientConfig`, `TlsServerConfig`, `Certificate`,
`PrivateKey`, `RootCertStore`, `ProtocolVersion`) are re-exported from
`wolfcrypt-tls`. There is no duplication of cert/key loading logic. Both
crates can coexist in the same binary: use `wolfcrypt-tls` for blocking I/O
and `wolfcrypt-tls-tokio` for async I/O with the same config objects.

## Features

| Feature | Description |
|---------|-------------|
| `vendored` | Compile wolfSSL from source (passes through to `wolfcrypt-tls`) |
| `fips` | Enable the wolfSSL FIPS 140-3 code path |

## Future work

- **DTLS** — the buffer architecture generalises to DTLS with MTU-aware
  chunking; planned for v0.2
- **Session resumption** — `wolfSSL_get_session` / `wolfSSL_set_session`
  session cache; planned for v0.2
- **Namespace** — once `wolfssl` is recovered on crates.io this crate will
  be renamed to `wolfssl-tokio` with `lib.name = "wolfssl_tokio"`

## Copyright

Copyright (C) 2006-2026 wolfSSL Inc.

## License

GPL-3.0-only OR LicenseRef-wolfSSL-commercial — see [LICENSE](LICENSE).

The underlying wolfSSL C library is licensed under GPL-2.0-or-later with a
commercial option available from [wolfSSL Inc.](https://www.wolfssl.com/license/)
