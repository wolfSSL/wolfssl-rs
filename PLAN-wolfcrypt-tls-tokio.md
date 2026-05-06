# PLAN: wolfcrypt-tls-tokio

Async TLS for Rust backed by wolfSSL, targeting `tokio::io::AsyncRead + AsyncWrite`.

## Why this crate exists

`wolfcrypt-tls` provides blocking `Read + Write` TLS via `wolfSSL_set_fd` —
it hands wolfSSL a raw file descriptor and lets the C library drive I/O
directly. This works for `std::net::TcpStream` but is fundamentally
incompatible with async runtimes: tokio sockets cannot safely expose a raw fd
to a C library that will call `read(2)`/`write(2)` on it while the tokio
executor is also managing that fd.

`wolfcrypt-tls-tokio` solves this by switching to wolfSSL's **custom IO
callback** mechanism (`wolfSSL_CTX_SetIORecv` / `wolfSSL_CTX_SetIOSend`)
instead of `wolfSSL_set_fd`. The callbacks are wired to an internal byte
buffer that tokio fills asynchronously, completely decoupling wolfSSL's
synchronous C calls from the async executor.

The eventual published crate name is `wolfssl-tokio`, mirroring
`tokio-rustls`. Until the `wolfssl` namespace is recovered from crates.io,
this lives as `wolfcrypt-tls-tokio` in this workspace.

## Target API

Model the public surface on `tokio-rustls` so users can drop in:

```rust
// Client
let connector = TlsConnector::from(Arc::new(config));
let stream = TcpStream::connect(addr).await?;
let tls = connector.connect("example.com".try_into()?, stream).await?;
// tls: TlsStream<TcpStream> — implements AsyncRead + AsyncWrite

// Server
let acceptor = TlsAcceptor::from(Arc::new(config));
let (stream, _peer) = listener.accept().await?;
let tls = acceptor.accept(stream).await?;
```

`TlsStream<IO>` implements:
- `tokio::io::AsyncRead`
- `tokio::io::AsyncWrite`
- `tokio::io::split` (via the standard split on `AsyncRead + AsyncWrite`)

Config types (`TlsClientConfig`, `TlsServerConfig`) are re-exported from
`wolfcrypt-tls` — no duplication of cert/key loading logic.

## Architecture

```
wolfcrypt-sys          FFI bindings (existing)
      │
wolfcrypt-tls          Config types, cert/key loading, TlsClientConfig,
      │                TlsServerConfig (existing — reused, not duplicated)
      │
wolfcrypt-tls-tokio    Async IO bridge + TlsStream + connector/acceptor (new)
      │
tokio                  AsyncRead, AsyncWrite, TcpStream
```

### The IO bridge (the hard part)

wolfSSL's C API is synchronous. The custom IO callbacks are `extern "C" fn`
— you cannot `.await` inside them. The bridge solves this with two internal
ring buffers:

```
         ┌─────────────────────────────────────────┐
         │             TlsStream<IO>                │
         │                                          │
  app    │   read_buf: BytesMut   write_buf: BytesMut│
  ──────►│   (decrypted, ready    (encrypted, to    │──────► network IO
         │    for caller)          be flushed)       │
         │                                          │
         │          WOLFSSL session                  │
         │   ┌──────────────────────────────┐       │
         │   │ recv_cb reads from           │       │
         │   │   net_in: BytesMut           │       │
         │   │ send_cb writes to            │       │
         │   │   net_out: BytesMut          │       │
         │   └──────────────────────────────┘       │
         └─────────────────────────────────────────┘
```

Four buffers total:
- `net_in`: encrypted bytes read from the network, waiting for wolfSSL to
  consume via the recv callback
- `net_out`: encrypted bytes wolfSSL has produced, waiting to be flushed to
  the network via the send callback
- `read_buf`: decrypted application data wolfSSL has produced, ready for the
  caller's `poll_read`
- `write_buf`: application data the caller has given us, waiting to be fed to
  wolfSSL via `wolfSSL_write`

The recv/send callbacks never block and never return WANT_READ/WANT_WRITE to
wolfSSL — they always succeed immediately against the in-memory buffers. All
actual async network I/O happens in the `poll_read` / `poll_write` driver
before and after calling into wolfSSL.

### poll_read flow

```
poll_read(cx, buf):
  1. If read_buf is non-empty, drain into buf and return Ready.
  2. Poll the underlying IO to fill net_in.
     If Pending, register waker and return Pending.
  3. Call wolfSSL_read into read_buf until WANT_READ or data available.
     (recv callback draws from net_in; send callback appends to net_out)
  4. Flush net_out to underlying IO (best-effort; may leave bytes for
     next poll_write).
  5. If read_buf non-empty, drain into buf and return Ready.
     Else return Pending.
```

### poll_write flow

```
poll_write(cx, buf):
  1. Feed buf to wolfSSL_write.
     (send callback appends to net_out)
  2. Poll the underlying IO to flush net_out.
     If Pending, register waker, but return Ready(n) — wolfSSL accepted
     the bytes even if the network write is pending.
  3. Return Ready(bytes consumed by wolfSSL_write).

poll_flush(cx):
  1. Poll the underlying IO to flush all of net_out.
  2. Return Ready when net_out is empty.
```

### Handshake

The connect/accept futures drive `wolfSSL_connect` / `wolfSSL_accept` in a
loop, advancing the same buffer machinery, until the call returns
`WOLFSSL_SUCCESS` or a fatal error.

```rust
pub struct Connect<IO> {
    state: Option<TlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = Result<TlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let stream = self.state.as_mut().unwrap();
        loop {
            // fill net_in from IO
            ready!(stream.fill_net_in(cx))?;
            let ret = unsafe { wolfSSL_connect(stream.ssl) };
            // flush net_out to IO
            ready!(stream.flush_net_out(cx))?;
            match ret {
                WOLFSSL_SUCCESS => return Poll::Ready(Ok(self.state.take().unwrap())),
                _ => {
                    let err = unsafe { wolfSSL_get_error(stream.ssl, ret) };
                    match err {
                        WANT_READ | WANT_WRITE => continue,
                        _ => return Poll::Ready(Err(...)),
                    }
                }
            }
        }
    }
}
```

## File structure

```
wolfcrypt-tls-tokio/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs          — public API, re-exports
│   ├── stream.rs       — TlsStream<IO>: AsyncRead + AsyncWrite, buffer machinery
│   ├── bridge.rs       — wolfSSL custom IO callback registration and shims
│   ├── connector.rs    — TlsConnector, Connect future
│   ├── acceptor.rs     — TlsAcceptor, Accept future
│   └── error.rs        — async-specific error types (wraps wolfcrypt-tls errors)
└── tests/
    ├── client_server.rs — loopback TLS handshake test (tokio::io::duplex)
    ├── tls12.rs         — TLS 1.2 specific
    └── tls13.rs         — TLS 1.3 specific
```

## Cargo.toml sketch

```toml
[package]
name = "wolfcrypt-tls-tokio"
version = "0.1.0"
edition = "2021"
description = "Async TLS backed by wolfSSL — tokio AsyncRead/AsyncWrite"
license = "GPL-3.0-only OR LicenseRef-wolfSSL-commercial"

# Future: rename to wolfssl-tokio once namespace is recovered.

[dependencies]
wolfcrypt-tls  = { path = "../wolfcrypt-tls" }
wolfcrypt-sys  = { path = "../wolfcrypt-sys" }
tokio          = { version = "1", features = ["io-util", "net", "rt"] }
bytes          = "1"

[dev-dependencies]
tokio          = { version = "1", features = ["full"] }
tokio-test     = "0.4"
```

## What is NOT duplicated from wolfcrypt-tls

- `TlsClientConfig` / `TlsServerConfig` — re-exported as-is
- `Certificate`, `PrivateKey`, `RootCertStore` — re-exported as-is
- `ProtocolVersion` — re-exported as-is
- `ensure_init()` — called internally, not re-exported

The WOLFSSL_CTX creation and cert/key loading stays in `wolfcrypt-tls`.
This crate only owns the async IO layer and session lifecycle.

## Key design decisions

**Why custom IO callbacks instead of `wolfSSL_set_fd`?**
Tokio sockets cannot be shared with a C library doing raw syscalls. The
callback approach fully decouples wolfSSL's sync C calls from the async
executor. This is the same reason `tokio-rustls` uses rustls's internal
buffer API rather than handing rustls a raw fd.

**Why not `spawn_blocking`?**
Running wolfSSL on a blocking thread avoids the async bridge complexity but
doesn't scale — one blocking thread per TLS connection. Fine for a prototype,
wrong for production. We build the bridge correctly from the start.

**Why four buffers and not two?**
wolfSSL does not expose its internal TLS record buffer. We need `net_in` to
give the recv callback something to return immediately (instead of blocking),
and `net_out` to capture what the send callback produces. `read_buf` and
`write_buf` are the application-visible sides. Two buffers would collapse
network and application data into the same region, creating ordering hazards
during renegotiation or key updates.

**Why not implement `tokio::net::TcpStream`-specific shortcuts?**
`TlsStream<IO>` is generic over any `AsyncRead + AsyncWrite + Unpin`. This
lets it work over `tokio::io::duplex` (in tests), Unix domain sockets, DTLS
transports, and any future IO type. TCP-specific shortcuts can be added later
as `impl TlsStream<TcpStream>` extensions.

**`Unpin` requirement**
Required because we need to call `poll_read`/`poll_write` on `IO` from within
our own `poll_read`/`poll_write` implementations without going through
`Pin::new_unchecked`. All tokio socket types are `Unpin`.

## Open questions / future work

- **DTLS**: The same buffer architecture works for DTLS but needs MTU-aware
  chunking in `net_in`/`net_out`. Defer to v0.2.
- **Session resumption**: `wolfSSL_get_session` / `wolfSSL_set_session` can
  be wired into a session cache. Defer to v0.2.
- **`tokio::io::split`**: Works automatically via the blanket impl on
  `AsyncRead + AsyncWrite`. No special work needed.
- **`AsyncRead` / `AsyncWrite` for `&mut TlsStream`**: Standard blanket impls
  handle this.
- **Zero-copy**: The buffer copies are unavoidable given wolfSSL's C API
  boundary. A future version could explore `wolfSSL_read_internal` or similar
  if wolfSSL exposes record-layer access.
- **Namespace**: When `wolfssl` is recovered on crates.io, rename package to
  `wolfssl-tokio`, set `lib.name = "wolfssl_tokio"`, and publish. The source
  stays identical.
