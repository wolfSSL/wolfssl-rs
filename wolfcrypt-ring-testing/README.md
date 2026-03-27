# wolfcrypt-ring-testing

Test suite and benchmarks for `wolfcrypt-ring-compat`. Runs ring's own test vectors against the wolfCrypt backend to verify API parity.

## Running tests

```
WOLFSSL_SRC=/path/to/wolfssl \
cargo test -p wolfcrypt-ring-testing
```

## Benchmarks

```
WOLFSSL_SRC=/path/to/wolfssl \
cargo bench -p wolfcrypt-ring-testing
```

Compare against ring with `--features ring-benchmarks` and against OpenSSL with `--features openssl-benchmarks`.

## License

MIT
