# Nodomi Agent

Nodomio is the source repository for Nodomi Agent, a Linux host metrics collector written in Rust.

## Build and run

Use Linux on x86-64 or ARM64, Rust 1.91.1, and a C compiler. With rustup, the toolchain file in `agent/` selects the Rust version.

```sh
cd agent
cargo build --locked --release --bin nodomi-agent
./target/release/nodomi-agent --samples 2 --interval-ms 1000
```

The diagnostic prints local samples as JSON lines.

## Test

Install Python 3 and OpenSSL 3. From `agent/` in a fresh checkout, generate the loopback TLS fixtures and run the test suite.

```sh
./tests/generate-loopback-tls.sh
cargo test --locked
```

The generated certificates are valid for seven days. To refresh them, remove the generated `tests/fixtures/tls/` directory and rerun the script.
