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

## Release candidates

The **Agent build** GitHub Actions workflow tests and builds static Linux packages on native amd64 and arm64 runners. Each candidate includes three Agent executables, systemd and OpenRC service templates, and a bundled license file. The workflow checks the contents and uploads the package with per-file verification evidence.

Publish only after reviewing both candidates from one successful run. `tools/release/publish.py` checks that run, both reviewed package digests, the exact tag and commit, and GitHub release immutability. The release manifests report the kernel version exercised for each package.
