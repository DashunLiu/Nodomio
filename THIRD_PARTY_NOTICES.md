# Third-party notices

The project source in this snapshot is licensed under the MIT license in [LICENSE](LICENSE). That license does not relicense third-party dependencies.

This is a source-only snapshot: it does not vendor dependency source or distribute prebuilt binaries. Cargo obtains dependencies separately. The following inventory records the published package-level license declarations for every registry package in [agent/Cargo.lock](agent/Cargo.lock), including build, development, and conditional platform dependencies. It is not a list of libraries linked into every Agent build.

Each declaration was read from the exact crate archive after checking its SHA-256 against Cargo.lock. Package source and upstream license files are available at `https://crates.io/crates/<name>/<version>`. Expressions are reproduced as published; `MIT/Apache-2.0` is legacy package metadata.

| Declared license expression | Locked packages |
| --- | --- |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | `unicode-ident 1.0.27` |
| `0BSD OR MIT OR Apache-2.0` | `adler2 2.0.1` |
| `Apache-2.0` | `sync_wrapper 1.0.2` |
| `Apache-2.0 AND ISC` | `ring 0.17.14` |
| `Apache-2.0 OR BSL-1.0` | `ryu 1.0.23` |
| `Apache-2.0 OR ISC OR MIT` | `hyper-rustls 0.27.10`, `rustls 0.23.46` |
| `Apache-2.0 OR MIT` | `atomic-waker 1.1.2`, `fastrand 2.5.0`, `idna_adapter 1.2.2`, `pin-project-lite 0.2.17`, `rustc-hash 2.1.3`, `utf8_iter 1.1.0`, `utf_types 1.0.0`, `zeroize 1.8.2` |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `linux-raw-sys 0.11.0`, `rustix 1.1.3`, `wasi 0.11.1+wasi-snapshot-preview1`, `wasip2 1.0.4+wasi-0.2.12`, `wit-bindgen 0.57.1` |
| `BSD-3-Clause` | `subtle 2.6.1` |
| `CDLA-Permissive-2.0` | `webpki-roots 1.0.11` |
| `ISC` | `rustls-webpki 0.103.16`, `untrusted 0.9.0` |
| `MIT` | `bytes 1.12.1`, `cfg_aliases 0.2.2`, `http-body 1.1.0`, `http-body-util 0.1.5`, `hyper 1.12.0`, `hyper-util 0.1.21`, `libsqlite3-sys 0.39.1`, `mio 1.2.4`, `rusqlite 0.41.1`, `simd-adler32 0.3.10`, `slab 0.4.12`, `synstructure 0.14.0`, `tokio 1.51.6`, `tower 0.5.3`, `tower-http 0.6.11`, `tower-layer 0.3.3`, `tower-service 0.3.3`, `tracing 0.1.44`, `tracing-core 0.1.36`, `try-lock 0.2.5`, `want 0.3.2` |
| `MIT OR Apache-2.0` | `base64 0.22.1`, `base64 0.23.1`, `bitflags 2.13.2`, `bumpalo 3.20.3`, `cc 1.11.1`, `cfg-if 1.0.5`, `chacha20 0.10.2`, `cpufeatures 0.3.1`, `crc32fast 1.5.5`, `deranged 0.5.9`, `displaydoc 0.2.7`, `errno 0.3.14`, `find-msvc-tools 0.1.15`, `flate2 1.1.11`, `form_urlencoded 1.2.2`, `futures-channel 0.3.34`, `futures-core 0.3.34`, `futures-io 0.3.34`, `futures-sink 0.3.34`, `futures-task 0.3.34`, `futures-util 0.3.34`, `getrandom 0.2.17`, `getrandom 0.3.4`, `getrandom 0.4.3`, `http 1.5.0`, `httparse 1.10.1`, `idna 1.1.0`, `ipnet 2.12.2`, `itoa 1.0.19`, `js-sys 0.3.107`, `libc 0.2.183`, `log 0.4.35`, `num-conv 0.2.2`, `once_cell 1.21.4`, `percent-encoding 2.3.2`, `pkg-config 0.3.34`, `powerfmt 0.2.1`, `proc-macro2 1.0.107`, `quinn 0.11.12`, `quinn-proto 0.11.19`, `quinn-udp 0.5.16`, `quote 1.0.47`, `rand 0.10.3`, `rand_core 0.10.1`, `rand_pcg 0.10.2`, `reqwest 0.12.24`, `rustls-pki-types 1.15.1`, `rustversion 1.0.23`, `serde 1.0.228`, `serde_core 1.0.228`, `serde_derive 1.0.228`, `serde_json 1.0.145`, `shlex 2.0.1`, `smallvec 1.16.5`, `socket2 0.6.5`, `stable_deref_trait 1.2.1`, `syn 2.0.119`, `syn 3.0.10`, `tempfile 3.23.0`, `thiserror 2.0.21`, `thiserror-impl 2.0.21`, `time 0.3.47`, `time-core 0.1.8`, `time-macros 0.2.27`, `tokio-rustls 0.26.6`, `url 2.5.8`, `wasm-bindgen 0.2.130`, `wasm-bindgen-futures 0.4.80`, `wasm-bindgen-macro 0.2.130`, `wasm-bindgen-macro-support 0.2.130`, `wasm-bindgen-shared 0.2.130`, `web-sys 0.3.107`, `web-time 1.1.0`, `windows-link 0.2.1`, `windows-sys 0.52.0`, `windows-sys 0.61.2`, `windows-targets 0.52.6`, `windows_aarch64_gnullvm 0.52.6`, `windows_aarch64_msvc 0.52.6`, `windows_i686_gnu 0.52.6`, `windows_i686_gnullvm 0.52.6`, `windows_i686_msvc 0.52.6`, `windows_x86_64_gnu 0.52.6`, `windows_x86_64_gnullvm 0.52.6`, `windows_x86_64_msvc 0.52.6` |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | `r-efi 5.3.0`, `r-efi 6.0.0` |
| `MIT OR Apache-2.0 OR Zlib` | `lru-slab 0.1.3` |
| `MIT OR Zlib OR Apache-2.0` | `miniz_oxide 0.9.1` |
| `MIT/Apache-2.0` | `fallible-iterator 0.3.0`, `fallible-streaming-iterator 0.1.9`, `serde_urlencoded 0.7.1`, `vcpkg 0.2.15` |
| `Unicode-3.0` | `icu_collections 2.4.0`, `icu_locale_core 2.4.0`, `icu_normalizer 2.4.0`, `icu_normalizer_data 2.4.0`, `icu_properties 2.4.0`, `icu_properties_data 2.4.0`, `icu_provider 2.4.0`, `litemap 0.8.3`, `potential_utf 0.1.6`, `tinystr 0.8.5`, `writeable 0.6.4`, `yoke 0.8.4`, `yoke-derive 0.8.4`, `zerofrom 0.1.8`, `zerofrom-derive 0.1.8`, `zerotrie 0.2.5`, `zerovec 0.11.9`, `zerovec-derive 0.11.7` |
| `Unlicense OR MIT` | `memchr 2.8.3` |
| `Zlib OR Apache-2.0 OR MIT` | `tinyvec 1.13.3` |

## Scope of this inventory

Package declarations do not replace upstream copyright notices or per-file terms. In particular, `ring` declares multiple required licenses, `unicode-ident` includes Unicode terms, `webpki-roots` declares CDLA-Permissive-2.0, and `libsqlite3-sys` can compile bundled SQLite code. Preserve and review the upstream materials relevant to any redistributed build.

No collection of dependency license texts is included in this source-only snapshot. If dependency source is later vendored or copied into the repository, preserve its applicable notices then. Before distributing binaries or containers, review the actual build's dependencies and bundled components, including compiler/runtime libraries outside Cargo.lock, and include the applicable license and attribution materials with that distribution. This inventory is not a binary-release compliance certificate.
