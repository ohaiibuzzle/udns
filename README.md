# udns

A tiny ad-blocking DNS forwarder.

- Serves plain DNS (UDP + TCP), DNS-over-TLS, DNS-over-QUIC and DNS-over-HTTPS, forwarded from configured upstreams.
- Blocks domains from one or more blocklists (URLs or files) with NXDOMAIN.

## Build

```sh
cargo build --release
cargo test
```

Static binaries (needs [zig](https://ziglang.org) 0.15.2 (due to mipsel) and `cargo install cargo-zigbuild`):

```sh
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
# mips/mipsel 
RUSTFLAGS="-C relocation-model=static" cargo +nightly zigbuild -Zbuild-std=std,panic_abort --release --target mipsel-unknown-linux-musl
```

| CPU | Rust target | OpenWRT | Entware | Docker |
|---|---|---|---|---|
| x86_64 | `x86_64-unknown-linux-musl` | `x86_64` | `x64-3.2` | `linux/amd64` |
| i386 | `i686-unknown-linux-musl` | `i386` | | `linux/386` |
| aarch64 | `aarch64-unknown-linux-musl` | `aarch64` | `aarch64-3.10` | `linux/arm64` |
| armv7 | `armv7-unknown-linux-musleabi` | `armv7` | `armv7-3.2` | `linux/arm/v7` |
| armv6 | `arm-unknown-linux-musleabi` | `armv6` | | `linux/arm/v6` |
| mips | `mips-unknown-linux-musl` | `mips` | `mips-3.4` | |
| mipsel | `mipsel-unknown-linux-musl` | `mipsel` | `mipsel-3.4` | |
| riscv64 | `riscv64gc-unknown-linux-musl` | `riscv64` | | `linux/riscv64` |

## Install

See [Releases](https://github.com/ohaiibuzzle/udns/releases)

The binaries are static, so one OpenWRT package covers every subtarget of a CPU family. Pick the one matching your CPU (`<cpu>` in the table). The packages are marked `all`/`noarch`, so opkg/apk will not stop you from installing the wrong one.

The OpenWRT and Entware packages ship a config that listens on `127.0.0.1:5354` to prevent collision with dnsmasq

## Run

```sh
udns <config.toml>
```

See `config.example.toml` for every option.

## Known limits

- Answers are rebuilt from the upstream records, so upstream DNSSEC flags aren't forwarded
- CNAME targets are not checked.
- Queries on one TCP/DoT connection are answered one at a time.
- No ARMv5 (e.g. kirkwood) build: zig's musl does not build for ARMv5.
- On Entware, logs aren't kept. 
