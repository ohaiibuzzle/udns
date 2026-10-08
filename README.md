# udns

A small ad-blocking DNS forwarder for low-RAM routers (OpenWRT x86_64/arm64).

- Serves plain DNS (UDP + TCP), DNS-over-TLS, DNS-over-QUIC and DNS-over-HTTPS, each toggled in the config.
- DoH can run over plain HTTP (HTTP/1.1 and h2c), so it can sit behind a reverse proxy.
- Blocks domains from one or more blocklists (URLs or files) and answers NXDOMAIN. Each entry blocks the domain and all of its subdomains. Domains in `allow` (and their subdomains) are never blocked.
- Forwards everything else, through a TTL cache, to the machine's own DNS servers (`/etc/resolv.conf`) by default, or to configured UDP, DoT or DoH upstreams.
- `GET /` returns `ok` (health check). The optional `GET /stats` returns counters as JSON.

## Build

```sh
cargo build --release          # local
cargo test
```

Static binaries (needs [zig](https://ziglang.org) 0.15.2 and `cargo install cargo-zigbuild`):

```sh
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
# mips/mipsel are tier 3: nightly + build-std, and non-PIE (static-PIE mips crashes)
RUSTFLAGS="-C relocation-model=static" cargo +nightly zigbuild -Zbuild-std=std,panic_abort --release --target mipsel-unknown-linux-musl
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests, then builds every target below and runs `ci/smoke.sh` on each binary (under qemu-user for non-x86). `ci/smoke.sh [binary]` also works locally. `ci/package.sh` turns one binary into the packages.

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

Every run keeps the binaries, packages (`packages` artifact, with `SHA256SUMS`) and the Docker image (`docker-image`, an OCI archive) as build artifacts. Pushing a tag `vX.Y.Z` (it must match the `Cargo.toml` version) also creates a GitHub release with the packages and pushes `ghcr.io/ohaiibuzzle/udns:vX.Y.Z` and `:latest`.

## Install

- **OpenWRT 25.x (apk):** `apk add --allow-untrusted udns_*_openwrt_<cpu>.apk` (the packages are not signed).
- **OpenWRT 24.10 and older (opkg):** `opkg install udns_*_openwrt_<cpu>.ipk`.
- **Entware:** `opkg install udns_*_<arch>.ipk`, then `/opt/etc/init.d/S55udns start`. Config is `/opt/etc/udns.toml`.
- **Docker:** `docker run -d -p 53:53/udp -p 53:53/tcp -v ./udns.toml:/etc/udns.toml ghcr.io/ohaiibuzzle/udns`. Without a mounted config it uses `config.example.toml`.
- **Standalone:** `udns-<version>-<rust-target>` from the release.

The binaries are static, so one OpenWRT package covers every subtarget of a CPU family. Pick the one matching your CPU (`<cpu>` in the table). The packages are marked `all`/`noarch`, so opkg/apk will not stop you from installing the wrong one.

The OpenWRT and Entware packages ship a config that listens on `127.0.0.1:5354`, next to dnsmasq (see below). OpenWRT enables and starts the service on install.

## Run

```sh
udns /etc/udns.toml
```

See `config.example.toml` for every option. Logs go to stderr.

The blocklist is downloaded after the listeners start, so a router that resolves through udns itself can still fetch it. If the download fails, udns retries every minute. Set `cache_file` so the last list is used immediately after a reboot.

## OpenWRT notes

- dnsmasq already listens on port 53. Either move dnsmasq to another port (`uci set dhcp.@dnsmasq[0].port='0'` disables its DNS), or run udns on another port and point dnsmasq at it (`list server '127.0.0.1#5354'`).
- With no `[upstream]` servers, set `resolv_conf = "/tmp/resolv.conf.d/resolv.conf.auto"` (the WAN DNS servers). `/etc/resolv.conf` points at 127.0.0.1, and udns skips nameservers that are itself. The file is read once at startup, so restart udns if the WAN DNS servers change.
- The package installs the procd init script `openwrt/udns.init` as `/etc/init.d/udns`. Logs show up in `logread`.
- DoT, DoQ and DoH-over-TLS need a certificate and key in PEM format (e.g. from acme.sh).

## Testing it

```sh
dig @127.0.0.1 -p 53 example.com
dig +tcp @127.0.0.1 -p 53 example.com
curl -s http://127.0.0.1:8053/stats
curl -s 'http://127.0.0.1:8053/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' | xxd
```

`kdig` (knot) or Python's dnspython cover DoT/DoQ (`kdig +tls`, `kdig +quic`).

## Known limits

- Answers are rebuilt from the upstream records, so upstream DNSSEC flags (AD) are not passed through.
- CNAME targets are not checked against the blocklist (only the queried name).
- Queries on one TCP/DoT connection are answered one at a time.
- No ARMv5 (e.g. kirkwood) build: zig's musl does not build for ARMv5. The mips builds need MIPS32r2 (ath79, ramips, most mips routers), not the older MIPS32r1.
- On Entware, `rc.func` sends output to `/dev/null`, so udns logs are not kept.
