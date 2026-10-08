# udns

A small ad-blocking DNS forwarder for low-RAM routers (OpenWRT x86_64/arm64).

- Serves plain DNS (UDP + TCP), DNS-over-TLS, DNS-over-QUIC and DNS-over-HTTPS, each toggled in the config.
- DoH can run over plain HTTP (HTTP/1.1 and h2c), so it can sit behind a reverse proxy.
- Blocks domains from one blocklist (URL or file) and answers NXDOMAIN. Each entry blocks the domain and all of its subdomains.
- Forwards everything else, through a TTL cache, to the machine's own DNS servers (`/etc/resolv.conf`) by default, or to configured UDP, DoT or DoH upstreams.
- `GET /` returns `ok` (health check). The optional `GET /stats` returns counters as JSON.

## Build

```sh
cargo build --release          # local
cargo test
```

Static binaries for OpenWRT (needs [zig](https://ziglang.org) and `cargo install cargo-zigbuild`):

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, both musl builds (zig 0.17.0), and `ci/smoke.sh` against the x86_64 binary. The binaries are uploaded as build artifacts. `ci/smoke.sh [binary]` also works locally.

## Run

```sh
udns /etc/udns.toml
```

See `config.example.toml` for every option. Logs go to stderr.

The blocklist is downloaded after the listeners start, so a router that resolves through udns itself can still fetch it. If the download fails, udns retries every minute. Set `cache_file` so the last list is used immediately after a reboot.

## OpenWRT notes

- dnsmasq already listens on port 53. Either move dnsmasq to another port (`uci set dhcp.@dnsmasq[0].port='0'` disables its DNS), or run udns on another port and point dnsmasq at it (`list server '127.0.0.1#5354'`).
- With no `[upstream]` servers, set `resolv_conf = "/tmp/resolv.conf.d/resolv.conf.auto"` (the WAN DNS servers). `/etc/resolv.conf` points at 127.0.0.1, and udns skips nameservers that are itself. The file is read once at startup, so restart udns if the WAN DNS servers change.
- No procd init script is included yet.
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
