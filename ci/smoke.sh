#!/bin/sh
# Smoke test: start udns with two one-line local blocklists and an allowlist, and query it over
# plain-HTTP DoH. Needs curl, od and working system DNS (/etc/resolv.conf).
# Usage: ci/smoke.sh [path/to/udns]
set -eu

BIN=${1:-target/release/udns}
DIR=$(mktemp -d)
printf '*.blocked.example\n' > "$DIR/list.txt"
printf 'example.org\n' > "$DIR/list2.txt"
# No [upstream]: udns uses this machine's /etc/resolv.conf.
cat > "$DIR/udns.toml" <<EOF
[blocklist]
sources = ["$DIR/list.txt", "$DIR/list2.txt"]
allow = ["www.example.org"]
[dns]
enabled = true
listen = ["127.0.0.1:5354"]
[doh]
enabled = true
listen = ["127.0.0.1:8053"]
stats_path = "/stats"
EOF

"$BIN" "$DIR/udns.toml" &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$DIR"' EXIT

# Wait until both blocklists (loaded in the background) are in place.
i=0
until curl -sf http://127.0.0.1:8053/stats | grep -q '"blocklist_entries":2'; do
    i=$((i + 1))
    if [ $i -gt 50 ]; then
        echo "FAIL: udns did not start or load the blocklist"
        exit 1
    fi
    sleep 0.2
done

[ "$(curl -s http://127.0.0.1:8053/)" = "ok" ] || { echo "FAIL: health check"; exit 1; }

# Byte 3 of a DNS response = RA flag (128) + response code.
rcode_byte() {
    curl -sf "http://127.0.0.1:8053/dns-query?dns=$1" | od -An -tu1 -j3 -N1 | tr -d ' '
}
# ads.blocked.example A -> NXDOMAIN (128 + 3)
[ "$(rcode_byte AAABAAABAAAAAAAAA2FkcwdibG9ja2VkB2V4YW1wbGUAAAEAAQ)" = "131" ] || { echo "FAIL: blocked name not NXDOMAIN"; exit 1; }
# example.org A -> NXDOMAIN from the second list (128 + 3)
[ "$(rcode_byte AAABAAABAAAAAAAAB2V4YW1wbGUDb3JnAAABAAE)" = "131" ] || { echo "FAIL: second list not applied"; exit 1; }
# www.example.org A -> NOERROR: allowed, even though example.org is blocked (128 + 0)
[ "$(rcode_byte AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA29yZwAAAQAB)" = "128" ] || { echo "FAIL: allowed name was blocked"; exit 1; }
# example.com A -> NOERROR via the system's DNS (128 + 0)
[ "$(rcode_byte AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE)" = "128" ] || { echo "FAIL: example.com not resolved"; exit 1; }

echo "smoke test passed"
