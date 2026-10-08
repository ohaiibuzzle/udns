#!/usr/bin/env python3
"""Load-test a DoH (RFC 8484) endpoint and report per-request latency.

Example:
    scripts/doh_bench.py https://192.168.1.1/dns-query -c 32 -n 5000 --insecure --csv out.csv
"""
import argparse
import csv
import http.client
import ssl
import struct
import sys
import threading
import time
from urllib.parse import urlsplit

DEFAULT_NAMES = ["example.com", "google.com", "cloudflare.com", "github.com", "wikipedia.org"]


def build_query(name):
    # id 0 as RFC 8484 recommends (cache friendly), RD set, one question, type A, class IN.
    header = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"
    return header + qname + struct.pack(">HH", 1, 1)


def worker(url, ctx, queries, counter, lock, results, timeout):
    def connect():
        if url.scheme == "https":
            return http.client.HTTPSConnection(url.netloc, timeout=timeout, context=ctx)
        return http.client.HTTPConnection(url.netloc, timeout=timeout)

    conn = connect()
    headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
    while True:
        with lock:
            i = counter[0]
            if i >= counter[1]:
                break
            counter[0] += 1
        name, body = queries[i % len(queries)]
        start = time.perf_counter()
        try:
            conn.request("POST", url.path or "/dns-query", body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            ms = (time.perf_counter() - start) * 1000
            rcode = data[3] & 0x0F if len(data) >= 12 else -1
            ok = resp.status == 200 and rcode == 0
            results.append((start, name, ms, resp.status, rcode, ok))
        except Exception as e:
            ms = (time.perf_counter() - start) * 1000
            results.append((start, name, ms, 0, -1, False))
            print(f"error: {name}: {e}", file=sys.stderr)
            conn.close()
            conn = connect()
    conn.close()


def pct(sorted_ms, p):
    return sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * p / 100))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="DoH endpoint, e.g. https://host/dns-query")
    ap.add_argument("-c", "--concurrency", type=int, default=16, help="parallel connections (default 16)")
    ap.add_argument("-n", "--requests", type=int, default=1000, help="total requests (default 1000)")
    ap.add_argument("--names", nargs="+", default=DEFAULT_NAMES, help="domains to query, round-robin")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-request timeout in seconds")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed certs)")
    ap.add_argument("--csv", help="write every request's latency to this CSV file")
    args = ap.parse_args()

    url = urlsplit(args.url)
    if url.scheme not in ("http", "https"):
        sys.exit("url must start with http:// or https://")
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    queries = [(n, build_query(n)) for n in args.names]
    counter = [0, args.requests]  # [next index, total]
    lock = threading.Lock()
    results = []  # list.append is thread-safe in CPython

    t0 = time.perf_counter()
    threads = [
        threading.Thread(target=worker, args=(url, ctx, queries, counter, lock, results, args.timeout))
        for _ in range(args.concurrency)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - t0

    ok_ms = sorted(r[2] for r in results if r[5])
    failed = len(results) - len(ok_ms)
    print(f"requests: {len(results)}  ok: {len(ok_ms)}  failed: {failed}")
    print(f"wall: {wall:.2f}s  throughput: {len(results) / wall:.1f} req/s  concurrency: {args.concurrency}")
    if ok_ms:
        print(
            f"latency ms  min {ok_ms[0]:.2f}  avg {sum(ok_ms) / len(ok_ms):.2f}  "
            f"p50 {pct(ok_ms, 50):.2f}  p90 {pct(ok_ms, 90):.2f}  "
            f"p99 {pct(ok_ms, 99):.2f}  max {ok_ms[-1]:.2f}"
        )

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t_offset_s", "name", "latency_ms", "http_status", "rcode", "ok"])
            for start, name, ms, status, rcode, ok in sorted(results):
                w.writerow([f"{start - t0:.4f}", name, f"{ms:.3f}", status, rcode, int(ok)])
        print(f"wrote {args.csv}")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    assert build_query("a.bc")[12:] == b"\x01a\x02bc\x00\x00\x01\x00\x01"
    main()
