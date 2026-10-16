# udns

Ad-blocking DNS forwarder for low-RAM routers (≤128 MB OpenWRT). Build/target details are in README.md.

## Before calling a change done

CI runs all of these; run them locally too:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release && sh ci/smoke.sh
```

`ci/smoke.sh` binds 127.0.0.1:5354 and 127.0.0.1:8053. If it fails with "Address already in use", a stray udns is still running (`lsof -nP -iTCP:8053`).

## Config changes

Config structs use `#[serde(deny_unknown_fields)]`, so renaming a key breaks every existing config and makes udns fail at startup. When a key changes, update all of:

- `src/config.rs`
- `config.example.toml` (also shipped in the packages)
- `README.md`
- `ci/smoke.sh` (it writes its own config)

New optional keys get `#[serde(default)]` so old configs keep working.

## Style

- Boring, explicit Rust: type annotations on lets, plain loops and matches, no clever iterator chains or macros. The owner finds Rust hard to audit.
- Watch RAM: the blocklist keeps only 64-bit hashes in sorted Vecs for this reason.
- Blocking work (downloads, parsing) runs in `spawn_blocking`.
- Shortcuts with a known limit get a `ponytail:` comment.
