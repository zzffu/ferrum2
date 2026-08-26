# Repository Guidelines

## Project Structure & Module Organization

Ferrum2 is a Rust 2024 workspace pinned to Rust 1.97.1. Binaries live in `bins/ferrum2-client` and `bins/ferrum2-server`; shared networking, crypto, DNS, runtime, configuration, and TUN code lives in `crates/ferrum2-*`. Cross-binary qualification tests are in `tests/m0-harness`; crate integration tests use each crate's `tests/` directory. Cross-workspace stable inputs and vectors belong under `tests/fixtures/{config,crypto,dns-tls,sip022,srs}`. The TUN crate's reviewed packet corpus is intentionally crate-owned under `crates/ferrum2-tun/tests/fixtures/packets`, with a separate fuzz seed set under `crates/ferrum2-tun/fuzz/corpus/packet_reassembly`. Platform qualification entry points, guest controllers, and their static contracts live in `tests/platform`; operator, topology-provisioning, and Windows TUN performance scripts live in `tools/windows-tun`. Performance-controller tests live in `tests/{performance_candidate,performance_rule}`, and qualification tooling is in `tools/{ferrum2-m4-qualification,ferrum2-rule-qualification}`. `vendor/shadowsocks-crypto` is patched through the root manifest; treat it as reviewed third-party source. Each workspace package and major test/tool subtree has a scoped `AGENTS.md`; follow the nearest guide while retaining this guide.

## Build, Test, and Development Commands

Use locked dependencies for reproducible results:

```text
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo test -p ferrum2-tun --all-features --no-run --locked
cargo test -p ferrum2-platform-windows --all-features --no-run --locked
cargo test -p ferrum2-dns --features __interop-test-root --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check
cargo doc --workspace --all-features --no-deps --locked
```

Run the ordinary Python controller tests with `python3` on Unix and `python` on Windows:

```text
python3 -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v
python3 -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v

python -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v
python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v
```

The client, TUN, and Windows platform test binaries are compile-only on ordinary hosts. Execute them, the
deterministic TUN smoke corpus, and all adapter/underlay qualification only inside the approved
local Hyper-V guest. `tests/platform/qualify_native.py` is a hosted-CI qualification command, not a
general local development command.

Use `cargo run -p ferrum2-client -- --help` (or `ferrum2-server`) for CLI help. Iterate with targeted tests, then run the full relevant gate.

## Coding Style & Naming Conventions

Accept `rustfmt` output (four-space indentation). Use `snake_case` for modules, functions, and tests; use `UpperCamelCase` for types and traits. Keep dependencies inherited and exactly pinned in the workspace manifest. Workspace Rust code forbids unsafe code; do not broaden the narrowly controlled Windows FFI exception. Python control scripts use four spaces, standard-library APIs, and `unittest`. Prefer behavioral assertions over source-text or implementation-shape checks.

## Compatibility Policy

Ferrum2 does not preserve backward compatibility. Remove obsolete APIs, schemas, aliases, migration shims, and legacy behavior instead of retaining compatibility paths; update every in-repository caller, fixture, and test to the current contract in the same change.

## Testing Guidelines

Place focused unit tests beside their module, public contract tests in `crates/*/tests`, and process/network behavior in `tests/m0-harness`. Name tests as descriptive outcomes, for example `missing_mandatory_guard_is_invalid`. Preserve fixture provenance when changing vectors. Platform- or privilege-dependent coverage belongs in the corresponding manual/platform workflow, not the ordinary unit suite.

## Commit & Pull Request Guidelines

Follow the repository's concise imperative convention: `fix(profiling): ...`, `test(platform): ...`, or `ci(perf): ...`. Keep each commit scoped to one reviewable concern. Pull requests should describe the behavior and risk, list commands actually run, note cross-platform impact, and link an issue when one exists. Attach workflow evidence for performance or privileged-network changes; screenshots are only useful for visible output changes.

## Security & Generated Files

Do not commit credentials, `target/`, `profiles/`, Python caches, or local archives. Keep logs and errors free of keys and peer data. Pin new CI actions and downloaded tools to reviewed versions or immutable SHAs.
