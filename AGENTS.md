# Repository Guidelines

## Project Structure & Module Organization

Ferrum2 is a Rust 2024 workspace pinned to Rust 1.97.1. Binaries live in `bins/ferrum2-client` and `bins/ferrum2-server`; shared networking, crypto, DNS, runtime, configuration, and TUN code lives in `crates/ferrum2-*`. Cross-binary qualification tests are in `tests/m0-harness`; crate integration tests use each crate's `tests/` directory. Cross-workspace stable inputs and vectors belong under `tests/fixtures/{config,crypto,dns-tls,sip022,srs}`. The TUN crate's reviewed packet corpus is intentionally crate-owned under `crates/ferrum2-tun/tests/fixtures/packets`, with separate fuzz seed sets under `crates/ferrum2-tun/fuzz/corpus/{packet_reassembly,udp_reset_races,config_legacy_fields,strict_route_rules}`. Platform correctness qualification and its static contract live in `tests/platform`; reusable Windows host modules live in `tools/powershell`, and Windows TUN performance scripts live in `tools/windows-tun/performance`. Performance-controller tests live in `tests/{performance_candidate,performance_rule}`; offline CI-controller tests live in `tests/ci`. Declarative workflow controllers live in `tools/ci`, and qualification tooling is in `tools/{ferrum2-m4-qualification,ferrum2-rule-qualification}`. `vendor/shadowsocks-crypto` is patched through the root manifest; treat it as reviewed third-party source. Each workspace package and major test/tool subtree has a scoped `AGENTS.md`; follow the nearest guide while retaining this guide.

## Build, Test, and Development Commands

Start with `README.md` for the local SOCKS5 example and `docs/README.md` for configuration,
architecture, and qualification documentation. Update those entry points when adding or moving a
public guide or example; verify documented commands against their owning CLI and workflow.

Use locked dependencies for reproducible results:

```text
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked
cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked
cargo check -p ferrum2-tun -p ferrum2-platform-windows --all-features --locked
cargo check -p ferrum2-tun --features fuzzing --target x86_64-unknown-linux-gnu --locked
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
python3 -B -m unittest discover -s tests/ci -p 'test_*.py' -v
python3 -B -m unittest discover -s tests/platform -p 'test_qualify_native.py' -v

python -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v
python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v
python -B -m unittest discover -s tests/ci -p 'test_*.py' -v
python -B -m unittest discover -s tests/platform -p 'test_qualify_native.py' -v
```

The Linux-target check requires that Rust target and its native cross-compilation prerequisites;
it is not a prerequisite for a Windows-only documentation or application change. On Windows, the
nonmutating qualification script contract can also be checked with:

```text
pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1
```

After building target-specific release binaries, run the unprivileged native contract locally with
the matching profile and target, for example on Windows:

```text
python -X utf8 tests/platform/qualify_native.py --local-contract --profile windows-msvc --target x86_64-pc-windows-msvc --client target/x86_64-pc-windows-msvc/release/ferrum2-client.exe --server target/x86_64-pc-windows-msvc/release/ferrum2-server.exe
```

The client test binary is compile-only on ordinary hosts. The hosted `ferrum2-tun` and
`ferrum2-platform-windows` library suites are safe by contract: they use target-neutral logic,
unsupported-target stubs, or injected Windows operations and run in ordinary Linux and hosted Windows
CI. Ordinary tests must never create a real adapter or mutate route, DNS, WFP, or interface state.
Privileged Windows TUN correctness qualification runs only through
`tests/platform/run_windows_tun_qualification_host.ps1`; it requires an already elevated shell,
the explicit `-AcknowledgeHostNetworkMutation` switch, run-owned RFC 2544 addresses and `/32` routes,
and a verified zero-residue transaction within 900 seconds. Windows TUN performance remains separate
at `tools/windows-tun/performance/run_windows_tun_performance_host.ps1` and has the same elevation and
acknowledgement requirements. Neither host runner may change a default route, host DNS, a physical
adapter, WLAN, sing-box, or unrelated state. The deterministic TUN smoke corpus and sanitizer-backed,
pure in-memory fuzz targets run only in their bounded Linux CI workflow.
`tests/platform/qualify_native.py --local-contract` may execute its unprivileged loopback binary
contract locally; omitting `--local-contract` retains hosted-CI identity and evidence checks.

Use `cargo run -p ferrum2-client --locked -- --help` (or `ferrum2-server`) for CLI help. Iterate with targeted tests, then run the full relevant gate.

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
