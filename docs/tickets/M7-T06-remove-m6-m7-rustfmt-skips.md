---
id: M7-T06
milestone: M7
status: ready
depends_on: [M7-T05]
owns:
  - bins/ferrum2-client/src/run.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-runtime/tests/udp_runtime.rs
  - crates/ferrum2-shadowsocks/tests/udp_packets.rs
  - crates/ferrum2-socks5/tests/command.rs
  - crates/ferrum2-socks5/tests/udp.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - docs/tickets/M7-T06-remove-m6-m7-rustfmt-skips.md
---

# M7-T06 — Remove M6/M7 rustfmt skips

## Outcome

Delete every current `#[rustfmt::skip]` attributed by `git blame` to M6 or M7，then accept standard
rustfmt output without changing test behavior。Keep the one M1-owned skip in
`tests/m0-harness/src/local_support/mod.rs` outside scope。

## Acceptance

- [ ] All 76 attributes introduced by M6/M7 commits are absent and the M1 attribute remains exact。
- [ ] Only the eight owned Rust files receive formatting changes；no assertion、fixture value、test
      selection or product behavior changes。
- [ ] Pinned rustloc reports code/tests `15529/25483`，exact schema 2 envelope equality PASS and a
      nonblocking ticket warning。
- [ ] Focused suites、Full、Rust 1.85、Clippy、rustfmt and diff checks pass。

## Validation

```powershell
rg -n --glob '*.rs' '#\s*\[rustfmt::skip\]' .
cargo fmt --all -- --check
cargo test -p ferrum2-config -p ferrum2-socks5 -p ferrum2-shadowsocks -p ferrum2-runtime -p ferrum2-client -p ferrum2-m0-harness --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-t05-sha> --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: —
- Review: —
- Notes: —
