+++
id = "M0-T08"
title = "Qualify pinned interoperability, MSRV, and three target artifacts"
milestone = "M0"
status = "ready"
priority = "P0"
blocked_by = ["M0-T07"]
owns = [
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/tests/external_interop.rs",
  "tests/m0-harness/tests/scope_audit.rs",
  "tests/interop/**",
  "tests/platform/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "A clean-worktree cargo build --workspace --bins --locked succeeds immediately before M0-INT-001 through M0-INT-004; the harness never relies on T07 or another worktree's untracked artifacts",
  "M0-INT-001 through M0-INT-004 all pass with exact sing-box 1.13.14 and shadowsocks-rust 1.24.0 asset checksums, independent process directions, bidirectional bytes, half-close, and sanitized diagnostics",
  "M0-MSRV-001 passes on Rust 1.85.0 without --ignore-rust-version",
  "M0-PLAT-001 through M0-PLAT-003 build both release binaries with Rust 1.97.1 and run valid and invalid offline config smoke on matching Windows MSVC, Linux GNU, and Linux musl runners",
  "M0-DETECT-002 passes separately on the native Windows MSVC and Linux GNU runners; one host result cannot substitute for the other",
  "M0-GATE-001 and M0-GATE-002 both pass on the same integrated commit, with every authoritative command executed and exit status recorded",
  "M0-SCOPE-001 audits the complete b41c6127b1834ebd97246451fd92bafea50cb205...HEAD diff and finds no non-goal code, real secret, external binary, generated result, or unreviewed fixture and dependency provenance",
]
+++

# M0-T08: Qualify pinned interoperability, MSRV, and three target artifacts

## Outcome

建立并实际执行M0的黑盒reference harness、MSRV gate、三目标release artifact smoke、
quick/full integration gates和scope/provenance审计，形成可用于M0 close的证据。

## Context

本票不是“写一个可skip的测试”。外部artifact、matching runner或network unavailable
会使票据BLOCK/FAIL，直到同一commit得到required evidence；不能fallback latest。
仓库尚无CI provider，因此实现provider-neutral harness/commands，不擅自创建remote
workflow。

## In scope

- `tests/interop/versions.toml`的pin/commit/URL/size/checksum/version/license记录。
- external process harness、四项required TCP-only AES-128 cases。
- generated-tool/temp/config/log isolation、deadline、bounded capture、kill-on-drop。
- Windows/GNU/musl direct Cargo build和artifact config smoke evidence templates。
- Rust 1.85.0 MSRV check/test、Rust 1.97.1 target builds。
- authoritative quick/full gates、scope/provenance audit和给Team Lead的结构化
  command/exit/artifact evidence。

## Out of scope

- vendor/link/copy/redistribute reference code/binary。
- CI provider选择、push、PR、release或artifact publication。
- M1完整TCP matrix、M2 UDP、M3 full platform/lifecycle、M4 performance。
- 修改product manifests/lock/source。
- workflow coordination文档；Team Lead在integration gate后独占更新
  `docs/ci-status.md`与roadmap。

## Implementation notes and constraints

- binary先SHA-256/version验证后执行；缺失/mismatch/download/429/crash/timeout失败。
- interop required job从clean worktree显式运行current-toolchain binary build；不得复用
  T07 worktree、另一个job或先前run留下的untracked artifact。
- external tests虽标`#[ignore]`，required jobs必须`--ignored --exact`逐项运行。
- 每case独立temp/ports，TCP-only且关闭multiplex/UDP/EIH/plugins。
- 三目标必须运行两个artifact的valid/invalid config；`cargo check`不可替代。
- evidence不得保存PSK/raw config；generated assets在`target/`或runner temp。

## Validation commands

```bash
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_sing_box
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_shadowsocks_rust
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact sing_box_client
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact shadowsocks_rust_client
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-pc-windows-msvc
cargo test -p ferrum2-m0-harness --test detection_probe --locked
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-gnu
cargo test -p ferrum2-m0-harness --test detection_probe --locked
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-musl
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
git merge-base --is-ancestor b41c6127b1834ebd97246451fd92bafea50cb205 HEAD
git diff --check b41c6127b1834ebd97246451fd92bafea50cb205...HEAD
git diff --name-status --find-renames b41c6127b1834ebd97246451fd92bafea50cb205...HEAD
cargo test -p ferrum2-m0-harness --test scope_audit --locked
cargo tree --workspace --locked
```

Artifact run commands、linkage/version/hash evidence按TEST-0001 platform matrix逐项执行
并记录，不能从build exit推断。

## Risks

- 当前matching Linux toolchains/runners未就绪，可能成为真实执行blocker。
- upstream asset/version/license drift或download rate limit会阻塞，但不得放宽pin。
- external child readiness/cleanup不严会导致flake；必须bounded、isolated、kill-on-drop。

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Architect verdict:
- QA verdict:
- Integrated commit:
