+++
id = "M0-T08"
title = "Qualify pinned interoperability, MSRV, and three target artifacts"
milestone = "M0"
status = "review"
priority = "P0"
blocked_by = ["M0-T07"]
owns = [
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/tests/external_interop.rs",
  "tests/m0-harness/tests/scope_audit.rs",
  "tests/interop/**",
  "tests/platform/**",
  ".github/workflows/m0.yml",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-CI-001 through M0-CI-006 pass for the sole workflow .github/workflows/m0.yml: exact trigger allowlist, full-SHA actions, read-only permissions, exact eleven job names, fixed runners, numeric timeouts, no cache dependency, clean current-SHA builds, provider evidence, and one pushed-SHA run/attempt close contract",
  "A clean-worktree cargo build --workspace --bins --locked succeeds immediately before M0-INT-001 through M0-INT-004; the harness never relies on T07 or another worktree's untracked artifacts",
  "M0-INT-001 through M0-INT-004 all pass with exact sing-box 1.13.14 and shadowsocks-rust 1.24.0 asset checksums; each independent case byte-compares distinct fixed 16386-byte payloads in both directions before application Shutdown::Write, then deadline-observes target clean EOF, successful target write shutdown, and client clean EOF with no extra byte or reset/error without claiming target-FIN causality, while same-SHA M0-E2E-001/M0-LIFE-003 independently retain post-FIN reverse-drain evidence",
  "M0-MSRV-001 passes on Rust 1.85.0 without --ignore-rust-version",
  "M0-PLAT-001 through M0-PLAT-003 build both release binaries with Rust 1.97.1 and run valid and invalid offline config smoke on windows-2022 or ubuntu-24.04 as specified; musl-tools is exactly 1.2.4-2 and both musl binaries prove no PT_INTERP or DT_NEEDED with file/readelf",
  "M0-DETECT-002 passes separately on the native Windows MSVC and Linux GNU runners; one host result cannot substitute for the other",
  "M0-GATE-001 and M0-GATE-002 both pass on the same integrated commit, with every authoritative command executed and exit status recorded",
  "One separately authorized GitHub Actions push run has all eleven required jobs successful in one run ID and attempt at the exact approved integration GITHUB_SHA; missing, skipped, unavailable, or differently attributed results remain FAIL/BLOCKED",
  "M0-SCOPE-001 audits the complete b41c6127b1834ebd97246451fd92bafea50cb205...HEAD diff and finds no non-goal code, real secret, external binary, generated result, or unreviewed fixture and dependency provenance",
]
+++

# M0-T08: Qualify pinned interoperability, MSRV, and three target artifacts

## Outcome

按 ADR-0007 建立 GitHub Actions workflow，并实际执行M0的黑盒reference harness、
MSRV gate、三目标release artifact smoke、quick/full integration gates和
scope/provenance审计，形成绑定 exact pushed integration commit 的M0 close证据。

## Context

本票不是“写一个可skip的测试”。外部artifact、matching runner或network unavailable
会使票据BLOCK/FAIL，直到同一commit得到required evidence；不能fallback latest。
GitHub Actions/GitHub-hosted runners已由ADR-0007固定为M0 required provider。
本票可创建唯一 workflow `.github/workflows/m0.yml`，但不得擅自初始化/修改
remote、push、创建PR或触发workflow；这些外部动作需要用户单独明确授权。

## In scope

- `tests/interop/versions.toml`的pin/commit/URL/size/checksum/version/license记录。
- 唯一 `.github/workflows/m0.yml`，实现 ADR-0007 的 triggers、checkout、
  action pins、permissions、11 jobs、runner/timeout、no-cache和 evidence合同。
- external process harness、四项required TCP-only AES-128 cases。
- generated-tool/temp/config/log isolation、deadline、bounded capture、kill-on-drop。
- Windows/GNU/musl direct Cargo build和artifact config smoke evidence templates。
- Rust 1.85.0 MSRV check/test、Rust 1.97.1 target builds。
- authoritative quick/full gates、scope/provenance audit和给Team Lead的结构化
  command/exit/artifact evidence。

## Out of scope

- vendor/link/copy/redistribute reference code/binary。
- 重新选择 CI provider，或创建其他 workflow/local/composite action。
- remote 初始化/URL修改、push、workflow execution、PR、release、tag、branch
  protection或artifact publication。
- M1完整TCP matrix、M2 UDP、M3 full platform/lifecycle、M4 performance。
- 修改product manifests/lock/source。
- workflow coordination文档；Team Lead在integration gate后独占更新
  `docs/ci-status.md`与roadmap。

## Implementation notes and constraints

- binary先SHA-256/version验证后执行；缺失/mismatch/download/429/crash/timeout失败。
- checkout固定
  `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`、
  `fetch-depth: 0`；所有`uses:`为full SHA；permissions只有`contents: read`。
- triggers只允许`pull_request`、push到`master`/`codex/integration/**`、
  `workflow_dispatch`；禁止`pull_request_target`。
- 11个job ID/display name、runner和`timeout-minutes: 60`精确遵循ADR-0007；
  `ubuntu-latest`/`windows-latest`、cache和`continue-on-error`禁止。
- interop required job从clean worktree显式运行current-toolchain binary build；不得复用
  T07 worktree、另一个job或先前run留下的untracked artifact。
- external tests虽标`#[ignore]`，required jobs必须`--ignored --exact`逐项运行。
- 每个filtered required command必须先证明exact match/run count；zero-test success
  是FAIL，不能只依赖libtest exit status。
- 每case独立temp/ports，TCP-only且关闭multiplex/UDP/EIH/plugins。
- 每case先完整比较distinct fixed 16386-byte双向payload，再依次观察application
  write-half close后的target clean EOF、target成功write-half close后的application
  clean EOF；任何early FIN、reset/error、truncation、extra byte、mismatch或
  timeout失败。该顺序不声明target FIN导致client EOF。M0-E2E-001/M0-LIFE-003
  继续在同一SHA证明peer FIN后新reverse bytes的ferrum2行为。
- 三目标必须运行两个artifact的valid/invalid config；`cargo check`不可替代。
- GNU job实际运行两个GNU artifacts并执行M0-DETECT-002。musl job固定
  `musl`/`musl-dev`/`musl-tools=1.2.4-2`，实际运行两个musl artifacts，并对两者
  assertion `file` static/static-pie且`readelf`无`PT_INTERP`/`DT_NEEDED`。
- 每job记录GitHub run/attempt/job/SHA、ImageOS/ImageVersion、Included Software
  URL、OS/kernel、rustc/cargo/linker；这只属于M0 smoke evidence，不是M3资格。
- required job已启动后的setup/command/evidence错误为FAIL；workflow、push、
  provider或job未产生结果为BLOCKED；missing/skipped/cancelled均非PASS。
- evidence不得保存PSK/raw config；generated assets在`target/`或runner temp。

## Validation commands

```bash
rustup toolchain install 1.85.0 --profile minimal
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_sing_box
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact client_shadowsocks_rust
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact sing_box_client
cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact shadowsocks_rust_client
rustup toolchain install 1.97.1 --profile minimal
rustup target add --toolchain 1.97.1 x86_64-pc-windows-msvc
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-pc-windows-msvc
cargo test -p ferrum2-m0-harness --test detection_probe --locked
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-gnu
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-gnu
cargo test -p ferrum2-m0-harness --test detection_probe --locked
sudo apt-get update
sudo apt-get install --yes --no-install-recommends musl=1.2.4-2 musl-dev=1.2.4-2 musl-tools=1.2.4-2
dpkg-query -W musl musl-dev musl-tools
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-musl
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
git merge-base --is-ancestor b41c6127b1834ebd97246451fd92bafea50cb205 HEAD
git diff --check b41c6127b1834ebd97246451fd92bafea50cb205...HEAD
git diff --name-status --find-renames b41c6127b1834ebd97246451fd92bafea50cb205...HEAD
cargo test -p ferrum2-m0-harness --test scope_audit --locked
cargo test -p ferrum2-m0-harness --test scope_audit --locked workflow_policy
cargo tree --workspace --locked
```

两个artifact的12条exact valid/invalid config commands、GNU evidence和musl
`file`/`readelf` assertions按TEST-0001 platform matrix逐项执行并记录，不能从build
exit推断。

## Risks

- workflow 尚未实现，remote capability/push/Actions execution 也未获授权，远程
  evidence 当前为真实 BLOCKED；不得用本机/WSL2替代。
- GitHub-hosted image weekly drift只能靠ImageVersion/Included Software evidence
  追溯，不能提供M3完整资格。
- upstream asset/version/license drift或download rate limit会阻塞，但不得放宽pin。
- external child readiness/cleanup不严会导致flake；必须bounded、isolated、kill-on-drop。

## Completion evidence

To be filled by the Team Lead after integration:

- Branch: `codex/ticket/m0-t08`
- Commit(s): initial `14343d222b5caa1dfdc2ebfc931c52d427a106de`;
  repair 1/2 `5accd02d290ba0cedc60f394adbc3f3d71332ad9`
- Architect verdict: pending
- QA verdict: pending
- Integrated commit: pending
- GitHub run URL / run ID / attempt:
- Pushed `GITHUB_SHA`:
- Eleven required job results:
- Runner ImageOS/ImageVersion/Included Software links:
- Platform artifact/linkage evidence: local Windows release build and exact
  valid/invalid exits `0,2,0,2` PASS；native detection 2/2 and side-effect helper
  mutation self-test PASS。The exact four-case helper is reserved for a clean
  runner because an unrelated pre-existing system-session `sing-box.exe` owns
  `127.0.0.1:1080`; Linux GNU/musl provider evidence remains pending.
- Recovery state (2026-07-27): upstream T07 Rust 1.85.0 syntax incompatibility is
  closed by candidate `50bf0b7` and reviewed integration `123618f`; Team Lead,
  Architect and QA gates all PASS. T08 was then blocked independently: exact
  sing-box 1.13.14 diagnosis found a third-party post-FIN reverse-delivery
  limitation requiring an explicit evidence-contract amendment, while static
  Architect review of checkpoint `14343d2` found required workflow/harness repairs.
  ADR-0014 and synchronized SPEC/TEST amendments are now accepted after final
  Product/Architect/QA PASS. The initial checkpoint remains unintegrated; repair
  1/2 closes the known static findings and is now under independent review.
- Initial checkpoint: `14343d222b5caa1dfdc2ebfc931c52d427a106de`;
  clean, nine T08-owned files, unintegrated.
- Initial Architect gate: **BLOCK**. Repair 1/2 must close all findings in one
  batch: clean-job binary prerequisites；absolute child/version/I/O/reap deadlines
  with checked statuses and bounded sanitized evidence；reserved unique ports plus
  child-specific readiness and cleanup/rebind proof；structural per-job workflow
  policy and immutable scope allowlist；nonzero exact filtered-test counts；native
  no-side-effect/compiler-linker/BLAKE3-backend evidence.
- ADR-0014 acceptance: `96d62628107a373a076266d8564d81309c915be1`;
  final Product/Architect/QA document gates PASS.
- Repair candidate: `5accd02d290ba0cedc60f394adbc3f3d71332ad9`;
  clean, eight T08-owned files. Engineer evidence: quick 3/3、full 4/4、scope
  audit 4/4、workflow policy 1/1、external default 6 passed/4 ignored、four
  exact pinned interop cases 1/1 each、same-SHA local E2E success 3/3、
  runtime half-close 1/1、Rust 1.85 build/check/test and local Windows
  build/config/detection gates all PASS.
- Current gate: **REVIEW**；final candidate Architect and QA verdicts pending.
