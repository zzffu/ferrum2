+++
id = "M0-T08"
title = "Qualify pinned interoperability, MSRV, and three target artifacts"
milestone = "M0"
status = "blocked"
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
  "The two diagnosed config/replay filters are listed and executed by their full test names with libtest --exact and exact count one, so valid config cannot match invalid_matrix and replay exact_invalid cannot match exactly_one; other filtered command semantics remain unchanged",
  "A clean-worktree cargo build --workspace --bins --locked succeeds immediately before M0-INT-001 through M0-INT-004; the harness never relies on T07 or another worktree's untracked artifacts",
  "M0-INT-001 through M0-INT-004 all pass with exact sing-box 1.13.14 and shadowsocks-rust 1.24.0 asset checksums; each independent case byte-compares distinct fixed 16386-byte payloads in both directions before application Shutdown::Write, then deadline-observes target clean EOF, successful target write shutdown, and client clean EOF with no extra byte or reset/error without claiming target-FIN causality, while same-SHA M0-E2E-001/M0-LIFE-003 independently retain post-FIN reverse-drain evidence",
  "M0-MSRV-001 passes on Rust 1.85.0 without --ignore-rust-version",
  "M0-PLAT-001 through M0-PLAT-003 build both release binaries with Rust 1.97.1 and run valid and invalid offline config smoke on windows-2022 or ubuntu-24.04 as specified; GNU/musl resolve compiler-reported absolute or bare linker names to an executable canonical path and run --version; Windows accepts link-help exit only 0 or 1 together with a Microsoft linker/version banner; musl-tools is exactly 1.2.4-2 and both musl binaries prove no PT_INTERP or DT_NEEDED with file/readelf",
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
  是FAIL，不能只依赖libtest exit status。M0-CFG-001必须使用full name
  `valid_client_and_server_configs_have_exact_offline_output`加libtest `--exact`；
  M0-REPLAY-001必须使用full name
  `exact_invalid_does_not_poison_then_duplicate_is_rejected`加libtest `--exact`。
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
- GNU/musl的compiler-reported linker若为bare name必须先经`command -v`，再
  canonicalize、检查executable并运行`--version`；不得相对checkout解析。Windows
  必须捕获`link /?`输出/exit，只接受exit 0或1且同时匹配Microsoft
  linker/version banner，并使已验证的help exit 1不污染step最终状态。
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
cargo test -p ferrum2-m0-harness --test config_cli --locked valid_client_and_server_configs_have_exact_offline_output -- --exact --list
cargo test -p ferrum2-m0-harness --test config_cli --locked valid_client_and_server_configs_have_exact_offline_output -- --exact
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact_invalid_does_not_poison_then_duplicate_is_rejected -- --exact --list
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact_invalid_does_not_poison_then_duplicate_is_rejected -- --exact
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

## Current risks

- Workflow已实现且首次authorized push/run已发生；run `30301746374`失败，
  repair/new exact SHA/重新资格与separately authorized新run当前为真实BLOCKED，
  不得用本机/WSL2或旧run局部success替代。
- GitHub-hosted image weekly drift只能靠ImageVersion/Included Software evidence
  追溯，不能提供M3完整资格。
- upstream asset/version/license drift或download rate limit会阻塞，但不得放宽pin。
- external child readiness/cleanup不严会导致flake；必须bounded、isolated、kill-on-drop。

## Completion evidence

- Branch: `codex/ticket/m0-t08`
- Commit(s): initial `14343d222b5caa1dfdc2ebfc931c52d427a106de`;
  repair 1/2 `5accd02d290ba0cedc60f394adbc3f3d71332ad9`
- Architect verdict: repair 1/2 `5accd02` **BLOCK**
- QA verdict: repair 1/2 `5accd02` **BLOCK**
- First integrated commit:
  `51fb7327af966cfc3f4a49058ea6bf2284009dcf`
- GitHub run URL / run ID / attempt:
  `https://github.com/zzffu/ferrum2/actions/runs/30301746374` / `30301746374` / `1`
- Pushed `GITHUB_SHA`: `51fb7327af966cfc3f4a49058ea6bf2284009dcf`
- Eleven required job results: 2 success（两个interop）、9 failure；不可作为close
- Runner ImageOS/ImageVersion/Included Software links: failing job logs retained；
  accepted same-run provider evidence pending a future 11/11 run
- Historical repair-1/2 platform artifact/linkage evidence: local Windows release build and exact
  valid/invalid exits `0,2,0,2` PASS；native detection 2/2 PASS。Repair 1/2's
  helper self-test overclaimed zero socket side effects and is not accepted.
  The exact four-case helper is reserved for a clean runner because an unrelated
  pre-existing system-session `sing-box.exe` owns `127.0.0.1:1080`; Linux
  GNU/musl provider evidence remains pending.
- Historical recovery state (2026-07-27): upstream T07 Rust 1.85.0 syntax incompatibility is
  closed by candidate `50bf0b7` and reviewed integration `123618f`; Team Lead,
  Architect and QA gates all PASS. T08 was then blocked independently: exact
  sing-box 1.13.14 diagnosis found a third-party post-FIN reverse-delivery
  limitation requiring an explicit evidence-contract amendment, while static
  Architect review of checkpoint `14343d2` found required workflow/harness repairs.
  ADR-0014 and synchronized SPEC/TEST amendments are now accepted after final
  Product/Architect/QA PASS. The initial checkpoint and repair 1/2 remain
  unintegrated；repair 2/2 is the final authorized local repair batch.
- Historical initial checkpoint: `14343d222b5caa1dfdc2ebfc931c52d427a106de`;
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
- Repair 1/2 review: Architect **BLOCK** with four REQUIRED groups：the live
  external EOF/shutdown observations lack target→application ordering and
  production-bound mutations；partial-progress I/O can exceed the absolute case
  deadline；workflow policy does not consume a closed YAML/command subset；the
  platform helper overclaims an unobservable failed-bind attempt. QA independently
  found the platform false-pass and returned **BLOCK**；all other local candidate
  commands passed after exact pin provisioning. Its first MSRV workspace run had
  one `child exited before readiness` lifecycle failure, while focused and exact
  full reruns passed；the flake is under separate diagnosis and is not silently
  counted as deterministic evidence.
- Repair 2/2 branch: `codex/repair/m0-t08-final-closure`; first candidate
  `3d5b1a2f5db716f55b4a3aa25f394e0fa0ac7f51`.
- Repair 2/2 first-candidate evidence: quick 3/3、full 4/4、MSRV workspace、
  scope 4/4、four exact pinned interop cases、same-SHA E2E/half-close and helper
  mutations PASS；clean three-file owned commit. Architect re-review **BLOCK**:
  target stream still dropped before an application EOF acknowledgment and the
  10-second per-operation timeout still slid after partial progress. Workflow
  closed-subset and narrowed platform evidence findings are closed.
- Authorized post-review closure:
  `49c63082b95e57fc68de20c21ba5bdd621a4ac39`, exact child of `3d5b1a2`;
  retains the target stream through same-deadline application acknowledgment,
  couples trace events to real clean EOF observations, freezes every operation
  deadline, and adds omission/read-error/extra-byte/reset/shutdown/ack/lifetime/
  drip mutations in the same T08-owned harness file.
- Follow-up Engineer evidence: focused contract 15/15、scope 4/4、external
  default 15 passed/4 intentional ignores、four exact pinned interop cases 1/1
  each、same-SHA local E2E/half-close、Rust 1.85、quick 3/3 and full 4/4 PASS.
- Follow-up review: Architect **PASS** with no BLOCKER/REQUIRED/advisory.
  Independent QA **PASS_WITH_ACTIONS** after the same local gates, exact four
  interop executions, Windows builds/config/detection and hygiene all passed.
  The unrelated Session 0 `sing-box` listener still prevents the fixed-port
  helper locally; isolated Windows、GNU/musl and one exact eleven-job run remain
  required remote evidence.
- Upstream readiness blocker: T07 harness diagnosis proved that ownership-blind
  `AddrInUse` readiness can false-pass a foreign port and then report
  `child exited before readiness`; narrow repair candidate `6139544` now has
  Architect **PASS** and QA **PASS_WITH_ACTIONS**.
- Pre-hosted gate (subsequently closed by `51fb7327`): **BLOCKED** until
  reviewed T07 `6139544` and T08 `49c63082` were combined and passed same-SHA
  Team Lead、Architect and QA gates；at that checkpoint no candidate had been
  integrated, pushed or published.
- First hosted attempt: exact T07/T08 integration
  `51fb7327af966cfc3f4a49058ea6bf2284009dcf` passed local Team Lead、final
  Architect and independent QA gates, then was pushed only to the authorized
  `origin/codex/integration/m0`. GitHub Actions run `30301746374`, attempt 1,
  instantiated all eleven required jobs: both interop jobs succeeded and the
  other nine failed. This is immutable **2/11 success, 9/11 failure** evidence
  and cannot be rerun, waived, or combined with a later run.
- Hosted roots: four jobs share Linux lifecycle exact-rebind `EADDRINUSE`;
  local-e2e and security each failed before execution because broad filters
  matched two tests; GNU/musl resolved compiler-reported bare `ld` relative to
  checkout; Windows hardcoded link-help exit 1100 although hosted `link /?`
  returned 1 with the expected usage output. No observed failure establishes a
  wire, replay, config, interop, platform artifact, or product-scope defect.
- Hosted repair: ADR-0015 is the prerequisite. T08 is limited to
  `.github/workflows/m0.yml` plus `scope_audit.rs`: full-name libtest `--exact`
  filters, fail-closed GNU/musl linker resolution, fail-closed Windows
  exit/banner validation, and synchronized closed-workflow policy. Job/runner/
  trigger/permission/action/toolchain/product contracts remain unchanged.
- Current gate remains **BLOCKED** until T07 and T08 repair candidates are
  integrated, all local gates plus Architect/QA pass on the new exact SHA, and
  one new separately authorized run/attempt is 11/11 success. No second push, rerun, PR,
  master push, tag, release, or other remote mutation has occurred.
