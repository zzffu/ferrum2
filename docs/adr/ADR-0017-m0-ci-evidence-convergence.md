# ADR-0017: M0 CI evidence convergence

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；`TEST-0001`；
  M0-T09、M0-T10；部分取代 `ADR-0006`、`ADR-0007`、`ADR-0011`、
  `ADR-0015`、`ADR-0016` 的 CI 编排与证据实现

## Context and problem

exact candidate
`5969bfdafea9056feb179e0a8454dd5dc7fe5bce` 的 GitHub Actions run
`30322690937`（attempt 1）完成 11 个 jobs，其中 6 success、5 failure。通过项
包含 security、lifecycle、Linux GNU、Linux musl 和两个 reference interop
jobs；失败来自四个证据机制假设：

1. `scope_audit` 调用 runner 未声明提供的 `rg`；
2. external helper 把 Linux 合法 timeout `WouldBlock` 固定为 `TimedOut`；
3. substring test filter 匹配两个测试，exact-count guard 在产品测试前失败；
4. `link.exe /?` 输出正确 MSVC 帮助，但返回 1100，不符合 workflow 猜测。

这些失败没有证明 wire、密码、replay、config、runtime、artifact 或 interop
产品缺陷。旧 run 保持整体失败，不得豁免、重跑追认或与其他 SHA/run 拼接。

证据控制面已经失衡：`.github/workflows/m0.yml` 约 761 行，
`tests/m0-harness/tests/scope_audit.rs` 约 2,019 行，
`tests/m0-harness/src/external_support/mod.rs` 约 2,263 行。workflow 以大量重复
Cargo 命令实现结果，`scope_audit` 又以第二套 parser、snapshot 和 mutation
逻辑验证 workflow 的实现细节。`external_interop` 虽将四个真实 case 标为
ignored，其 module 内 15 个 helper tests 仍被普通 workspace test 执行，使
hosted external dependency 泄漏到本机 gate。

## Why this requires an ADR

ADR-0007 与 ADR-0016 把 exact 11-job topology、job/command allocation 和若干
probe 纳入受保护合同。本次不是修正命令拼写，而是重新划分 local/hosted seam、
删除一套自验证控制面并改变 release conformance profile。它跨越 Cargo test
discovery、CI provider、平台与供应链证据，必须先显式替换旧合同。

## Decision drivers and invariants

以下是继续有效的 normative invariants：

- SIP022 wire、认证先于副作用、replay/binding/bounds、secret redaction 和
  bounded-resource 结果不变。
- lifecycle 五类各 20 次、owner cleanup、immediate restart、live-owner
  exclusion、half-close、timeout/cancel/shutdown 结果不变。
- sing-box 1.13.14 与 shadowsocks-rust 1.24.0 的固定版本、asset size/hash、
  license boundary，以及 reference × direction 四项 AES-128 TCP interop
  全部通过。
- Windows MSVC、Linux GNU、Linux musl 均 locked release-build 两个 binaries，
  各执行 client/server valid/invalid offline config smoke；GNU/Windows 保留
  47-row native detection，musl 保留 static linkage assertions。
- Rust 1.85.0 必须检查全部targets并实际运行workspace tests。
- M0 close 只接受一个另行授权 push 的 exact SHA，在一个完整 GitHub workflow
  run/attempt 中取得全部 required result；missing、skipped、cancelled、
  unavailable 或不同 SHA 均非 PASS。
- workflow 保持 read-only permissions、所有 actions full-SHA pin、fixed runner
  labels、无 secrets、无 cache dependency、clean checkout 与
  `HEAD == GITHUB_SHA`。

job 数量、display name、exact timeout 数字、test filter、test count、
linker help/version probe、Included Software URL 拼接、workflow blob hash、
YAML parser、historical control-plane path snapshot 和 helper mutation 属于
selected profile 或 mechanical realization，不是产品或 release invariant。

## Options considered

### Option A: continue four narrow repairs

为 runner 安装 `rg`、接受更多 timeout kind、修正 filter 和 `link /?` exit。
改动最小，但保留 11 个重复 jobs、两千行 workflow self-audit 和本机 helper
执行；下一次 runner 差异仍会增加永久探针。拒绝。

### Option B: move the same commands into shell or PowerShell scripts

workflow 会变短，但重复职责、平台分叉和本机 external seam 仍存在；复杂度只是
移动文件。拒绝。

### Option C: matrix every reference and direction independently

使用 quality、MSRV、三平台、四 interop cells 和 aggregate gate。失败隔离最强，
但 M0 只有四个小型 interop cases，四个 clean VM/build 增加时间和可变环境，
没有增加结果覆盖。拒绝作为初始 profile。

### Option D: outcome-oriented hosted profile with one deep qualification seam

CI 只有四个 job definitions，platform 展开三行，interop 在一个 hosted job
内执行并聚合四案；普通Cargo gate编译/lint qualification code但无法运行
external case。接受。

## Decision

### Local interface

本机 authoritative interface 仍是 `workflow.toml`：

- quick：fmt、workspace check、workspace test；
- full：fmt、strict Clippy、all-features workspace test、docs。

这些命令不得下载、配置或运行 reference binaries，不要求 reference 环境变量，
也不得通过libtest discovery执行external cases或OS/process helper tests。
qualification是`ferrum2-m0-harness`中的Cargo-managed non-test binary：
manifest显式设置`test = false`，因此metadata/check/Clippy可见并受workspace
`unsafe_code = "forbid"`、lint、dependency/license和lock policy约束，但
`cargo test --workspace`即使带`--all-features`也不会执行其`main`。

本机只允许运行不创建socket/process、不读取reference、不访问network的少量
hermetic qualification state tests。interop job通过Cargo显式构建并运行一个无
参数、closed qualification entry。entry可用固定参数调用`git`读取checkout
identity；随后必须在任何network/socket I/O、reference/ferrum child spawn前验证
`GITHUB_ACTIONS=true`、Linux runner、clean checkout和`HEAD == GITHUB_SHA`。
它不接受arbitrary URL、binary path、version或unreviewed pin。

### Hosted profile

`.github/workflows/m0.yml` 初始实现四个 job definitions、六个 rendered jobs：

| Definition | Rendered jobs | Required result |
|---|---:|---|
| `quality` | 1 | 先`cargo build --workspace --bins --locked`，再运行`workflow.toml` full四条命令；current-toolchain security、lifecycle、local E2E、unit/integration和docs只运行一次 |
| `msrv` | 1 | Rust 1.85.0 `check --workspace --all-targets --locked`与`test --workspace --locked` |
| `platform` | 3 | explicit `windows-msvc`、`linux-gnu`、`linux-musl` matrix，`fail-fast: false`；保留三目标 artifact/config/detection/static results |
| `interop` | 1 | 分别provision两个pinned references；显式driver运行全部可运行cases并固定报告M0-INT-001～004；仅4/4成功且cleanup完成时exit 0 |

job definition/name/count 是可替换 profile，不是新的永久 invariant。当前 M0 不增加
aggregate job；完整 workflow conclusion、同一 run/attempt 的六个 rendered
results 与 exact SHA 是 close interface。以后若 branch protection 需要一个稳定
aggregate check，属于单独 remote policy 决定和授权，不是本 ADR 的隐含远程变更。

`quality`先显式构建两个binaries供process harness定位，再运行full；它不再先跑
quick，也不拆security/lifecycle/local-E2E/full重复jobs。`msrv`保留既有
`check --all-targets`和完整workspace test execution；external qualification
不在libtest discovery中，因此不会在MSRV job运行reference。

platform 成功构建并原生运行 artifacts 本身就是 linker 可用性的强证据。
删除 `link.exe /?`、GNU/musl linker canonicalization/help 和 BLAKE3 backend
探针；保留有产品意义的 artifact hash、native config exits、GNU ELF 记录和
musl `file`/`readelf` assertions。

interop driver 隐藏 pin读取、safe provision/extraction、version/hash验证、
temp/port/child ownership、absolute deadlines、bounded/redacted capture、
双向 16,386-byte comparison、ordered clean EOF 和 cleanup。四案彼此隔离；
单案失败被记录但不得阻止其余案尝试，最终聚合为非零退出。timeout 判断依赖
absolute deadline 与 elapsed result，不固定某个 OS error kind。
external driver不再证明exact-address rebind；该结果由同一SHA上`quality`中的
M0-LIFE-005独立拥有，避免external seam复制lifecycle policy。

四行summary的最小schema固定为`case_id`、`status=PASS|FAIL`和可选
`canonical_root`。某reference provision失败时，其两个case不声称已执行，均以同一
setup root报告FAIL；另一个reference的两个可运行cases仍执行。全局ferrum
build/exact-SHA guard失败可终止case plan，但必须作为唯一共同前置root报告。

### Evidence and scope boundary

删除：

- `scope_audit.rs` 对 workflow/YAML/blob/path snapshot 的自验证；
- `--list | grep`、substring filters 和 exact-count guards；
- external module内依赖OS/socket/process spelling的默认helper tests；仅保留少量
  无I/O的guard/aggregation/failure-continuation state tests；
- exact 11-job allocation、linker help probes及重复 Ubuntu jobs。

保留 focused workspace architecture、unsafe/secret/zeroize/license、fixture
provenance、resolved dependency graph 和 reference pin checks。scope 由 ticket
ownership、`git diff --name-status`、`git diff --check`、Architect/QA review 和
实际 locked build/test 证明，不再由同一提交中的第二套 workflow parser 充当
安全边界。用户已明确排除的 skill optimization 不再进入 M0 自动 scope audit。

### Failure semantics

- job 已启动后的 setup、network、package、pin、checksum、build、test、
  timeout、cleanup 或 evidence 错误为 FAIL。
- workflow/provider/授权 push 不存在，或 required result 未产生，为 BLOCKED。
- missing、skipped、cancelled、neutral、zero-case 或 3/4 interop 均非 PASS。
- matrix `fail-fast: false`；interop driver 也收集全部四案后失败，避免首因掩盖。
- 任何旧 SHA/run 的局部 success 都不能拼接到新 candidate。

## Consequences and tradeoffs

### Positive

- 本机 gate只验证 ferrum2，自外部网络、reference process 和 GitHub runner
  mechanical behavior 解耦。
- CI 失败更接近真实结果：Cargo gate、MSRV tests、artifact smoke或interop case。
- workflow 从第二份规范变回薄 orchestration；deep driver隐藏并统一 external
  lifecycle。
- 删除重复编译、filter/count、link-help 和 workflow self-audit，降低维护面。

### Negative

- interop 共用一个 VM；driver 必须保证每案独立并在失败后继续，公共 provision
  failure仍会形成一个 canonical setup root。
- MSRV仍重复执行workspace runtime suite；这是保留既有compatibility contract的
  明确成本，不再叠加external reference execution。
- 删除 automated whole-diff parser 后，ownership 与 non-goal 审查依赖简短的
  focused checks和独立 Architect/QA review。
- GitHub-hosted image仍会漂移；runner label、run ID/attempt、SHA、
  ImageOS/ImageVersion 与 toolchain版本用于追溯，但不伪装成 immutable image。

## Compatibility and upstream divergence

不改变 wire、product API、config schema、listener/runtime、reference pins、
toolchain versions、target triples 或 upstream compatibility claim。external
evidence继续只声明 pre-FIN 双向 bytes 与 ordered clean-EOF convergence；
post-FIN reverse drain 仍由 ferrum2-owned local/runtime tests证明。

## Migration and rollback

迁移按两个 ownership-disjoint tickets执行：

1. M0-T09 建立Cargo-managed non-test qualification seam，从libtest discovery
   移除external cases和OS/process helper tests，同时保留workspace compile/lint。
2. M0-T10 收敛 workflow和platform mapping，删除 `scope_audit.rs`。两票可并行
   实现；M0-T10 仅在 M0-T09 entrypoint集成后合入。

当前配置的`workflow.base_branch = "master"`落后于M0 implementation checkpoint。
执行时两张Engineer worktree必须从“包含`5969bfd`且接受ADR-0017的exact planning
commit”创建，不能从stale `master`重建；Team Lead可先把planning commit纳入local
integration或显式从该SHA创建worktree。该要求不授权更新master或任何remote ref。

必须一次性以新合同、driver、workflow和删除项形成一个 exact integration SHA。
旧 run `30322690937` 保持 6/11 overall failure。回滚需整体恢复旧 profile，M0
随即恢复 BLOCKED；不存在 wire/config/data migration。push、rerun、PR、branch
protection、tag 和 release 仍需用户单独授权。

## Verification plan

合同：

- Product、Architect、QA 对 ADR/SPEC/TEST/tickets 给出 PASS。
- `workflow.py doctor`、`validate`、`frontier`、`next` 与 `git diff --check`
  在 planning commit 通过。

实现：

- `cargo metadata`显示qualification binary为Cargo-managed且`test = false`；
  quick/full、`--all-features`和`--all-targets`可编译/lint它但不执行entry、
  external case或OS/process helper，无reference env、binary或network仍能完成。
- hosted-only entry除固定checkout identity `git` probe外，在非GitHub/exact-SHA
  环境于network/socket I/O或reference/ferrum child前拒绝。
- Cargo focused tests覆盖guard、aggregation、failure continuation与summary；
  它们不得创建socket/process、读取reference或访问network。真实deadline、
  bounded diagnostics与cleanup由hosted四案和review证明。
- 新 exact integration SHA 上 local quick/full、Architect和QA通过。
- 另行授权 push 后，同一 workflow run/attempt 的六个 rendered results全部
  success，interop明确报告 M0-INT-001～004 4/4。

## References

- `ADR-0006`：reference pins、四项互操作与平台结果。
- `ADR-0007`：GitHub Actions provider与安全边界。
- `ADR-0014`：external half-close evidence boundary。
- `ADR-0016`：normative invariant、selected profile与mechanical realization。
- GitHub Actions run `30322690937`，exact SHA `5969bfd...`。
