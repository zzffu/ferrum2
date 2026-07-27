# ADR-0007: M0 GitHub Actions CI provider 与 hosted-runner 证据

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T08；补充 ADR-0006；关闭 DEC-011

## Context and problem

ADR-0006 已冻结 M0 的 reference pins、四项互操作、MSRV、三目标 artifact smoke
和 unavailable=FAIL/BLOCK 语义，但当时仓库尚未选择 CI provider，因此有意保持
provider-neutral。M0 现在需要一个能验证已推送 exact integration commit、提供原生
Windows/Linux runner 且留下可审计证据的 required CI provider。

本机 Windows/WSL2 仍可用于开发诊断，但其可变本机状态和 WSL kernel 不能证明
GitHub 上已推送 commit 在独立 native runner 上通过。此次决定只补充 M0 的 CI
执行与证据合同；不改变任何产品范围、协议行为、测试语义或 M3/M4 资格边界。

目标 repository 是公开仓库 `zzffu/ferrum2`。本次 plan 不创建 workflow、不验证
或修改 remote、不 push，也不触发 GitHub Actions。

## Decision drivers and invariants

- required CI 必须绑定一个已推送的 exact Git commit，而不是本机 working tree。
- Windows MSVC 必须在原生 Windows runner 运行；GNU、musl、MSRV、安全、
  生命周期、full 和 interop 必须在原生 Linux runner 运行。
- ADR-0006 的 reference version/SHA-256、四项 matrix、artifact smoke、
  unavailable=FAIL/BLOCK 和 M0/M3 边界保持不变。
- workflow supply chain、token permissions、trigger surface、timeout 和 cache
  行为必须可静态审计。
- GitHub-hosted image 会滚动更新，M0 必须记录 provider-native image evidence，
  但不得把它描述为不可变 OCI image或 M3 完整平台资格。
- workflow、tests 和 logs 只使用公开 synthetic PSK，不读取 repository、
  organization 或 environment secrets。

## Options considered

### Option A：GitHub Actions + GitHub-hosted runners

每个 required job 使用 provider 创建的 clean VM；固定 Windows/Linux labels，
并把 run、job、commit、runner image 和 toolchain evidence 关联起来。

### Option B：本机 Windows + WSL2 作为 required CI

可用于快速诊断，但不能独立证明已推送 integration commit，也不能提供原生
GitHub-hosted Windows/Linux evidence。

### Option C：self-hosted runners

可以控制 image，但会引入持久主机的加固、清理、凭据、容量和可用性责任，超出本次
窄范围 M0 amendment。

## Decision

### Provider、workflow 与 triggers

M0 required CI provider 选择 GitHub Actions，使用 GitHub-hosted runners。唯一
workflow 路径固定为 `.github/workflows/m0.yml`，由 M0-T08 独占 ownership。
本次 plan 只冻结合同，不创建该 YAML。

允许且仅允许以下 triggers：

```yaml
on:
  pull_request:
  push:
    branches:
      - master
      - "codex/integration/**"
  workflow_dispatch:
```

禁止 `pull_request_target`、`workflow_run`、`schedule`、
`repository_dispatch`、tag trigger 和其他隐式或显式 trigger。

### Checkout、actions 与权限

- `actions/checkout` 固定为
  `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`
  （reviewed upstream tag `v6.0.2`），设置 `ref: ${{ github.sha }}`、
  `fetch-depth: 0`、`clean: true` 和 `persist-credentials: false`。
- 每个外部或 GitHub-authored `uses:` 必须固定到经 review 的完整 40-hex commit
  SHA；tag、branch、短 SHA、floating major version 和 reusable workflow
  floating ref 均禁止。M0 workflow 不使用 local/composite action。
- workflow 顶层权限只能是 `permissions: { contents: read }`。根据 GitHub
  permissions 语义，未列出的权限均为 `none`；job 不得声明或提升权限。
- workflow 不读取 `secrets.*`，不配置 environment，不上传或发布 binary、
  config、pcap 或 raw log。

每个 job 在 checkout 后、生成任何文件前必须证明工作树 clean，并断言
`git rev-parse HEAD` 等于 `GITHUB_SHA`。`pull_request` 与
`workflow_dispatch` run 可提供诊断，但 M0 close evidence 只接受一次完整
`push` run：同一 run ID、同一 run attempt 的 11 个 required jobs 全部 success，
且其 `GITHUB_SHA` 精确等于 Team Lead 批准并另行授权推送的 integration commit。
不得拼接多个 run/attempt/commit 的成功 job。

### Required job、runner 与 timeout

job ID 和 displayed `name` 必须同时精确等于下表；matrix expansion 或 suffix
不得改变 required check name。每个 job 显式设置数值
`timeout-minutes: 60`，不得使用 `continue-on-error`。

| Required job | `runs-on` | `timeout-minutes` |
|---|---|---:|
| `m0-host-quick` | `ubuntu-24.04` | 60 |
| `m0-security` | `ubuntu-24.04` | 60 |
| `m0-lifecycle` | `ubuntu-24.04` | 60 |
| `m0-local-e2e` | `ubuntu-24.04` | 60 |
| `m0-integration-full` | `ubuntu-24.04` | 60 |
| `m0-msrv` | `ubuntu-24.04` | 60 |
| `m0-windows-msvc` | `windows-2022` | 60 |
| `m0-linux-gnu` | `ubuntu-24.04` | 60 |
| `m0-linux-musl` | `ubuntu-24.04` | 60 |
| `m0-interop-sing-box` | `ubuntu-24.04` | 60 |
| `m0-interop-shadowsocks-rust` | `ubuntu-24.04` | 60 |

`ubuntu-latest`、`windows-latest` 和其他 `*-latest` label 禁止。required jobs
不 restore/save Actions cache 或 Cargo cache，不能以 cache output/hit/miss 决定
是否执行命令。platform 与 interop job 必须在自己的 clean VM 内从当前 checkout
构建 ferrum2 binaries；不得下载、复用或消费另一个 job/run 的 ferrum2 artifact。

### Platform commands 与证据

Rust versions 保持 ADR-0001/0006 的固定值：MSRV 1.85.0，current target build
1.97.1。四个 platform config fixtures 固定为：

```text
tests/platform/config/client-valid.toml
tests/platform/config/client-invalid-key-length.toml
tests/platform/config/server-valid.toml
tests/platform/config/server-invalid-key-length.toml
```

它们只含 synthetic PSK。valid 必须 exit 0，invalid key length 必须 exit 2，且均不
创建 listener。

`m0-linux-gnu` 在 `ubuntu-24.04`：

```text
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-gnu
target/x86_64-unknown-linux-gnu/release/ferrum2-client --config tests/platform/config/client-valid.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-client --config tests/platform/config/client-invalid-key-length.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-server --config tests/platform/config/server-valid.toml --check-config
target/x86_64-unknown-linux-gnu/release/ferrum2-server --config tests/platform/config/server-invalid-key-length.toml --check-config
cargo test -p ferrum2-m0-harness --test detection_probe --locked
```

它必须实际运行两个 GNU artifacts，记录 `file`、ELF interpreter/`DT_NEEDED`、
required `GLIBC_*` symbols、artifact SHA-256 和 M0-DETECT-002 结果。

`m0-linux-musl` 在 `ubuntu-24.04` 安装并核实
`musl=1.2.4-2`、`musl-dev=1.2.4-2`、`musl-tools=1.2.4-2`，设置
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc`，安装 Rust
`x86_64-unknown-linux-musl` target，然后执行：

```text
cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-musl
target/x86_64-unknown-linux-musl/release/ferrum2-client --config tests/platform/config/client-valid.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-client --config tests/platform/config/client-invalid-key-length.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-server --config tests/platform/config/server-valid.toml --check-config
target/x86_64-unknown-linux-musl/release/ferrum2-server --config tests/platform/config/server-invalid-key-length.toml --check-config
```

对两个 musl binaries 分别运行 `file`、`readelf -hW`、`readelf -lW` 和
`readelf -dW`，保存 sanitized output；任一 binary 出现 `PT_INTERP` 或
`DT_NEEDED`、未被 `file` 识别为 static/static-pie、无法原生运行或 config exit
不符即 FAIL。

`m0-windows-msvc` 保持 native Windows 2022 + VS 2022 build/run，并运行
M0-DETECT-002。详细 job-to-command mapping 由 TEST-0001 冻结。

### Interop、runner evidence 与 failure semantics

两个 interop job 在各自 clean VM 先构建当前 commit binaries。reference archive
下载到 runner temp；必须在 safe extraction 和执行前验证 ADR-0006 既有固定
asset SHA-256/size、version output 和 license record。任何 mismatch、下载失败、
unexpected archive entry、readiness/command timeout 或 child crash 均 FAIL；
不得 fallback 到 `latest`。

每个 required job 记录 `GITHUB_RUN_ID`、`GITHUB_RUN_ATTEMPT`、job name、
`GITHUB_SHA`、`RUNNER_OS`/`RUNNER_ARCH`、`ImageOS`、`ImageVersion`、OS/kernel、
`rustc -Vv`、Cargo 和实际 linker/C compiler version。CI status 还必须链接该
job `Set up job` 中的 exact `Included Software` URL。platform jobs 另记录
artifact SHA-256 与 linkage evidence。

GitHub-hosted VM 不提供本项目可固定的 OCI image digest。上述
provider-native evidence 被批准为 M0 build/config/interop smoke 的 runner
证据；weekly image drift 是显式剩余风险。它不能替代 M3 的完整平台、生命周期、
operator 或 packaging qualification。

required job 已启动后发生 setup、network、package、reference、command、timeout
或 evidence failure，job 结果为 **FAIL**。required job 因 provider outage、
权限/配额、未授权 push、workflow 缺失或未调度而没有可审计结果，M0 evidence
状态为 **BLOCKED**。missing、cancelled、skipped、neutral 或 unavailable
均不得解释为 PASS。

## Consequences and tradeoffs

### Positive

- M0 required evidence 可绑定到一个已推送 exact integration commit。
- native Windows/Linux、reference 和 platform jobs 在彼此隔离的 fresh VM 内
  自行构建，消除本机/WSL2 与 cross-job artifact 偶然状态。
- action supply chain、token、trigger、timeout 和 unavailable 语义均可静态审计。

### Negative

- GitHub-hosted images 每周滚动，固定 OS label 并不等于 immutable image。
- provider/network/package outage 会阻塞 M0 close。
- 11 个无 cache 的 clean builds 增加执行时间，但 M0 required evidence 更易审计。

## Compatibility and upstream divergence

ADR-0006 继续规范 reference pins、protocol fixture provenance、interop cases 和
platform smoke semantics；本 ADR 只绑定 provider、runner 和证据表达。reference
行为不能改写 SIP022，也不能为 GitHub 环境引入协议例外。

M0 在 hosted runners 上通过只证明 approved AES-128 TCP slice 的 build、config、
native detection、interop 和 integration gates；不得表述为 M3 三目标完整资格或
M4 performance/resource qualification。

## Migration and rollback

M0-T08 在 execute 时创建 workflow 前，Team Lead 必须取得用户对 remote
初始化/URL 修正（若实际需要）、`codex/integration/m0` CI branch push 和
GitHub Actions execution 的单独明确授权。当前本地 `origin` 的存在不等于授权，
本次 plan 不修改或验证 remote capability。

rollback 是在本地回退 workflow/contract integration commit；任何远程 revert、
branch deletion、workflow rerun 或设置变更仍需单独授权。没有产品数据或协议迁移。
改变 provider、workflow path、job names、runner labels、trigger/permission
surface 或 evidence semantics 需要新的 ADR/spec amendment。

## Verification plan

- M0-CI-001：唯一 workflow path 与 exact trigger allowlist；拒绝
  `pull_request_target` 和其他 trigger。
- M0-CI-002：11 个 job ID/display name、runner mapping 和数值 timeout 精确。
- M0-CI-003：permissions、checkout SHA/options 与所有 `uses:` full-SHA policy。
- M0-CI-004：job-to-command、clean current-SHA build、无 cache dependency 和无
  cross-job ferrum artifact。
- M0-CI-005：musl pin/static proof、GNU native smoke/detection、runner evidence、
  reference verification-before-execution 和 synthetic-no-secrets policy。
- M0-CI-006：一个 pushed exact integration SHA、单一 run/attempt 的 close evidence。
- ADR-0006 的 M0-INT-001～004、M0-PLAT-001～003、M0-MSRV-001、
  M0-GATE-001～002 全部保持 required。

## References

- `docs/adr/ADR-0006-m0-interoperability-provenance-and-platform-evidence.md`
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub-hosted runner images](https://github.com/actions/runner-images)
- [Ubuntu 24.04 musl 1.2.4-2 source package](https://launchpad.net/ubuntu/noble/+source/musl)
