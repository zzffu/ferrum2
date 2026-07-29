# TEST-0004: M3 operational, lifecycle, and platform contract

- **Status:** Approved
- **Milestone:** M3
- **Spec:** `docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md`
- **Gate profile:** strict

## Risk summary and cheapest reliable seams

最高风险不是新增 wire behavior，而是把既有 operator behavior意外改坏、partial
startup 已服务、root/child 失去 owner、shutdown 假成功，以及不同 SHA/platform
evidence 拼接。Cheapest reliable seams：

1. existing config/observability table tests冻结 identity/effective values；
2. paused-time runtime table证明 state/owner/deadline；
3. production-used local process adapter证明 OS listener/signal/rebind；
4. native release runners证明 artifact/linkage，external interop证明兼容。

M3 只允许一个有独特 failure mode 的新 seam：**native release-artifact lifecycle
observation**。不得为每个 MUST/branch/helper 新建 harness，也不得把现有 platform
helper 的 self-test/mutation 当成 product 或 release PASS。

## MUST-to-primary-evidence matrix

| MUST / invariant | Primary evidence | Gate | Distinct uncovered failure mode |
|---|---|---|---|
| M3-MUST-01 preserved v1 cohort | one config effective-value/invalid table using committed synthetic fixtures | product | future time-window compliance remains a release obligation |
| M3-MUST-02 evolvable topology/version rules | architecture dependency/deep-boundary assertions plus explicit non-exhaustive member/target row | product | none |
| M3-MUST-03 CLI/exits/errors/zero-resource validation | existing `config_cli` + `cli_contract` process table | product | native release binary repeated in MUST-09 for artifact mismatch |
| M3-MUST-04 trace identity/redaction | existing `tracing_contract` closed-field/sentinel table | product | process startup run-code row in MUST-08 |
| M3-MUST-05 metric identity/semantics | existing `metrics_contract` exact fourteen-family/type/labels table | product | native endpoint availability in MUST-09 |
| M3-MUST-06 prepare/rollback/ownership | one paused-time supervisor state/owner snapshot table | product | real bind/activation in MUST-08 |
| M3-MUST-07 cancel/deadline/isolation/shutdown | existing lifecycle/shutdown/half-close/backpressure/UDP tables extended by state rows | product | OS signal/rebind in MUST-08 |
| M3-MUST-08 binary composition/100 bounded cycles | existing local process lifecycle suite with production-used adapter | integration | native release/linker differences in MUST-09 |
| M3-MUST-09 three native targets | direct runner execution + artifact SHA-256/linkage reports | release | none |
| M3-MUST-10 same-SHA convergence | one fail-closed CI evidence summary keyed by exact SHA/run/attempt | release | none |

Additional evidence is justified only where the last column names a distinct boundary。

## Product gate commands

### M3-T01 — config compatibility

```powershell
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-config --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

### M3-T02 — observability

```powershell
cargo test -p ferrum2-observability --test metrics_contract --test tracing_contract --locked
cargo clippy -p ferrum2-observability --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

### M3-T03 — reusable supervisor

```powershell
cargo test -p ferrum2-runtime --test lifecycle --test shutdown --test half_close --test backpressure --test udp_runtime --locked
cargo clippy -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

### M3-T04 — current binary composition

```powershell
cargo test -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test cli_contract --test config_cli --test lifecycle_cycles --test local_e2e --test udp_local_e2e --locked
cargo clippy -p ferrum2-client -p ferrum2-server -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

### M3-T05 — qualification implementation

```powershell
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

T05 local tests validate fail-closed evidence parsing/markers only；它们不 substitute
native execution，且不得通过自测/模拟一份平台报告来声称 target PASS。

## Integration gate commands

在 milestone integration worktree 串行运行 `workflow.toml` authoritative full：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate milestone --base <milestone-base-sha>
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py validate
git diff --check
```

Full gate不得并发运行于多个 worktree。Security/config/observability/runtime/process
suites由 workspace all-features command 包含；若实现改变 suite routing，必须在
candidate review 前记录等价映射。

## Release qualification

### Artifact build identity

每个平台 job 先校验 `git rev-parse HEAD == <candidate-sha>`，使用 lockfile 与
repository-pinned toolchain：

```text
cargo build --workspace --bins --release --locked --target <target>
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --release --locked --target <target>
```

保存两 binary 的 SHA-256、size、toolchain/runner identity 和 exact target。
Artifacts/logs/linkage reports 是 generated evidence，不提交仓库；不要求 archive、
installer、signature、upload 或 publication。

### Native target matrix

| Target | Required direct observations |
|---|---|
| `x86_64-pc-windows-msvc` | native `.exe` help/version；valid/invalid check-config；startup rollback；Ctrl-C/equivalent graceful + forced path；restart/rebind；`dumpbin /headers` and `/dependents`；SHA-256 |
| `x86_64-unknown-linux-gnu` | native help/version/config/lifecycle/rebind；`file`、`readelf -h -l -d`、`objdump -p`；record GLIBC requirements；SHA-256 |
| `x86_64-unknown-linux-musl` | native help/version/config/lifecycle/rebind；`file`/`readelf` prove static or static PIE，no `PT_INTERP` and no `DT_NEEDED`；SHA-256 |

每个平台对 client/server 使用 synthetic config，至少覆盖 valid check、redacted
invalid、occupied proxy/metrics resource rollback、signal shutdown 与 immediate
rebind。每个 required marker 恰一次；timeout、skip、missing tool/setup、wrong
architecture 或 non-native execution 是 `BLOCKED/FAIL`。

### Same-SHA external and close evidence

- 复用固定 sing-box `1.13.14` 与 shadowsocks-rust `1.24.0` pins；
- TCP M1-INT-001～012 和 UDP M2-UDP-INT-001～012 各 `12/12` + cleanup；
- setup failure 不短路后续 cases，但 final status 非零；
- full、interop、three targets 与 evidence summary 均指向同一
  SHA/run/attempt；
- no required job skipped/cancelled；unavailable provider 是 release BLOCKED；
- release failure 只有在指向 shipped behavior defect 时才重开 product ticket。

## Fixtures and harness economy

- 扩展 `crates/ferrum2-config/tests/config_contract.rs` 的既有 table 与
  `tests/fixtures/config/**`，不按 field 建 fixture。
- 扩展 observability existing exact identity/sentinel tables；不再建 process
  logging harness。
- Runtime state table复用 `OwnerRegistry`、paused Tokio time、existing fake
  roots；real-process只留一个 production-used adapter。
- T04 复用 `tests/m0-harness/src/local_support/**`；100 cycles共享 scenario rows，
  不构造 method×platform×failure 全 cross product。
- T05 可替换不能证明 native artifact 的 helper invocation；只有发现具体独立
  failure mode 时才增加第二个 platform harness。

## Test-budget expectation

Planning baseline (`7907cda05a56e1c3b85af2dd8faeb85a385154b7`)：
code `11714`、tests `19234`、ratio `1.641967`。Ratchet step `0.05`，在 code
volume 不变时 milestone 目标约为 `<=1.591967`；authoritative script按实际 delta
计算。每票 tests delta 不超过 code delta + `120`；尤其 T05 test-only growth
保持一个 allowance 内。不得用无意义 production lines 改善 ratio。

## Exit conditions and accepted gaps

Blocking：

- 任一 MUST primary evidence FAIL/skip/missing；
- open blocker/major 或 second targeted blocking review；
- test-budget regression；
- wrong/mixed SHA，缺 native/linkage/hash 或 hosted provider unavailable；
- product owner snapshot/rebind failure。

Accepted gaps/debt：

- 兼容窗口的时间与 release-count 条件是后续 release obligation；M3 只证明
  policy/cohort guard。
- QA-M3-PLAN-N01～N06 是 planning constraints，不是额外 test layers。
- M4 throughput、RSS/tasks、10k idle 和 long soak；future topology features；
  archives/installers/publication 均不属于 M3。
