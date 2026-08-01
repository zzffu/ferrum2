# ferrum2 v0 M3 差距分析与关闭结论

## M3 关闭结论

M3 已在 local integrated/evidence source
`d784b06171723bb93fd467cea1a799f58f7d60b0` 完成关闭复核。Remotely
qualified product SHA 是其直接父提交
`d9e59d787c3fe78dfca778ee8a36668a45387368`；GitHub Actions run
`30494736004` attempt `1` 在同一 SHA 上通过 quality、MSRV、Windows MSVC、
Linux GNU、Linux musl、TCP/UDP interop 和 final qualification。两个早期失败
runs 保持失败历史，没有证据拼接。

| Planning gap | Close result | Primary close evidence |
|---|---|---|
| GAP-M3-O01 | satisfied | ADR-0023、T01 preserved parser-accepted cohort/effective-value table |
| GAP-M3-O02 | satisfied | T01 non-exhaustive architecture/dependency/deep-seam guards |
| GAP-M3-O03 | satisfied | T06 client/server stable exit/run-code/redaction 与 zero-resource validation table |
| GAP-M3-O04 | satisfied | T02 closed trace fields、exact fourteen metric families、cardinality/secret sentinels |
| GAP-M3-L01 | satisfied | T03 reusable `ProcessSupervisor` state/rollback/owner/cancellation evidence |
| GAP-M3-L02 | satisfied | T06 production adapters、terminal-root arbitration、single grace/force/reap |
| GAP-M3-L03 | satisfied | T06 每 binary 至少 100 bounded cycles、half-close、UDP 与 immediate rebind |
| GAP-M3-P01 | satisfied | T05 native release lifecycle、SHA-256、PE/ELF/GLIBC/static-musl evidence |
| GAP-M3-G01 | satisfied | exact `d9e59d78...` run `30494736004/1` seven-job fail-closed convergence |

M3-T04 在唯一 full/repair/targeted review lifecycle 后保持 `deferred`；
M3-T06 导入其未集成产品 lineage，修复 terminal UDP circular wait 与 forced-root
bound，并通过 fresh bounded reviews。因此 T04 的诚实 deferral 不留下未交付的
M3 lifecycle outcome。当前 `done=7`、`deferred=1`、active phases/open roots
均为空；性能基线与单主机bounded 10k-idle resource qualification仍属于
proposed M4。

## Planning 证据基线（历史）

本分析在 2026-07-29 的 M3 planning source
`master@3a877b6beeb955b5237ab4048f8dec02a92f06b6` 更新。M2 exact qualified
product SHA 是 `7907cda05a56e1c3b85af2dd8faeb85a385154b7`；GitHub Actions
run `30425476328` attempt 1 在同一 SHA 完成 local/full、Rust 1.85、
Windows/Linux GNU/Linux musl、TCP 12/12、UDP 12/12 和 focused IPv6 direct
target evidence。完整证据见 roadmap、CI status与M2 handoff。

当前 shipped facts：

- 两个 binary 在进入 `run::run` 前加载 typed v1 config；`--check-config` 在
  listener 前完成，CLI 具有0/1/2 exit classes和四类stable config errors。
- Config current validated endpoint types是`SocketAddrV4`；client有单
  `listen/server`，server有单`listen`；这只是当前shape，不是future topology。
- `ferrum2-observability` 已有closed JSON fields和七个TCP + 七个UDP metric
  families；secret/destination cardinality tests存在。
- `ferrum2-runtime` 已有`BoundedSupervisor`、`OwnerRegistry`、absolute phase
  deadlines、TCP relay/half-close/shutdown和bounded UDP session runtime。
- Client/server `run.rs` 分别协调 runtime/listeners/metrics/shutdown；server
  的部分fallible root preparation仍发生在root polling路径中。
- CI 已有三个exact target的locked build/config smoke和musl static checks，
  但M0的ADR-0006明确把full native lifecycle/artifact qualification留给M3。
- Planning test budget：code `11714`、tests `19234`、ratio `1.641967`；
  baseline commit `7907cda`，ratchet step `0.05`。

QA 在 planning baseline 上运行：

- config contract：7 passed；
- metrics/tracing contract：4 + 3 passed；
- runtime lifecycle/shutdown/UDP：13 + 3 + 12 passed；
- architecture/CLI/config process：7 + 3 + 3 passed。

这些结果是M3 entry/regression evidence，不证明M3实现或release qualification。

## M3 planning 差距（已在关闭时满足）

| ID | 当前代码/证据 | M3 必须结果 | 严重度 | Primary owner/evidence |
|---|---|---|---|---|
| GAP-M3-O01 | ADR-0003/0022分别记录v1行为，但没有跨release preserved cohort、兼容窗口、additive/new-version规则 | 所有M3合法v1配置的effective-value guard；v0.x + successor后12个月/2 minors/prior notice；no heuristic fallback | P0 | M3-T01；config cohort table |
| GAP-M3-O02 | architecture test断言exact十members和“all future targets”；validated endpoints当前IPv4 | 保留dependency/deep-module合同，同时显式允许future members、IPv6/richer endpoints和topology extension | P0 | M3-T01；non-exhaustive architecture guard |
| GAP-M3-O03 | config errors稳定，但`main.rs`丢弃run error cause；exit 1无stable classification | 固定CLI/0-1-2 exits和closed redacted startup/runtime/shutdown codes | P0 | M3-T04；CLI/run process table |
| GAP-M3-O04 | trace/metrics实现及tests存在，但stable compatibility/evolution policy未统一 | exact fields、十四family name/type/labels/meaning、redaction和additive-only policy | P0 | M3-T02；existing identity/sentinel tables |
| GAP-M3-L01 | runtime已有per-flow supervisor/owners，但没有all-root prepare/activate transaction | topology-neutral Validated→Prepared→Active→Quiesce/Drain/Stop supervisor，deterministic rollback | P0 | M3-T03；paused-time fake-root state table |
| GAP-M3-L02 | binary-local root coordination重复；server有partial activation risk | current TCP/UDP/metrics adapters全部prepare后poll；fatal arbitration/cancel/reap统一 | P0 | M3-T04；production-used process table |
| GAP-M3-L03 | existing lifecycle tests分散证明若干路径，未形成完整process repeated contract | minimum 100 bounded startup/failure/shutdown/rebind cycles，无owner growth/leak | P0 | M3-T04；existing lifecycle cycle harness |
| GAP-M3-P01 | target matrix主要证明build/config smoke；native artifact hash/linkage/lifecycle不完整 | Windows PE、GNU ELF/GLIBC、musl static/static-PIE；release binaries native config/signal/rebind；SHA-256 | P0 | M3-T05；direct runner evidence |
| GAP-M3-G01 | M2已有same-SHA gate，但M3新full/native lifecycle evidence尚不存在 | same exact SHA/run/attempt上的full/security/TCP12/UDP12/three targets/budget/no blocking roots | P0 | M3-T05；fail-closed completion summary |

## 已批准的 M3 决策

1. **兼容 cohort：**ADR-0023保护M3 close时全部合法v1 config，不把representative
   fixture缩成完整集合；结束支持需同时满足time/release-count/notice。
2. **演进：**future v1只允许optional/additive或safe widening且omission保留旧
   behavior；breaking change使用显式新schema，old binary forward-read不保证。
3. **可观察合同：**CLI flags、0/1/2 classes、four config codes、eight run codes、
   closed trace fields和十四metric family identity/meaning稳定。
4. **生命周期：**ADR-0024固定observable state/outcomes、prepare-before-poll、
   transitive single ownership、monotonic cancellation/deadlines、rollback、
   graceful/forced/reap；不固定helper API。
5. **平台：**固定三个existing targets；native release binaries、hash、linkage、
   bounded lifecycle是primary evidence，不要求archive/installer/publication。

## 明确延期或非差距

以下不是M3缺陷，也不得在execute中静默加入：

- multi-inbound、multi-outbound、routing rules、DNS proxy/resolver、multiple
  upstreams、load balancing、proxy chaining；
- Linux transparent inbound、Windows TUN、SOCKS5 UDP ASSOCIATE或其他public
  UDP inbound；
- SIP023/multi-user、多PSK product behavior、hot reload、management API；
- schema v2或actual IPv6 operator endpoint widening（只保留兼容路径）；
- M4 可复现 throughput 基线（比值非 preview 硬门）与单主机bounded 10k-idle
  resource qualification；
- archives、installers、signing、upload或publication。

## 风险与控制点

| 风险 | 等级 | 控制 |
|---|---|---|
| representative fixtures被误当完整compatibility集合 | P0 | spec定义parser-accepted cohort；fixture只作guard；Architect/QA review |
| topology compatibility被误写成exact member/binary/listener freeze | P0 | ADR-0023 + T01替换exhaustive assertions |
| config通过后partial root activation | P0 | ADR-0024 prepare-all-before-poll；failure-position rollback table + real bind row |
| root/child double owner、late completion resurrection或cleanup假成功 | P0 | transitive ownership、generation/cancel lineage、snapshot/reap table |
| timeout在candidate/retry/relay阶段重置 | P0 | monotonic absolute deadline paused-time rows |
| run errors泄密或metric/trace identity repurpose | P0 | closed codes/categories、exact identity tables、secret/destination sentinels |
| native artifact只cross-build未执行或self-test冒充PASS | P0 | direct native release execution、linkage/hash、missing/setup=BLOCKED |
| full/interop/platform evidence来自不同SHA/run/attempt | P0 | one fail-closed exact-SHA completion summary |
| tests继续以比production更快速度膨胀 | P1 | reuse tables；ticket delta allowance 120；milestone ratchet约1.591967 |
| hosted runner/provider unavailable | P1 | release BLOCKED；不重开product ticket，除非证据指向product defect |

## Planning 票据依赖与执行前沿（历史）

```text
M3-T01 config ─────────┐
M3-T02 observability ──┼─ M3-T04 binary composition ── M3-T05 qualification
M3-T03 supervisor ─────┘
```

M3-T01/T02/T03 ownership-disjoint，是initial frontier且符合
`max_parallel_engineers = 3`。T04 implementation/integration等待三票；T05
implementation/integration等待T04，release等待T01～T04。每票由Architect/QA
各一次exact-candidate full review；仅blocker/major阻断，至多一次substantive
repair和一次targeted re-review。

Execute 不隐含 remote authority。M3 实际执行中只使用了 exact、single-use
授权把 `bba40d12...`、`bc14971c...` 和最终 `d9e59d78...` 依次
non-force fast-forward 到 `refs/heads/codex/integration/m3`；所有授权均已
耗尽并撤销。Close mode 没有 push、rerun、dispatch、PR、tag、release、
publication 或 ref deletion。关闭后的下一入口是显式
`mode=plan milestone=M4`。
