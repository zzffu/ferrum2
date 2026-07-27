# ADR-0016: M0 invariant-first contract and equivalent evidence substitution

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；`TEST-0001`；
  M0-T01、M0-T02、M0-T03、M0-T06、M0-T07、M0-T08；部分取代 ADR-0001 的永久
  manifest/lock ownership、ADR-0004/0008 的 provenance-correction process、
  ADR-0005/0011/0013/0015 的 evidence mechanism 与 exact test-only dependency
  allowlist、ADR-0006/0014 的 external half-close evidence mechanism，以及
  ADR-0009/0010/0012中明确列出的manifest/test/private-helper spelling；不取代任何
  密码、SIP022 wire、安全、production package identity/resolved feature、
  production interface semantics、产品行为、平台结果或 release gate

## Context and problem

M0 已经通过 ADR-0008、ADR-0011、ADR-0013、ADR-0014 和 ADR-0015 纠正多项
合同缺口：

- 两组不变的 AES-GCM numeric cases 被错误绑定到不包含它们的 CAVP archive；
- black-box child process 被要求证明其无法观察的进程内 task/resource state，
  historical fixture 又被要求构造其无法认证的 current-time semantic branches；
- deterministic binary paused-time tests 被要求使用 package-local capability，
  同时 manifest ownership 又禁止添加该 test-only edge；
- external interop 将未规定的 FIN/payload 顺序强化为 pinned peer 不支持的
  post-FIN reverse-production requirement；
- exact-rebind probe 和固定 harness dependency allowlist 无法表达选定的
  platform-specific listener policy。

这些修订均保持了结果性不变量，但每次都必须先把某个具体 fixture、probe、
dependency edge 或 ownership 安排从“唯一合同”改回“证明合同的手段”。继续把
证据手段写成不可替代的架构决定，会让事实勘误和等价证据修复重复成为串行
contract blocker；反过来把所有测试手段都视为可选，又会允许以“等价”为名降低
安全与 release gate。

## Why this requires an ADR

本决定同时影响 dependency/lock ownership、密码与供应链 provenance、
进程内/黑盒 evidence claim、platform listener evidence、external interoperability
以及 M0 exact-SHA close gate。它需要一个跨模块、可审计的边界来区分哪些内容是
不可降低的规范性不变量，哪些只是当前选定的 conformance profile，以及何时一个
替代证据需要 ADR、spec amendment、ticket amendment 或仅机械修复。

## Decision drivers and invariants

- SIP022 revision、wire bytes、KDF、nonce、authentication/validation ordering、
  replay、binding、secret lifetime、abortive/normal close classification保持不变。
- v0/M0 product scope、config/API、one-owner-task lifecycle、half-close behavior、
  immediate-restart/live-owner-exclusion outcomes保持不变。
- 四项 pinned external interop、MSRV、Windows/GNU/musl、十一项 GitHub Actions
  job、同一 exact pushed SHA 和 11/11 success close gate保持不变。
- missing、skipped、zero-test、unavailable、timeout、unreviewed fixture 或不完整
  evidence 仍不是 PASS。
- evidence 只能声称其 seam 实际观察到的事实；不得循环调用被测 production
  implementation 来制造独立 oracle。
- 当前已批准并已实现的 exact profiles 保持有效；本 ADR 本身不把任何 open
  blocker、失败 run 或未执行 command 改成 PASS。

## Options considered

### Option A：normative invariant + selected conformance profile + bounded substitution

把不可降低的产品/安全/release outcome 与当前证据配置分层。允许在严格等价条件、
明确 ownership、受影响 gate 重跑和 exact candidate-SHA review 下替换证据手段。

### Option B：继续把每个 fixture、dependency edge 和 probe 写成永久 ADR 条款

最容易静态比较，但已经反复把事实勘误、test-only capability 与平台 plumbing
变成不必要的 product-contract blocker。

### Option C：任何能让测试通过的替代都视为等价

速度最快，但无法防止 circular oracle、coverage 缩减、平台替代、skip-pass 或以
文档修改抹去真实失败。

## Decision

### Three contract layers

M0 合同分为三层：

1. **Normative invariant**：产品、wire、安全、public API、平台 outcome 或
   release claim。改变它必须有新的 ADR/spec revision，且不能由 repair
   authorization、review verdict 或 passing test隐式改变。
2. **Selected conformance profile**：当前批准的 test matrix、fixture/probe、
   dependency edge、runner、command 和 evidence mapping。它是默认且可复现的
   证明路径，不自动等于唯一可能的证明。
3. **Mechanical realization**：line-ending normalization、完整 test name/filter、
   executable/linker discovery、同义 parser helper 或其他不改变 claim/coverage/
   failure semantics 的实现细节。它按 ticket 范围修复并只重跑被影响的中间 gate；
   最终 release candidate 仍运行完整 exact-SHA gates。

### Closed protected/profile matrix

只有下表“可替换profile/mechanic”列明的内容可以使用本ADR。未列出的内容默认属于
protected boundary并fail closed；不能用“等价”自行扩大清单。

| Contract area | Protected boundary | Replaceable selected profile/mechanic | Minimum unchanged coverage/gate |
|---|---|---|---|
| SIP022/crypto | wire、KDF、nonce、auth ordering、replay、binding、secret lifetime、package identity与resolved zeroize features | test helper、recording adapter、fixture读取/比较实现 | 全部既有正负向/KAT/ordering/mutation；Architect+QA |
| Production dependency/API | package name/version/source/checksum/license、resolved production features、workspace public/cross-crate capability semantics | 在相同package identities和相同resolved feature outcome下的manifest declaration/anchor spelling | locked metadata/tree/MSRV/full；Architect+QA |
| Test-only dependency | production/release graph不得含test capability | package-local dev/test edge的placement或等价固定test dependency | exact lock delta、license/provenance、排除dev的production tree；Architect+QA |
| Lifecycle | one-owner、bounds、partial stats、half-close、cleanup、五类各至少20次 | private registry/helper名称、test file/process组织 | success/auth reject/connect failure/cooperative cancel/forced termination各≥20，逐cycle cleanup/rebind；Architect+QA |
| Native detection | fixed single-I/O/detection semantics、Windows+GNU native、每案target=0 | independent generator/helper/process组织 | prefixes `0..42` exhaustive，加Authentication/InvalidType/TimestampSkew/AddressBounds四行，共47；Architect+QA |
| Deadline evidence | separate configured connect/fresh first-write deadlines、default/non-default、no hardcode | package-local controlled-time tool/helper | paused/controlled deterministic time同时杀死hardcode与wall-clock mutation，production graph无test feature；Architect+QA |
| External interop | exact pins/checksums、四reference/direction、双向bytes、ordered clean EOF、本地post-FIN drain | payload字面值、test/helper/filter mechanics | 每方向distinct payload≥16386 bytes且FIN前逐byte相等，四案独立；Architect+QA |
| Listener restart | terminated owner exact-address immediate restart、live-owner exclusion、Windows default exclusive、no reuse-port | same-policy bind/probe helper与test-only socket dependency | 五类cycles内逐案bind+listen，Unix/Windows分别证明；Architect+QA |
| Provenance | fixture/reference bytes、expected result、accepted actual source/artifact identity、pin、license/distribution conclusion | 错误attribution的受审事实勘误、URL mirror、size/hash转录、metadata layout | byte identity、source/rights evidence、superseded trail、scope/provenance tests；Architect+QA |
| GitHub Actions | ADR-0007全部provider/path/trigger/action pin/permission/job ID+name/runner/timeout、exact pushed SHA、one run/attempt、11/11 | shell spelling、完整test filter、compiler/linker executable discovery与evidence formatting | 同一11 jobs全部执行且fail-closed；QA，涉及security/supply-chain时Architect |

### Equivalent evidence substitution

替换 selected conformance profile 的一部分时，变更记录必须同时给出：

- 被证明的 exact AC/invariant 与原 evidence claim；
- 原 seam/profile 无法诚实证明或无法跨平台执行的具体证据；
- 新 seam/profile 的可观察量、正负向 failure modes、determinism、bounds 和
  cleanup；
- production-oracle independence、secret/provenance 和 platform边界；
- 精确 ownership paths、candidate SHA、受影响 commands/gates 与旧 evidence 的
  superseded 状态。

替代只有在以下条件全部满足时才是 equivalent：

- 不删除、跳过、xfail、缩短或合并独立 required outcome；
- 不用一个平台、reference、方向、ticket 或本机结果替代另一个 required result；
- coverage 与 mutation/failure discrimination不弱于原 claim；
- fail-closed，零测试、setup failure、timeout 和证据缺失均不能 false-pass；
- 不扩大 product/operator surface，不暴露 secret，不引入 circular oracle；
- 在新的 exact candidate SHA 上实际执行全部受影响 gate。文档批准本身不是 PASS。

定量floor只能在新的ADR/spec中降低。超过floor、增加mutation或以更强deterministic
proof替代重复组织仍须在执行前映射；reviewer必须明确说明为何不是coverage减少。

仅改变 evidence/profile、且上述 invariant 不变时，不要求新的产品 ADR：

- Product 只在 scope、operator claim 或 milestone exit criterion 改变时重审；
- security/protocol/cross-module/production dependency graph 由 Architect 复核；
- test/evidence mapping 与 gate validity 由 QA 复核；
- final integrated/release SHA 仍执行配置的完整 gate。

### Manifest, dependency, and lock ownership

ADR-0001 的 T01 ownership 是避免并发 writer 的默认协调策略，不再是整个 M0 的
永久写禁令。实现或证据发现已批准 invariant 需要一个遗漏 edge 时，可以通过
ticket amendment 和运行时 authorization 把精确路径临时租给一个 exclusive
writer，而不创建新的产品 ADR，前提是：

- 同一 manifest/lock family 同时只有一个 writer；
- production package identity、版本、source、checksum、license与resolved feature
  outcome不得改变；
- test-only edge 保持 package-local/dev-kind，不进入 release graph；
- production declaration/feature-anchor只能在已经批准的package identities与
  resolved feature outcome内改变spelling/placement；新增package、启停resolved
  feature或改变public API、wire、unsafe、license、产品behavior仍必须新ADR；
- `Cargo.lock` delta、metadata/tree、workspace-policy、MSRV 与受影响 full gate
  全部重跑。

因此 ADR-0009 的 `aes`/`ghash` zeroize package identities与resolved feature sets
保持规范性；其manifest/policy helper spelling、ADR-0011/0015 的 harness edges
和 ADR-0013 的 binary Tokio dev edges仍是当前 M0 selected profile，但不再被描述
为未来唯一合法的实现。任何替代在合入前必须先更新 ticket/test mapping并提供上述
等价证据；不得用本 ADR 删除当前 edge 或绕过其 gate。

### Provenance corrections

fixture bytes、expected result、wire behavior 和 product claim 不变时，错误的来源
attribution可以通过evidence amendment改为有证据的actual source identity；URL
mirror、作者、archive entry、size/hash转录或metadata layout也可一并修正。此类
勘误不再要求新的产品ADR，但必须由Architect与QA复核。勘误必须：

- 保留错误记录并明确 superseded；
- 固定实际 source、selected entry、hash、classification 与 rights evidence；
- 证明 numeric/byte identity，且不把 hosting/collection 误称为 authorship、
  endorsement 或 validation；
- 通过 scope/provenance 与受影响 fixture tests。

更换fixture bytes、expected cryptographic result、accepted actual artifact、
reference pin，或改变license/distribution decision仍是normative change，必须
单独审查并在适用时新增ADR。事实勘误不能通过降低rights结论来使原本不可分发的
artifact变为可分发。

### Lifecycle, native, platform, and external evidence

- black-box process evidence只证明process、socket、filesystem和application-visible
  outcome；进程内 owner/resource invariant 由production-used private/direct seam
  证明。允许等价的 compositional seam，但不得把外观推断成内部状态。
- time-dependent authenticated negative case可由独立 primitive construction生成，
  不要求复用无法表达当前时间的 historical fixture；仍不得调用被测production
  encoder作为oracle。
- deterministic timeout evidence必须使用受控时间并覆盖default与non-default
  values；当前 package-local Tokio `test-util` 是selected profile，但任何替代都
  必须保持production graph不含test capability并杀死hardcoding/wall-clock mutation。
- external reference只证明双方共同支持且由规范要求的wire/data/ordered-close
  行为。ferrum2更强的post-FIN reverse-drain invariant必须在同一SHA由本地/runtime
  evidence独立证明，不能强迫pinned peer充当其唯一oracle，也不能因此降低
  ferrum2行为。
- listener evidence必须证明terminated-owner immediate restart和live-owner
  exclusion。bind option与probe实现可按平台不同，但probe必须镜像production
  policy；Windows不得因Unix方案放宽其exclusive behavior。

`TransportIo`、`PlainDuplex`、`ConnectedClientOpen`等production/cross-crate
interface的名称、ownership、phase、error与caller-capability semantics不属于可替换
profile。本ADR只放宽private test helper/result carrier spelling；若production
interface需改变，按ADR-0010/0012的架构路径重新修订。

### Current M0 effect and authorization boundary

本 ADR 不回滚或豁免 ADR-0008～ADR-0015 已选择的 M0 profiles，不关闭当前 T07
hosted-rebind 或 T08 evidence-script blocker，不接受 run `30301746374` 的 2/11
结果，也不授权 push、rerun、PR、tag、release 或其他 remote mutation。

当前 T07/T08 repair仍须按已批准 profile完成；若后续确需替代 profile，必须先有
明确 ticket/test amendment、exact authorization scope和新candidate evidence，
不得在失败后以本 ADR 追认旧结果。

## Consequences and tradeoffs

### Positive

- 产品/安全 invariant 继续 fail-closed，同时事实勘误和等价 evidence repair不再
  自动升级为新的产品 ADR。
- manifest/lock 仍保持 single-writer 与可复现审计，但遗漏的 test/security edge
  不再强制回到永久 T01 ownership。
- future reviewer能够准确区分“改变承诺”和“改变证明承诺的方法”。

### Negative

- Architect/QA 必须判断 evidence equivalence，不能只比较固定文件或命令字符串。
- selected profile不再等同永久唯一机制，scope/lineage/evidence记录要求更高。
- production declaration替代若分类错误可能掩盖真实架构变化；因此package
  identity/resolved feature/version/source/API/wire/unsafe/license/behavior任一变化
  都继续fail-closed到新ADR。

## Compatibility and upstream divergence

本 ADR 不改变SIP022、RustCrypto行为、reference pins、Tokio/socket2平台语义或
GitHub-hosted provider contract。它只改变 ferrum2 对内部合同层次和等价证据替换的
治理方式；任何 upstream divergence仍按原 ADR记录并验证。

## Migration and rollback

在 ADR-0001、ADR-0004、ADR-0005、ADR-0006、ADR-0008、ADR-0009、ADR-0010、
ADR-0011、ADR-0012、ADR-0013、ADR-0014 与 ADR-0015保留历史正文，只添加本ADR
的partial-supersession注记。同步更新 SPEC-0001、TEST-0001、
M0-T01/T02/T03/T06/T07/T08 与 roadmap/CI evidence mapping。

本修订不修改 Rust source、workflow、manifest、`Cargo.lock`、fixture、CI job或
runtime ledger。回滚只需移除本 ADR 及同步 mapping；已通过 ADR-0008～ADR-0015
批准的现有 exact profiles继续有效。

## Verification plan

- `workflow.py doctor`、`validate`、`status`、`frontier`、`next`全部成功且无新增
  contract warning。
- 文档审计证明 ADR/SPEC/TEST/ticket 对三层术语、partial supersession、
  no-waiver/no-remote边界一致。
- `git diff --check`与bare-CR检查通过。
- Product确认scope/exit criteria不变；Architect确认security/protocol/dependency
  fail-closed边界；QA确认没有required result被删除且当前open blockers未被改写。

提案提交`a389aa9861806a5d7d0d4fa8f8379f6ecef925d2`（tree
`c2a2bb2bada9c88f912b917da6941370c335c9ce`）已取得Product、Architect与QA
exact-SHA document gate PASS；接受提交只同步decision status与审查记录，不改变
该提案的protected/profile matrix。

## References

- `CONTEXT.md`
- `docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md`
- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/adr/ADR-0006-m0-interoperability-provenance-and-platform-evidence.md`
- `docs/adr/ADR-0008-m0-aes-gcm-kat-provenance-correction.md`
- `docs/adr/ADR-0009-m0-aead-state-zeroize-feature-unification.md`
- `docs/adr/ADR-0010-m0-opaque-sip022-duplex-flow.md`
- `docs/adr/ADR-0011-m0-evidence-boundaries-and-native-detection-probes.md`
- `docs/adr/ADR-0012-m0-phase-deadlines-and-partial-relay-accounting.md`
- `docs/adr/ADR-0013-m0-binary-paused-time-test-boundary.md`
- `docs/adr/ADR-0014-m0-external-half-close-evidence-boundary.md`
- `docs/adr/ADR-0015-m0-unix-listener-restart-and-rebind-evidence.md`
- `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`
- `docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md`
