# ADR-0009: M0 AEAD state drop-zeroize feature unification

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T01、M0-T02；仅部分取代 ADR-0001 的 direct dependency baseline 与一次性 manifest ownership repair 条款

## Context and problem

ADR-0001 为 `ferrum2-crypto` 固定
`aes-gcm 0.11.0` 的 `aes,bytes,zeroize` features，ADR-0002 要求 secret lifetime
证据由 `ZeroizeOnDrop`、显式 clear seam 与依赖审查共同组成。M0-T02 review 对
固定 registry source 与实际 resolved feature graph 的审查发现：

- `aes-gcm/zeroize` 只启用其可选 `zeroize` dependency，并在构造
  `AesGcm` 时清除临时 `ghash_key`；
- 它不转发 `aes/zeroize` 或 `ghash/zeroize`；
- 当前 `cargo tree -p ferrum2-crypto -e features` 因此没有启用
  `aes 0.9.1` 或 `ghash 0.6.0` 的 `zeroize` feature；
- `TcpSealer`/`TcpOpener` 长期持有的 `Aes128Gcm` 因而没有 expanded AES round
  keys 与 GHASH/POLYVAL keyed state 的 upstream drop-zeroize 证据。

M0-T02 repair commit 已为 ferrum2 自有 `NonceCounter` 增加显式 `Drop` zeroize；
剩余缺口不能通过 T02-owned source 访问 `AesGcm` 私有字段来修复。用户已明确授权
本窄修订与一次独占 T01 manifest repair；不得借此改变依赖版本、密码/协议行为、
public API 或产品范围。

## Decision drivers and invariants

- `aes-gcm`、`aes`、`ghash`、`polyval` 与 `zeroize` 的 resolved versions 和
  registry checksums保持不变；完整 lock package identity baseline 也保持不变。
- 不 vendor、patch 或复制 RustCrypto code，不新增 crate package。
- AES/GHASH state 的清除使用固定上游 feature-gated `Drop` implementation；
  ferrum2 不引入 `unsafe` 或对已释放内存做不安全 inspection。
- `aes-gcm 0.11.0` 的 `aes,bytes,zeroize` feature contract、AES-128-GCM API、
  empty AAD、nonce、KDF、ciphertext/tag、SIP022 wire 与错误语义保持不变。
- 只有一个 Engineer 可写 root/member manifests、`Cargo.lock` 与
  `workspace_policy.rs`；T02 仍不得修改 manifest。
- feature graph 必须由自动化 metadata policy 与人工可读 `cargo tree` 双重证明，
  不能把“tests 能通过”替代为 zeroize feature 证据。

## Options considered

### Option A：用 exact direct feature anchors 统一底层 zeroize features

在 workspace 固定 `aes = 0.9.1` 与 `ghash = 0.6.0`，由
`ferrum2-crypto` 以 normal direct dependencies 引用并只启用 `zeroize`。Cargo
feature unification 随后为 `aes-gcm` 内部相同 package instances 启用
`aes/zeroize`、`ghash/zeroize`，后者继续转发 `polyval/zeroize`。

### Option B：每次 operation 临时构造并立即 drop `Aes128Gcm`

这会增加 hot-path key schedule 工作，却仍不能证明未启用 feature 的 expanded
state 在 drop 时清除；同时改变实现性能形状，不能关闭依赖审查 finding。

### Option C：接受 expanded state 不清除

这需要降低 ADR-0002 的既有 secret-lifetime contract。用户没有授权降低安全
合同，而且该缺口可用固定上游 features 窄幅修复。

## Decision

选择 Option A。ADR-0001 的 direct dependency baseline 增加且只增加：

| Crate | Exact version | Feature contract | Purpose |
|---|---:|---|---|
| `aes` | `0.9.1` | no-default；`zeroize` | feature anchor，使批准的 x86_64 build 上 `Aes128` AES-NI/portable backend expanded key state 使用上游 feature-gated drop zeroize |
| `ghash` | `0.6.0` | no-default；`zeroize` | feature anchor；上游继续启用 `polyval/zeroize`，使 GHASH keyed state 在 drop 时清除 |

root `[workspace.dependencies]` 使用 exact requirements：

```toml
aes = { version = "=0.9.1", default-features = false, features = ["zeroize"] }
ghash = { version = "=0.6.0", default-features = false, features = ["zeroize"] }
```

`crates/ferrum2-crypto/Cargo.toml` 的 normal dependencies 增加：

```toml
aes.workspace = true
ghash.workspace = true
```

这两个条目是经批准的 **feature anchors**：production Rust source 不直接导入其
symbols，也不把它们视为新的 cipher/hash API。它们是 ADR-0001“member 只声明
实际使用条目”规则的唯一窄例外，实际用途是为 `aes-gcm` 已解析的相同 package
instances 统一安全 features。

`Cargo.lock` 必须由 Cargo 基于现有 lock 做受控的 in-place manifest-edge update
并提交；不得删除 lock、执行 broad `cargo update` 或从空 lock 重新 resolution。
预期只改变既有 package dependency edges/features 所需的 lock representation；
不得改变任何 package version、registry source 或 checksum，也不得新增 package。
规范性 pre-repair baseline 是
integration checkpoint
`999d4f95a2d597fb283689b9306d2a6773af707d` 的 110 个
`(name, version, source, checksum)` package identity tuples；其 `Cargo.lock` Git
blob 是 `ab04f6dbd696793b67c35b75b818b924ac557c93`。policy test 必须内嵌并
逐项比较这组 identity tuples，不能依赖 checkout 中存在该历史 commit，也不能用
`cargo metadata` 或人工 `cargo tree` 代替 checksum evidence。

`tests/m0-harness/tests/workspace_policy.rs` 必须：

1. 以 CRLF-independent helper 断言 root 两个 exact declarations、workspace
   dependency name set，以及 member 的两个 workspace-inherited declarations；
2. 从 `cargo metadata --locked` 断言 `ferrum2-crypto` 对 `aes`/`ghash` 是
   exact、no-default、normal、unrenamed、unconditional direct feature anchors，
   并且 direct edges 与 `aes-gcm` transitive edges 指向同一个 exact registry
   package ID；每个相关 crate 只允许一个 resolved instance；
3. 对 `resolve.nodes[].features` 断言 exact sets：
   `aes-gcm={aes,bytes,zeroize}`、`aes={zeroize}`、
   `ghash={zeroize}`、`polyval={hazmat,zeroize}` 与
   `zeroize={aarch64,alloc,derive,zeroize_derive}`；因此
   `aes-gcm/hazmat` 与 `aes/hazmat` 必须缺失，而 `polyval/hazmat` 是
   `ghash 0.6.0` 所需的批准 feature；
4. 解析 candidate `Cargo.lock` 并将完整、排序后的 package identity tuples 与
   上述 110-tuple pre-repair baseline exact 比较；package addition/removal、
   version、source 或 checksum 任一变化都失败；
5. 对 root/member manifest helpers 与 lock identity parser 使用相同的 LF、CRLF
   正向 fixture 和 mutation 负向 fixture，证明 line-ending 不影响每项新断言；
6. 保留原 dependency/member/license/unsafe policy assertions。

`cargo tree` 仍可能显示 `aes/default` 与 `polyval/default` dependency edges；在
固定 upstream manifests 中这两个 `default` 都是空 feature，且 Cargo metadata
resolved node feature sets 不包含它们。policy 不得错误拒绝这些空 upstream edges，
但 exact node sets 会拒绝任何实际额外 feature。`aes/zeroize` 还会按固定
`aes 0.9.1` manifest 启用 `zeroize/aarch64`；在 `zeroize 1.9.0` 中该 feature
为空 compatibility feature，仍必须作为完整 feature delta 的一部分被记录和断言。
四条 focused `cargo tree` evidence 必须同时显示这两个批准的空 default edges、
required `polyval/hazmat` 与 `zeroize/aarch64`，不能只截取 headline zeroize
features。

ADR-0002 的语义无需修改；本 ADR 提供其要求的 dependency-review evidence，不把
zeroization 夸大为编译器、操作系统或物理内存保证。

## Consequences and tradeoffs

### Positive

- 在三个批准的 x86_64 repository build configurations 中，
  `TcpSealer`/`TcpOpener` drop 时，固定 RustCrypto 的 runtime-selected AES-NI
  或 portable backend 与 GHASH/POLYVAL keyed state zeroize implementation
  被实际编译；custom upstream backend cfg 需要另行审查。
- 修复只改变 build-time feature graph，不改变 wire、API、runtime state machine
  或产品范围。
- metadata 与 lock identity policy 能阻止未来 dependency upgrade/feature drift
  静默移除证据或改变 package artifacts。

### Negative

- `aes` 与 `ghash` 在 manifest 中成为直接 feature anchors，即使 production
  source 不直接引用 symbols；该例外必须保留解释，不能泛化为任意 unused
  dependency。
- zeroize 仍是 best-effort software guarantee；编译器 copy、寄存器、allocator、
  OS snapshot 与物理介质不在该保证内。
- locked graph 的 direct dependency surface 增加两项，需要重新执行 license、
  MSRV、workspace policy 与完整 M0 scope review。

## Compatibility and upstream divergence

`aes 0.9.1` 声明 `MIT OR Apache-2.0`，`ghash 0.6.0` 声明
`Apache-2.0 OR MIT`；二者已作为 `aes-gcm 0.11.0` transitives 存在于当前
`Cargo.lock`，本修订不引入新 source artifact。ferrum2 不 patch upstream，
只使用其公开 Cargo features。

AES-128-GCM primitive values、SIP022 KDF/framing、nonce sequence、request/response
binding、error mapping、reference interoperability 与三个 release targets 均不变。

## Migration and rollback

没有 config、wire、持久状态或 operator migration。实施顺序固定为：

1. ADR-0009 与 SPEC/TEST/T01/T02 映射通过 Product、Architect、QA document gate；
2. Team Lead 复用并快进 clean `codex/ticket/m0-t01` worktree 到批准的 coordination
   commit；
3. 一个 Engineer 独占修改 `Cargo.toml`、`crates/ferrum2-crypto/Cargo.toml`、
   `Cargo.lock`、`tests/m0-harness/tests/workspace_policy.rs`；
4. Architect/QA ticket gate 与 integration gate 通过后才恢复 T02 integration。

回滚这些 feature anchors 会重新引入已确认的 secret-lifetime blocker，不能作为
静默正常回滚；若未来 crate upgrade 原生转发相同 features，必须以新 ADR 更新
dependency contract 与 evidence 后移除 anchors。

若 isolated repair 的 package identity comparison、feature sets、MSRV、license
或 ticket regression 任一失败，Engineer 不得提交候选；应保留失败证据并交回
Team Lead。Team Lead 不得把该 worktree/commit 合入 integration，T01/T02 保持
blocked，并在原 coordination checkpoint 上要求新的 ADR/授权。不得以删除 security
anchors、换版本或 broad re-resolution 作为静默回滚。

## Verification plan

- `cargo +1.97.1 metadata --locked --format-version 1`
- `cargo +1.97.1 test -p ferrum2-m0-harness --test workspace_policy --locked`
- `cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i aes`
- `cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i ghash`
- `cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i polyval`
- `cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i zeroize`
- M0-T02 的 primitive/KDF/secret tests、strict Clippy 与 fmt 全部重跑
- `workflow.toml` quick/full、M0-MSRV-001 与三平台/interop gates 在最终同一
  integration commit 重跑
- fixed-baseline scope/license review 证明只增加两个已锁定 permissive feature
  anchors，package version/source/checksum 与产品/协议行为均未改变

## References

- `docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md`
- `docs/adr/ADR-0002-m0-secret-key-clock-and-entropy-boundaries.md`
- `docs/research/M0-upstream-baseline.md`
- `aes-gcm 0.11.0` fixed registry `Cargo.toml` 与 `src/lib.rs`
- `aes 0.9.1` fixed registry `Cargo.toml` 与 backend `Drop` implementations
- `ghash 0.6.0` fixed registry `Cargo.toml`
- `polyval 0.7.3` fixed registry `Cargo.toml` 与 `Drop` implementation
