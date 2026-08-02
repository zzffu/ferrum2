# SPEC-0006 — M5 `shadowsocks-crypto` 单一实现迁移

- **Status:** Approved
- **Milestone:** M5
- **Baseline:** `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`
- **Decision:** `docs/adr/ADR-0025-m5-single-shadowsocks-crypto-implementation.md`
- **Test plan:** `docs/test-plans/TEST-0006-m5-shadowsocks-crypto-migration.md`

## Scope

在不改变 `ferrum2-crypto` 公开 seam、`ferrum2-shadowsocks` TCP/UDP 状态机、
SIP022 wire 或 schema v1 config 的前提下，把三个标准方法的产品 cipher/KDF
实现全部切换到受控 patched `shadowsocks-crypto 0.7.0`，并删除旧实现与无用依赖。

## Requirements

### M5-MUST-01 — 单一产品实现

- 产品正常 dependency graph MUST 只有 patched `shadowsocks-crypto` 提供 SIP022
  AES-GCM、ChaCha/XChaCha、AES block header protection 和 BLAKE3 KDF。
- `ferrum2-crypto` MUST 删除被替代的 primitive/KDF 实现；MUST NOT 保留旧 backend、
  fallback、双实现、compile/runtime selector 或 shadow verification path。
- 独立 fixture/KAT oracle MAY 使用 dev-only primitives，但不得进入产品正常图。

### M5-MUST-02 — 方法、公开 seam 与配置兼容

- `MethodProfile::ALL`、canonical names、key/salt/tag/nonce widths 和所有现有公开
  crypto types/traits/methods/error text MUST 保持 source-compatible。
- config MUST 继续只接受三个标准方法，并继续拒绝
  `2022-blake3-chacha8-poly1305`、未知方法和错误 key width。
- Patched dependency MUST 只解析 `v2` feature；`v2-extra`、`reduced-round`、default/
  v1、`ring` 和 `aws-lc` MUST absent from the resolved product feature graph。

### M5-MUST-03 — TCP 密码语义

- 三方法 TCP KDF、request/response salt binding、two-record framing 和 exact wire
  bytes MUST 与现有 fixtures 一致。
- 每个 directional owner MUST 从 zero u96le nonce 开始；只有成功 primitive
  operation 才 commit 下一个 nonce。没有可保留的 next nonce 时 MUST 在读取或
  修改 caller buffer 前返回 `AeadError::NonceExhausted`，不得回绕或重用。
- Authentication failure MUST 保持 `AuthenticationFailed`，seal failure MUST
  保持 `OperationFailed`；失败不得泄漏 secret/nonce/source error。

### M5-MUST-04 — UDP 密码语义

- AES MUST 保持 16-byte separate header、PSK block protection、
  `PSK || session ID` KDF、header bytes `[4..16]` body nonce 和 AES-GCM tag。
- ChaCha MUST 保持 direct PSK、fresh CSPRNG 24-byte nonce、authenticated
  session/packet identity 和 XChaCha20-Poly1305 tag。
- Outbound u64 packet ID MUST 只在完整 wire 成功后 commit；`u64::MAX` 可用一次，
  之后 `CounterExhausted`。Capacity/random/method/primitive failure MUST 保持 counter
  与 caller-owned result 不变；authentication failure MUST 清除 candidate plaintext。

### M5-MUST-05 — secret、unsafe 与错误边界

- PSK、KDF material、derived keys 和展开 primitive key state MUST 在 owner drop 或
  临时值结束时按受控 patch 明确 zeroize；现有 public secret owners 继续
  `ZeroizeOnDrop` 且不可打印/clone。
- Selected `v2` production path MUST contain no `unsafe`；adapter MUST 在调用上游
  primitive 前验证全部 buffer/tag/nonce/key widths，避免 peer input 触发 panic。
- Debug、Display、source chains、logs、traces 和 metrics MUST 保持 secret-free。

### M5-MUST-06 — 协议与外部兼容

- `ferrum2-shadowsocks` framing、timestamp、replay、binding、session、allocation/
  mutation ordering 和 public UDP API MUST 不变。
- 现有三方法 KAT/composite fixtures、全部 TCP/UDP negative suites 和同一 exact
  SHA/run/attempt 的 sing-box/shadowsocks-rust TCP/UDP `24/24` MUST pass。

### M5-MUST-07 — dependency、MSRV、license 与 performance review

- Upstream version/archive checksum/VCS commit、vendor delta、resolved package IDs/
  features、licenses 和 removed dependencies MUST 有可审计记录；所有 license MUST
  与 `GPL-3.0-only` distribution compatible。
- Rust 1.85.0 MUST 完成 workspace all-target check/build/test；三个 release targets
  MUST 在同一 hosted run 通过既有 native qualification。
- 既有 M4 hosted performance profile MUST 在 accepted exact SHA 上通过并记录正的
  ferrum/reference medians、ratio 和 resource cleanup。M5 不新增 throughput floor；
  数据与 dependency delta 必须获得 blocking review PASS。

### M5-MUST-08 — 关闭规则

- Full validation、ticket/milestone budget、Architect/QA blocking review、MSRV、
  license/dependency、KAT/negative、performance、三平台和 external interop 全部
  满足后 M5 才 MAY close。
- 任一 required evidence failed、missing、skipped、unauthorized 或 unavailable 时
  M5 MUST be `blocked`；不得拼接旧 SHA/run，也不得恢复旧 backend 作为关闭方案。

## Non-goals

- 替换 `ferrum2-shadowsocks` protocol state machines 或采用另一个代理的 protocol core。
- 新 method、SIP023/EIH、多用户、多 PSK、public UDP inbound 或 schema/config 变化。
- `v2-extra`、reduced-round ChaCha、ring/AWS-LC backend 或 runtime crypto selection。
- 上游发布、crate publication、performance optimization 或新的 benchmark framework。
- Push、workflow dispatch/rerun、PR、tag、release 或 publication；这些需要单独授权。
