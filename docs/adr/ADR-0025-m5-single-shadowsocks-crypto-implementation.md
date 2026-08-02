# ADR-0025 — M5 单一 `shadowsocks-crypto` 密码实现

- **Status:** Accepted
- **Date:** 2026-08-02
- **Milestone:** M5
- **Baseline:** `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`

## Context

`ferrum2-crypto` 当前公开一个协议无关、method-bound 的 secret/cipher seam，内部
自行实现 SIP022 TCP/UDP KDF 与 primitives。项目已决定改用
`shadowsocks-crypto`，但 0.7.0 原包存在 silent TCP nonce wrap、secret-bearing
KDF 临时值未清零、AES-UDP header protection 不在其高层 API 内等差距。直接
wrapper 无法同时删除本地实现并维持既有安全语义。

## Decision

1. 精确固定 crates.io `shadowsocks-crypto 0.7.0`，archive SHA-256
   `9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0`，
   packaged commit `2affa6c39b30f7626137a1792c533610cf133ade` 和 MIT license。
2. 以仓库内可审计 vendor source + Cargo patch 承载最小安全差异；保留上游
   provenance/LICENSE，并对 pristine source 到 ferrum patch 的 delta 做独立审查。
3. 产品 edge 只允许 `default-features = false, features = ["v2"]`。禁止
   `v2-extra`、`reduced-round`、default/v1、`ring`、`aws-lc`；ferrum method map
   仍闭合为三个标准方法。
4. Patch 只补齐 checked nonce/operation boundary、secret zeroization、AES-UDP
   header protection 和 selected-v2 dependency/unsafe 收敛。它不拥有 SIP022
   framing、replay、timestamp、binding、session、routing 或 config。
5. `ferrum2-crypto` 保留当前公开 types、traits、methods、redacted errors 和
   CSPRNG seam；内部 adapter 是唯一调用 patched crate 的位置。
6. TCP u96le nonce 在没有下一个值时必须在 primitive 调用前返回现有
   `NonceExhausted`，只有成功 primitive operation 才 commit；认证失败不 commit，
   协议 owner 按既有 fail-closed 语义终止。UDP u64 packet ID 仍只在完整 seal 成功后
   commit。认证失败、capacity/random/method mismatch 的 closed error 语义不变。
7. 最终产品正常 dependency graph 删除被替代的本地 cipher/KDF dependencies 和
   implementation。独立 KAT oracle 可保留必要 dev dependencies，但不进入产品
   backend。
8. 不提供旧实现、fallback、双实现、feature/runtime selector。任何关闭门失败时
   M5 标记 `blocked`，不回退本决策。

## Consequences

- 一个上游 primitive core 替代 ferrum 自有 TCP/UDP cipher/KDF，同时保留更深的
  `ferrum2-crypto` seam 和全部协议状态机。
- 仓库承担一个小型 vendored security patch 的来源、升级和 license 审查成本。
- 上游升级只能通过新的 exact source/patch delta、KAT、interop、performance、
  MSRV/license/dependency review；不能依赖 semver 自动漂移。
- M5 不产生新 wire、config、method、operator 或 public UDP inbound 行为。
