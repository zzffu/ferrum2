# M5 — `shadowsocks-crypto` 单一密码实现迁移

- **Status:** validating
- **Qualification:** BLOCKED on `QA-T03-001` (hosted evidence unauthorized/not run)
- **Baseline:** `ccb1ec5edf2637fd1e35b5f4dd68eb5421ac3498`
- **Owner:** primary thread

## Outcome

在保持 `ferrum2-crypto` 公开 seam、`ferrum2-shadowsocks` TCP/UDP 状态机、
SIP022 wire 和 schema v1 config 不变的前提下，把三个标准方法的产品 cipher/KDF
完整切换到受控 patched `shadowsocks-crypto 0.7.0`，删除旧实现与无用依赖，并在
同一 exact SHA 上完成安全、互操作、平台、性能和依赖资格。

## Non-goals

- 新 method、`v2-extra`、reduced-round ChaCha、SIP023/EIH 或 multi-user。
- 替换协议状态机、改变 public API/wire/config，或引入 dual backend/fallback/switch。
- 新 benchmark framework、性能优化、public UDP inbound、发布或 publication。

## Exit criteria

- [x] Exact vendored 0.7.0 provenance/license 和最小 patch delta 通过审查；产品图只
      启用 `v2`，forbidden features/backend/unsafe absent。
- [x] TCP/UDP 三方法全部经现有公开 seam 使用唯一上游实现；旧 cipher/KDF 与无用
      product dependencies 已删除，secret zeroization 与显式 exhaustion 保持。
- [ ] KAT、composite wire、全部 negative/regression 和 Full/budget/review gates
      在一个 accepted integration commit 上通过。
- [ ] Rust 1.85、三 native targets、TCP/UDP external `24/24` 和 existing hosted
      performance 在同一 SHA/run/attempt 通过。
- [ ] Blocking findings 为零；任一 required gate 缺失或失败时状态为 `blocked`，
      且不恢复旧实现或拼接证据。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M5-T01 | Pin exact upstream source and apply the bounded security patch | — | done |
| M5-T01R | Add the missing checked raw TCP subkey owner | M5-T01 | done |
| M5-T02 | Atomically switch TCP/UDP and delete native cipher/KDF | M5-T01R | done |
| M5-T03 | Qualify one exact commit across all closing gates | M5-T02 | blocked |

T01/T02 intentionally serialize overlapping manifests/policy paths. T02 is the only
product switch and must integrate atomically; T03 is evidence-only unless a failed gate
identifies a concrete owning-ticket defect.

## Blocker / next action

Local-only exact candidate `816fa7b9a19a7c0f805280063dce837caa751c3a` passed Full,
Rust 1.85, dependency/security review and milestone budget, but it did not run hosted
qualification. T03 and M5 close remain blocked on `QA-T03-001`: no explicit push
authorization, run ID or attempt exists. No remote action or evidence splice occurred.
After future authorization, use the then-current clean integration HEAD and rerun the
complete local and hosted same-SHA gates; do not treat `816fa7b` as a closed SHA.
