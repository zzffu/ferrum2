---
id: M9-T01
milestone: M9
status: done
depends_on: []
owns:
  - AGENTS.md
  - CONTEXT.md
  - docs/milestones/M9-multi-upstream-closure.md
  - docs/specs/SPEC-0010-m9-multi-upstream-capability.md
  - docs/test-plans/TEST-0010-m9-multi-upstream-capability.md
  - docs/tickets/M9-T01-verify-multi-upstream-coverage.md
  - docs/handoffs/HANDOFF-M9-2026-08-04.md
  - docs/roadmap.md
  - docs/vision.md
  - docs/gap-analysis.md
  - docs/ci-status.md
  - docs/review-debt.md
  - docs/workflow-debt.md
  - docs/research/M9-test-footprint-schema-v3.md
---

# M9-T01 — 核验并关闭 multi-upstream

## Outcome

以现有 M7/M8 config、runtime 和 real-process evidence 证明 multi-upstream 已交付，并
用零 product/test code 关闭 M9。

## Acceptance

- [x] 同一 client process 可配置并实际使用至少两个 concrete Shadowsocks upstreams。
- [x] TCP 与 UDP 均有真实双上游证据；同一 SOCKS UDP association 可跨 upstream。
- [x] Upstream group/load balancing 与 multi-upstream 明确区分，且无当前需求要求前者。
- [x] Focused、Full、lifecycle、docs 和 footprint validation 通过。
- [x] 独立 Architect/QA review PASS，blocking findings 为零。

## Validation

Exact commands and results are recorded in `TEST-0010` and the M9 milestone。No command was
credited unless it executed at least one intended test and exited `0`。

## Result

- **Accepted exact:** `5b0a8020e5dac1a915dc64c8229ddd129dd4da4a`（baseline identical；zero product/test diff）。
- **Review:** Architect `PASS`；QA `PASS`；all findings resolved in documentation。
- **Footprint:** `PASS`，ratio `1.682671`，case/support/fixture deltas `0/0/0`。
- **Remote:** none authorized or performed。
