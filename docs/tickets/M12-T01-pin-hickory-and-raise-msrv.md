---
id: M12-T01
milestone: M12
status: done
depends_on: []
owns:
  - Cargo.toml
  - Cargo.lock
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/lib.rs
  - .github/workflows/m0.yml
  - tests/m0-harness/tests/workspace_policy.rs
---

# M12-T01 — Pin Hickory and raise MSRV

## Outcome

Add the minimum compiling `ferrum2-dns` workspace edge，pin the latest stable Hickory family exactly at
0.26.1 and raise the one workspace/CI MSRV contract from Rust 1.85.0 to 1.88.0。

## Acceptance

- [x] `hickory-resolver/proto/server =0.26.1` are exact and resolver features are only Tokio、
      ring-backed DoT/DoH and WebPKI roots required by ADR-0031；normal graph has one Hickory family。
- [x] Workspace and metadata MSRV are exactly 1.88.0；all CI commands use `+1.88.0` while
      `rust-toolchain.toml` remains 1.97.1。
- [x] Workspace policy forbids system-config、DNSSEC/recursor、DoQ/DoH3、AWS-LC、duplicate Hickory/
      crypto providers and non-registry sources。
- [x] License/provenance/lock review passes for Windows MSVC、Linux GNU and Linux musl；no product DNS
      behavior or config field is added in this ticket。
- [x] `TEST-0013` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0013` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Candidate/integrated exact：`d874865f4a66db8d7c50abad85e6092a16f52fb6`；其CI-only parent
  `3ff66c118d847759a189a446ce30243130feae58`隔离Rust 1.88 workflow修改。
- Review：Architect `PASS`；QA `PASS_WITH_NOTES`，仅`M12-T01-QA-001` note指出mutation guard
  未拒绝额外未来MSRV selector，当前workflow和acceptance exact，blocking IDs为零。
- Validation：全部T01命令、repository Quick和`git diff --check`在candidate及fast-forward integration
  上exit 0；workspace-policy `21/21`。Target-resolved Windows/GNU/musl graph均为单一Hickory
  0.26.1 + ring/rustls/WebPKI；QA另跑Windows MSRV all-features check通过。
- Footprint：integrity/category `PASS`，code/tests `16024/32685`、ratio `2.039753` `WARN`，
  case/support/fixture `+229/0/0`。`workspace_policy.rs` 1,925 test LOC触发numeric
  `REVIEW_REQUIRED`；Architect/QA接受其复用existing table/helpers且无第三个等价helper。
- Provenance：新增107个lock identities、移除/换版0；106个registry包和一个workspace crate均有
  license metadata，无Git source、unreviewed patch、forbidden provider或第二TLS实现。

## Rollback / risk

Rollback removes the new empty crate/dependency edge and restores Rust 1.85.0 everywhere。Primary risks
are hidden Hickory default features、a second TLS provider or an incomplete MSRV replacement。
