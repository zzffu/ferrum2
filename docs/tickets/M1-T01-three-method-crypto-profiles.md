+++
id = "M1-T01"
title = "Establish the three method-bound crypto profiles and reviewed fixtures"
milestone = "M1"
status = "ready"
priority = "P0"
risk = "critical"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "Cargo.toml",
  "Cargo.lock",
  "crates/ferrum2-crypto/**",
  "tests/fixtures/crypto/**",
  "tests/m0-harness/tests/architecture.rs",
  "tests/m0-harness/tests/workspace_policy.rs",
]
spec = "docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md"
test_plan = "docs/test-plans/TEST-0002-m1-complete-tcp-methods-and-interop.md"
acceptance = [
  "Exactly the three canonical M1 methods have immutable method-bound secret profiles with 16-byte AES-128 and 32-byte AES-256/ChaCha PSK, salt, and derived-subkey widths; cross-profile construction is impossible",
  "The existing AES-128 fixtures remain byte-identical and reviewed AES-256 proposal cases 13/14 plus RFC 8439 section 2.8.2 ChaCha positive and corrupted-tag rows pass through one parameterized primitive table",
  "SIP022 KDF output selection, 12-byte little-endian nonce progression, nonce exhaustion, failed authentication, full-width salt ownership, and zeroization preserve ADR-0018 for every profile",
  "Key lookup returns method-bound derivation capability without exposing raw PSK, and wrong-width or noncanonical material produces only redacted stable errors",
  "chacha20poly1305 is pinned exactly to 0.11.0 with only bytes and zeroize features; locked package/checksum/MSRV/license/feature/zeroize evidence passes and reduced-round support is absent",
  "Workspace dependency direction, unsafe_code=forbid, existing M0 resolved-graph policy, and test-budget ticket gate pass without an unreviewed manifest or lock change",
]
+++

# M1-T01: Establish the three method-bound crypto profiles and reviewed fixtures

## Outcome

提供一个把 method、exact-width PSK、salt/KDF 与 AEAD owner 绑定在一起的 crypto
deep module，使后续 protocol/composition 无法选择错 cipher 或取得 raw key。

## In scope

- AES-128/AES-256/ChaCha20-Poly1305 三个 exact profiles。
- bounded 16/32-byte secret/salt/subkey ownership。
- AES-256/RFC ChaCha primitive fixtures、KDF rows 和 negative authentication。
- exact `chacha20poly1305` dependency、lock、feature/MSRV/license/zeroize policy。
- architecture/workspace-policy 对 method/feature/dependency boundary 的 focused
  evidence。

## Out of scope

- Shadowsocks framing/state、SOCKS5/address、runtime、binary config composition。
- interop driver/workflow、reference 下载或 execution。
- UDP、reduced-round ChaCha、SIP023、多用户、performance。

## Contract references

- `ADR-0018`：method profile、dispatch/KDF/nonce/replay-width boundary。
- `docs/research/M1-tcp-method-baseline.md`：source、numeric rows、dependency pins。
- `SPEC-0002` M1-AC-01/02/03/08。
- `TEST-0002` fixture/harness 与 test-budget sections。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | method/profile construction table and compile/runtime capability checks |
| 2 | one reviewed primitive fixture table with positive/corrupted-tag rows |
| 3 | existing crypto owner/KDF/nonce suites parameterized by profile |
| 4 | secret/key-provider/redacted-error table |
| 5 | Cargo metadata/tree + provenance/license/feature policy |
| 6 | architecture/workspace-policy + ticket test-budget/diff review |

附加 layer 只用于不同 failure mode：static dependency policy 不能替代 primitive
numeric result；primitive KAT 也不能证明 raw-key/API boundary。

## Validation commands

```powershell
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-m0-harness --test architecture --test workspace_policy --locked
cargo metadata --locked --format-version 1
cargo tree -p ferrum2-crypto -e features --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T01 是 root manifest/lock 的唯一 M1 writer；其他票只使用它固定的 workspace
  dependencies。
- fixture expected bytes 必须 committed；generator/source/output hashes 和 rights
  metadata 一起 review，测试时不生成 expected output。
- enum/helper 命名是 implementation freedom；不得把 method dispatch 扩散成三套
  flow 或 per-frame allocation。
- Engineer 不运行 external qualification，不编辑 T02/T03/T04 owns。

## Completion evidence

Filled by the Team Lead after integration:

- Branch/worktree/candidate and integrated commit:
- Full/targeted Architect and QA reviews; stable finding IDs:
- Exact validation exits:
- Test-budget counts/baseline:
- Accepted review debt:
- Push/publish state:
