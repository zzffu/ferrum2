+++
id = "M2-T01"
title = "Establish method-bound SIP022 UDP crypto capabilities and fixtures"
milestone = "M2"
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
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "The canonical transport-neutral MethodProfile binds exactly the three supported methods to exact 16-byte AES-128 or 32-byte AES-256/ChaCha PSKs, while TcpMethodProfile remains source-compatible and no raw secret capability escapes crypto",
  "AES-128 and AES-256 UDP capabilities implement reviewed 16-byte separate-header block protection, session-ID subkey derivation, plaintext-header bytes 4 through 16 nonce selection, and 16-byte-tag body authentication",
  "The ChaCha UDP capability uses the direct 32-byte PSK with fresh 24-byte CSPRNG nonces and XChaCha20-Poly1305, passes the pinned primary numeric vector, and rejects a corrupted tag without fallback",
  "Fresh client/server 8-byte session IDs remain direction-distinct, retry live collisions at most eight times, and fail the affected session without exposing or retaining partial secret or nonce state",
  "Outbound directional packet owners start at zero, consume an ID only when complete wire bytes become externally ownable, cover the terminal u64 state, and fail closed without wrap or AEAD key-nonce reuse",
  "Committed primitive fixtures record exact source, row, rights, generator and output hashes; the independent generator links neither ferrum nor reference code, and locked feature, zeroize, unsafe, license and test-budget policies pass",
]
+++

# M2-T01: Establish method-bound SIP022 UDP crypto capabilities and fixtures

## Outcome

把M1的TCP-named profile深化为transport-neutral method capability，并在crypto
边界内正确拥有AES UDP header/KDF与ChaCha XChaCha construction。

## In scope

- `MethodProfile` canonical name和`TcpMethodProfile` compatibility alias。
- Opaque AES/ChaCha UDP seal/open capability，不暴露raw PSK。
- 8-byte session ID、24-byte ChaCha nonce、directional packet counter ownership。
- AES header/KDF与XChaCha primitive fixtures、provenance和dependency policy。

## Out of scope

- SIP022 main-header codec、replay window、association或routing。
- Core/runtime sockets、session table、server config/composition。
- Composite UDP wire fixture和external qualification。

## Contract references

- `ADR-0020`：profile、envelope、entropy和counter boundary。
- `docs/research/M2-udp-baseline.md`：numeric sources和fixture contract。
- `SPEC-0003` M2-AC-01/03/08。
- `TEST-0003` T01 product evidence和test-budget。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | one profile/capability table + workspace consumer compile |
| 2 | reviewed AES block/header/KDF/nonce/tag table |
| 3 | pinned XChaCha positive/corrupted-tag table |
| 4 | scripted entropy collision rows 0..8 |
| 5 | directional counter 0/1/MAX/exhausted table |
| 6 | fixture provenance + Cargo metadata/tree/policy + budget |

Primitive numeric evidence与static capability boundary是不同failure modes，不能
互相替代。

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

- T01是M2 root manifest/lock唯一writer；T03不能临时增加root dependencies。
- T01不编辑Shadowsocks composite packet/state；round-trip不能替代expected bytes。
- Existing TCP fixtures/bytes必须不变，reduced-round feature必须继续缺席。

## Completion evidence

由Team Lead integration后填写：

- Branch/worktree/candidate and integrated commit:
- Architect/QA full/targeted review and stable finding IDs:
- Exact validation exits and test-budget counts/baseline:
- Accepted review debt:
- Push/publish state:
