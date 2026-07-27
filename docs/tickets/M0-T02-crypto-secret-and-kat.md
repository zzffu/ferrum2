+++
id = "M0-T02"
title = "Implement secret ownership, AES-128 primitives, and deterministic capabilities"
milestone = "M0"
status = "in_progress"
priority = "P0"
blocked_by = ["M0-T01"]
owns = [
  "crates/ferrum2-crypto/src/**",
  "crates/ferrum2-crypto/tests/**",
  "tests/fixtures/crypto/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-CRYPTO-001 and M0-CRYPTO-002 pass exactly the ADR-0004 BLAKE3 input-length 0, 1, and 1024 rows plus the ADR-0008 McGrew/Viega GCM proposal test cases 1 and 2 and the unchanged corrupted-tag reject, with pinned hashes and truthful submitter-source provenance",
  "M0-CRYPTO-003 passes for the exact SIP022 context, 32-to-16-byte subkey selection, empty AAD, zero u96le nonce, carry, and checked increment",
  "M0-CRYPTO-004 proves redacted Debug, explicit-clear and ZeroizeOnDrop seams, production entropy failure, response-salt collision handling, standalone-counter overflow, and actual TcpSealer/TcpOpener private nonce-owner overflow fail closed without a public setter",
  "The KeyProvider, Clock, and SecureRandom interfaces match ADR-0002 and expose neither raw PSK bytes nor a production deterministic fallback; the integrated dependency graph satisfies ADR-0009 exact package-ID, feature-set, and lock-identity evidence",
]
+++

# M0-T02: Implement secret ownership, AES-128 primitives, and deterministic capabilities

## Outcome

交付无 socket/policy 依赖的 secret/KDF/AEAD capability，提供 SIP022 TCP state
machine可安全消费且可确定性测试的 key、clock和entropy边界。

## Context

M0-T03依赖本票的不可 clone AEAD owners与注入 seams。本票只证明 primitive和
capability，不实现 TCP framing/replay。

## In scope

- `Aes128Psk`、`TcpSubkey`、`TcpSealer`、`TcpOpener`及redacted errors。
- strict 16-byte secret conversion所需的 fixed-buffer API。
- `KeyProvider`/`SinglePskProvider`、`Clock`、`SecureRandom` interfaces/adapters。
- exact BLAKE3 KDF、AES-128-GCM in-place encrypt/decrypt、u96le nonce owner。
- primitive/protocol-subkey fixtures与 provenance metadata。

## Out of scope

- TOML/base64 operator parsing（T04）。
- SIP022 frame/message/replay/state machine（T03）。
- sockets、tracing、metrics、global key database、SIP023行为。
- AES-256、ChaCha20-Poly1305、UDP。

## Implementation notes and constraints

- 不得修改任何 manifest/Cargo.lock；依赖必须来自T01。
- raw secret types不得实现明文 `Display`/`Debug`/tracing fields。
- production entropy唯一入口是 `getrandom::fill`；scripted adapter只在 tests。
- AEAD owner独占nonce；调用者不能设置counter或clone owner。
- fixture expected bytes不由被测production code在runtime生成，并标注非官方层级。

## Validation commands

```bash
cargo test -p ferrum2-crypto --test primitive_vectors --locked
cargo test -p ferrum2-crypto --test sip022_vectors --locked
cargo test -p ferrum2-crypto --test secret_entropy --locked
cargo test -p ferrum2-crypto --lib --locked tcp_owner_nonce_exhaustion
cargo clippy -p ferrum2-crypto --all-targets --all-features --locked -- -D warnings
cargo fmt -p ferrum2-crypto -- --check
```

## Risks

- KDF output长度/nonce endianness错误会产生自洽但不互操作的wire。
- zeroization证据可能被夸大；只能声明approved safe-code seam与dependency contract。
- test RNG泄漏到production feature会破坏CSPRNG invariant。

## Completion evidence

- Branch: `codex/ticket/m0-t02`
- Commit(s): `45c0e2fcf8630a128f9ee422854ea0a089be75c8`,
  repair 1/2 `df22d7efe287043d90b5823d0f69c69913eda56b`
- Repair evidence: primitive/KDF/secret tests, strict Clippy, fmt and provenance
  integration assertion all exit 0；provenance 与 `NonceCounter` repair
  Architect/QA PASS。
- Prior overall Architect/QA verdict was **BLOCK** only because the T01-owned
  resolved graph lacked `aes/zeroize` and `ghash/zeroize`. ADR-0009/T01 candidate
  `edaee3d` and integration `4f3f0ac` closed that blocker.
- Final combined integration `f9e218eca241f3002500b932fdcb4db93c52313b`:
  Architect **PASS**、QA **PASS**；T02 tests 3/3 + 2/2 + 6/6、strict Clippy/fmt、
  T01 policy 13/13、architecture 6/6、core 4/4、SOCKS5/runtime 36/36，合计
  70 tests PASS。Lock identities 110→110、0 differences；generated `target/`
  已清理。
- Integrated commit: `f9e218eca241f3002500b932fdcb4db93c52313b`
- Reopened narrow evidence repair: T03 final review showed that standalone
  `NonceCounter` overflow does not directly prove the private counter used by
  `TcpSealer`/`TcpOpener`. The user-authorized blocker exception permits one
  crate-private `cfg(test)` module with exactly two owner cases (sealer/opener);
  public constructors/setters, release
  fields, wire behavior, manifests, dependencies, fixtures and versions remain
  unchanged. Candidate and re-integration evidence: pending.
