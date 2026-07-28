# ADR-0018: M1 method-bound TCP crypto profile

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M1；`SPEC-0002`；`TEST-0002`；
  M1-T01、M1-T02、M1-T03、M1-T04；扩展 ADR-0002、ADR-0004、ADR-0009、
  ADR-0010

## Context and decision boundary

M0 已实现 AES-128-only 的 secret、key-provider、AEAD owner 和 opaque TCP flow。
当前配置虽保存 method，两个 composition roots 没有把它传入 protocol owner；
crypto 使用固定 16-byte owners，Shadowsocks 使用固定 AES-128 factories 和
43/59-byte first-read。直接增加 enum label 会产生 method/key 错配和 wire-width
错误。

M1 必须增加 AES-256-GCM 与 ChaCha20-Poly1305，又不能复制 transport state
machine、泄露 raw key、放宽 replay/binding/detection ordering 或引入
peer-controlled method negotiation。本 ADR 冻结 method/secret/profile 边界和
ChaCha 兼容性解释；具体 helper/type 名留给 Engineer。

## Outcome invariants

- 只接受三个 canonical method；不支持别名、fallback、auto-detection、协商、
  reduced-round ChaCha 或 XChaCha。
- 配置 method 与 PSK 是一个不可错配的 validated capability；raw key 不跨出
  `ferrum2-crypto`。
- AES-128 使用 16-byte PSK/salt/subkey；AES-256 与 ChaCha20-Poly1305 使用
  32-byte PSK/salt/subkey。
- tag 固定 16 bytes；TCP nonce 固定 12 bytes，从全零开始按 u96 little-endian
  单调递增；耗尽时 fail closed，绝不回绕。
- request/response salt、response binding 和 exact replay key 使用 method 的完整
  salt width；不得截断或让 16/32-byte 值别名。
- 一个共享 opaque TCP flow 继续拥有 framing、authentication、replay、
  request/response binding、detection prevention、duplex lifecycle 和 terminal
  arbitration。
- method 在 flow 创建前固定且在整个 flow 内不可改变；peer input 不能选择 cipher。
- 所有 secret、derived state、salt 和 nonce 的 redaction/zeroize 约束继续适用。

## Options considered

### Option A：按 cipher 泛型化整个 TCP flow

可静态分派，但会复制 monomorphized transport state、扩大 caller type surface，
并提高三个实现发生安全漂移的风险。拒绝。

### Option B：每个 frame 使用 trait-object AEAD

外层接口较小，但把 dynamic dispatch 放进 hot path，也不能自然表达 exact-width
secret capability。拒绝。

### Option C：method-bound secret/profile，AEAD owner 内部 enum dispatch

method、PSK、salt/KDF/AEAD 选择集中在 crypto deep module；protocol 只看到既有
小型 seal/open 能力和 method-derived wire widths。接受。

## Decision

### Method profile

| Method | PSK/salt/subkey | Initial request read | Initial response read |
|---|---:|---:|---:|
| `2022-blake3-aes-128-gcm` | 16 bytes | 43 bytes | 59 bytes |
| `2022-blake3-aes-256-gcm` | 32 bytes | 59 bytes | 91 bytes |
| `2022-blake3-chacha20-poly1305` | 32 bytes | 59 bytes | 91 bytes |

read sizes 是 `salt + fixed encrypted header + tag` 的 method-derived 结果，
不是三个复制的 parser 常量。

SIP022 明列两个 AES 方法的 key/salt width，并说明 TCP ChaCha 只替换 AES-GCM，
但没有单列 ChaCha width。ChaCha 的 32/32/32 因此是显式兼容性解释，依据
RFC 8439 32-byte key、SIP022 salt=key-length 规则、两个 pinned reference 和
repository-owned independent fixture；不得写成 SIP022 的直接原句。

### Secret and key lookup boundary

- 配置解析只产生 method-matched secret owner；wrong-width 和 non-canonical
  Base64 在创建 listener/runtime resource 前以既有 redacted semantic error 失败。
- key lookup 返回的 capability 必须绑定 method；caller 不能把 AES-128 key
  capability 交给 AES-256/ChaCha profile。
- future selector/multi-user seam 继续存在，但 M1 仍只有一个 PSK，不新增 SIP023。
- bounded secret/salt owners 只容纳 16 或 32 bytes；不使用 input-sized owner。

### KDF and AEAD owner

KDF 继续为 SIP022 context 下的 BLAKE3 derive over `PSK || salt`。AES-128 选择
前 16 bytes；AES-256/ChaCha 选择 32 bytes。temporary full output 和 keyed state
遵守 ADR-0002/0009 的 zeroize boundary。

AEAD choice 只在 crypto owner 内分派。AES-GCM 继续使用已固定的 RustCrypto
dependencies；ChaCha 固定 `chacha20poly1305 = "=0.11.0"`、
`default-features = false`、features `bytes,zeroize`。不得启用
`reduced-round`；entropy 继续由 ferrum2 CSPRNG boundary 提供。

### Shared protocol state

`ferrum2-shadowsocks` 可查询 method 的 salt/initial-read width 并构造相应
sealer/opener，但必须复用同一 request/response/replay/binding/frame/duplex
状态路径。method-specific type 不能扩散成三套 public flow。

authentication 和完整 semantic validation 继续先于 replay insertion、target
connect、peer-sized allocation、forwarding 和 accepted-session mutation。
wrong method 与 wrong PSK 一样表现为当前 flow 的 abortive detection failure，
不尝试另一 method。

### Fixture and dependency evidence

`docs/research/M1-tcp-method-baseline.md` 固定 primitive source、numeric selection、
dependency revision/features、synthetic wire inputs 和 reference pins。T01/T02
必须提交 expected bytes、fixture/generator hashes 与 rights metadata；测试运行时
不得生成 expected result。fixture generator 不得链接 ferrum2 production 或
reference code。

## Consequences and tradeoffs

- Positive：cipher variation 集中在一个 deep crypto boundary，TCP security
  state 和 lifecycle 只有一份。
- Positive：method/key mismatch 在 capability construction 时消失，protocol
  caller 无法取得 raw key。
- Negative：AEAD owner 有一个三分支 enum dispatch；必须用 allocation/ownership
  evidence确认没有 per-frame input-dependent allocation。
- Negative：ChaCha width 是明确记录并以 interop 验证的 compatibility choice，
  不是规范原文可直接证明的事实。

## Compatibility, migration, and rollback

AES-128 config、wire bytes、nonce、replay、binding 和 M0 error semantics 保持兼容。
新 method names 是 schema v1 的允许值扩展，不增加 negotiation 或 persisted
migration。

回滚到 M0 binary 时，使用 AES-256/ChaCha 的配置会在离线 validation 中清晰、
脱敏地失败；AES-128 配置继续工作。若 dependency、feature、width 或 dispatch
boundary 必须改变，需先修改本 ADR/spec，不能在 execute 中隐式决定。

## Verification seam

最小主证据是一个 method-profile table：

- 三个 accepted method/key-width pairs 和全部 cross-pair rejection；
- AES-128 既有 KAT、AES-256 proposal cases 13/14、RFC 8439 §2.8.2 ChaCha vector；
- 三种 SIP022 KDF/subkey、nonce 0/1、tampered tag 和 nonce exhaustion；
- 同一 public opaque flow/type path 的三方法 protocol matrix；
- locked metadata/tree/license/zeroize/unsafe policy。

12-cell hosted interop 是 release compatibility 证据，不替代上述 primitive 和
ferrum-owned security state evidence。

## References

- `docs/research/M1-tcp-method-baseline.md`
- `docs/adr/ADR-0002-m0-secret-key-clock-and-entropy-boundaries.md`
- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- `docs/adr/ADR-0009-m0-aead-state-zeroize-feature-unification.md`
- `docs/adr/ADR-0010-m0-opaque-sip022-duplex-flow.md`
- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
