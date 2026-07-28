# ADR-0020: M2 method-bound SIP022 UDP cryptographic envelope

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M2；`SPEC-0003`；`TEST-0003`；
  M2-T01、M2-T02；扩展 ADR-0002、ADR-0009、ADR-0018

## Context and decision boundary

M1 的 crypto deep module 只提供 TCP salt/KDF/AEAD owner，canonical public
名称仍是 `TcpMethodProfile`。SIP022 UDP 的 AES construction 与 TCP framing
不同；ChaCha UDP 又不是 TCP ChaCha 的 12-byte nonce construction。复用 TCP
owner 或让 protocol 取得 raw PSK 都会造成 wire 错误或 key/nonce reuse 风险。

本 ADR 冻结 method profile、AES separate header、ChaCha XChaCha、entropy 和
opaque key capability。Session/replay ordering 属于 ADR-0021，socket/resource
policy 属于 ADR-0022。

## Outcome invariants

- 只支持三个 canonical methods；method 与 exact-width PSK 继续不可错配。
- canonical profile 概念改为 transport-neutral `MethodProfile`；
  `TcpMethodProfile` 在 M2 保留 source-compatible alias。
- raw PSK、derived key、expanded cipher state、session ID 和 nonce 不跨出
  crypto capability 或进入 diagnostic。
- AES UDP 使用 16-byte encrypted separate header、session-ID-derived key 和
  AES-GCM body；ChaCha UDP 使用 direct 32-byte PSK、XChaCha20-Poly1305 和
  fresh 24-byte CSPRNG nonce。
- client/server session IDs 必须不同；fresh live ID 最多 8 次 collision draw，
  仍冲突则只终止 affected session。
- outbound packet ID 从 0 开始、per direction 独立；一个成功产出并可由 caller
  持有的 packet 消费一个 ID，失败不消费；到 `u64` 耗尽后 fail closed，绝不回绕。
- TCP bytes、KDF、nonce、flow 和 three-method behavior 不变；禁止 reduced-round
  ChaCha。

## Options considered

### Option A：复用 TCP salt/subkey/AEAD owners

AES UDP 的 salt 是 8-byte session ID，ChaCha UDP 又直接使用 PSK；TCP owner 的
16/32-byte salt 和 12-byte counter nonce 无法正确表达。拒绝。

### Option B：protocol 获取 raw key并自行选择 primitive

会破坏 secret/key-lookup boundary，并把 method dispatch 扩散到 packet state。
拒绝。

### Option C：method-bound opaque UDP crypto capability

crypto 统一拥有 exact secret、header protection、KDF/AEAD selection 和
redaction；protocol 只看到 bounded seal/open result。接受。

## Decision

### Profile and key boundary

`MethodProfile` 继续只有 AES-128、AES-256、ChaCha20 三值，并保留 M1 的
16/32-byte PSK widths。Key provider 返回 method-bound capability，不返回 raw
key；future selector/multi-user seam 保留，但 M2 仍是 one PSK、无 SIP023。

UDP 使用明确 8-byte session-ID owner，不把它别名为 `MethodTcpSalt`。Exact type
和 helper 名是 implementation freedom，只要 caller 无法构造 wrong-method
capability 或读取 secret material。

### AES UDP envelope

对两个 AES methods：

1. plaintext separate header 为 8-byte session ID + u64be packet ID；
2. 以 PSK 对完整 16-byte block 做 AES encrypt/decrypt；
3. 以 SIP022 context 对 `PSK || session ID` derive session subkey；
4. body AEAD nonce 是 plaintext separate header `[4..16]`；
5. body 使用 profile 对应 AES-GCM 和 16-byte tag。

解出的 separate header 在 body authentication 前只可用于 bounded lookup 或
precheck；不能返回 plaintext、建立 session 或 mutation accepted state。

### ChaCha UDP envelope

ChaCha wire 以 fresh 24-byte nonce 开头，随后是 XChaCha20-Poly1305 encrypted
body/tag。PSK 直接作为 key；session ID 和 u64be packet ID 位于 authenticated
main header。Production nonce 必须来自 ADR-0002 entropy capability，不能由
peer/config/caller 注入。SIP022 不要求 nonce replay set，M2 也不增加一个
input-dependent nonce store。

### Failure and ownership

Seal/open 是 bounded consuming operations：

- output capacity 不足、random/key unavailable、counter exhausted、
  authentication failure 均返回 closed/redacted category；
- packet ID 只在完整 wire bytes 成为 externally ownable 后推进；
- temporary subkey/plaintext/expanded state zeroize where practical；
- authentication failure 不返回 partial header/payload 或 method fallback。

## Consequences and tradeoffs

- Positive：method-specific crypto 保持在一个 deep module，protocol 共享 semantic
  state。
- Positive：source-compatible alias 避免为 UDP 无关地破坏 TCP consumers。
- Negative：AES 与 ChaCha 必须有不同 envelope 分支；fixture/review 必须分别证明，
  不能用一个抽象的 round-trip 自证。
- Negative：random XChaCha nonce collision 依赖 CSPRNG 概率；SIP022 明确不要求
  nonce replay store。

## Compatibility, migration, and rollback

M0/M1 TCP public behavior 不变。M2 source 可继续使用 `TcpMethodProfile`，新代码
应使用 canonical `MethodProfile`。回滚到 M1 时 UDP API/fixtures 消失，TCP
alias 的 underlying profile 与 bytes 不变；没有 persisted key/session migration。

## Verification seam

- 一张 method/capability table：three profiles、wrong widths、alias compile、
  raw-key unavailability；
- AES block/separate-header/KDF/nonce rows；
- pinned XChaCha primitive vector和 corrupted tag；
- repository-owned three-method composite fixtures；
- scripted entropy collision 0～8、packet-ID `0/1/MAX/exhausted`；
- locked dependency/features/zeroize/unsafe/license policy。

## References

- `docs/research/M2-udp-baseline.md`
- `docs/adr/ADR-0002-m0-secret-key-clock-and-entropy-boundaries.md`
- `docs/adr/ADR-0009-m0-aead-state-zeroize-feature-unification.md`
- `docs/adr/ADR-0018-m1-method-bound-tcp-crypto-profile.md`
- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [XChaCha20-Poly1305 draft-02](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-02)
