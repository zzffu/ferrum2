# M2 SIP022 UDP 规范、fixture 与互操作基线

- **Status:** Reviewed planning baseline
- **Date:** 2026-07-28
- **Milestone:** M2
- **Related decisions:** `ADR-0020`、`ADR-0021`、`ADR-0022`

## 结论

M2 沿用 M0/M1 固定的 SIP022 revision、三个 method profile、两个 reference
版本和 thin hosted evidence 边界。以下来源与选择在 Engineer 开始前冻结：

1. SIP022 规范固定为
   `shadowsocks/shadowsocks-org@34598d65054dad975d330ff9d7317b0d41cf1efd`，
   `docs/doc/sip022.md` Git blob
   `f6b203facf219fe47bfe2913c2e576240d2bf1f9`。
2. AES UDP 按 SIP022 §3.2：16-byte encrypted separate header、session-ID
   derived subkey、AES-GCM body；ChaCha UDP 按 §4.1：direct PSK、
   XChaCha20-Poly1305、每包 fresh 24-byte nonce。
3. XChaCha primitive numeric evidence 固定为
   `draft-irtf-cfrg-xchacha-02` Appendix A.1/A.3.1 的
   `AEAD_XCHACHA20_POLY1305` vector；该文档是 work in progress，不冒充 RFC。
4. SIP022 没有 official UDP KAT。三方法 composite wire fixture 是
   repository-owned synthetic input，由不链接 `ferrum2-*` 或 reference code
   的独立 generator 产生。
5. reference 继续固定 sing-box `1.13.14` 和 shadowsocks-rust `1.24.0`；
   `tests/interop/versions.toml` 的 commit、asset、size、SHA-256、safe extraction
   和 license review 不变。

## Normative UDP wire selection

### AES-128-GCM / AES-256-GCM

- wire 是 16-byte encrypted separate header + AEAD body + 16-byte tag；
- separate header plaintext 是 8-byte session ID + u64be packet ID；
- separate header 以 PSK 的 AES block cipher 处理；
- body subkey 是 SIP022 context
  `shadowsocks 2022 session subkey` 对 `PSK || session ID` 的 BLAKE3 derive；
- body nonce 是 plaintext separate header 的 bytes `[4..16]`；
- client/server 使用不同 session ID 和 packet counter。

解出的 separate header 只能用于 bounded preliminary lookup/window precheck；
body authentication、type/timestamp/address/padding/full-length semantics 成功前，
它不是 accepted state。

### ChaCha20-Poly1305

- wire 是 24-byte random nonce + XChaCha20-Poly1305 ciphertext + 16-byte tag；
- PSK 直接作为 32-byte XChaCha key，不走 AES UDP session subkey；
- session ID 和 u64be packet ID 位于 authenticated plaintext main header；
- client/server direction、type、timestamp、response client-session binding、
  padding/address 语义与 AES UDP 共用一条 protocol state path；
- SIP022 不要求 nonce replay set；ferrum2 仍必须通过已批准 CSPRNG boundary
  产生每包 fresh nonce，不接受 caller-supplied production nonce。

### Common header and replay behavior

- client packet type 为 `0`，server packet type 为 `1`；
- timestamp 与 system time 相差超过 30 秒按 replay 拒绝；
- response 必须携带并匹配 client session ID；
- server 只按 authenticated client session ID 路由，不按 source address；
- valid packet 才能更新 last-seen client address；
- incoming replay state 每 direction 独立，最高 ID 及向后 8,128 个 ID
  可表示；duplicate 或更旧 ID 拒绝；
- client 对一个 client session 恰保留 current + old 两个 server-session
  associations，association/session state 不少于 60 秒。

8,128-lag 是 M2 固定 conformance profile，用于与 pinned
shadowsocks-rust 1.24 行为一致；只研究 observable behavior 和参数，不复制其
实现。SIP022 本身只要求 sliding window，没有规定该数值。

## Primitive fixture

XChaCha primary numeric row：

- source：`draft-irtf-cfrg-xchacha-02` Appendix A.1/A.3.1；
- key：bytes `80..9f`；
- nonce：bytes `40..57`；
- AAD：`50515253c0c1c2c3c4c5c6c7`；
- plaintext：该 appendix 的 114-byte “Ladies and Gentlemen…” vector；
- tag：`c0875924c1c7987947deafd8780acf49`；
- negative row：翻转 tag 一个 bit，必须 authentication failure；
- rights：IETF Trust Legal Provisions；fixture metadata 使用
  `NOASSERTION`，不臆造 SPDX。

AES block/header rows复用已固定 AES primitive dependencies，但要新增：

- AES-128 与 AES-256 单 block positive row；
- separate-header encrypt/decrypt；
- session subkey input/output；
- nonce slice `[4..16]`；
- corrupted body tag。

Primitive table 证明 primitive/header operation；不能替代 composite packet
layout、semantic validation 或 state ordering。

## Repository-owned composite fixtures

每个 method 至少提交一组 request + response expected wire bytes。固定输入：

| Field | AES-128 | AES-256 | ChaCha |
|---|---|---|---|
| PSK | bytes `00..0f` | bytes `20..3f` | bytes `40..5f` |
| client session ID | bytes `60..67` | bytes `70..77` | bytes `80..87` |
| server session ID | bytes `68..6f` | bytes `78..7f` | bytes `88..8f` |
| client/server packet ID | `0` / `0` | `1` / `1` | `2` / `2` |
| ChaCha request nonce | n/a | n/a | bytes `90..a7` |
| ChaCha response nonce | n/a | n/a | bytes `a8..bf` |
| timestamp | `1700000000` | `1700000000` | `1700000000` |
| target/source | IPv4 `192.0.2.1:53` | IPv6 `[2001:db8::1]:5353` | `example.test:8443` |
| padding | `a1b2` | `b1b2b3` | `c1` |
| request payload | `m2-aes128-req` | `m2-aes256-req` | `m2-chacha-req` |
| response payload | `m2-aes128-rsp` | `m2-aes256-rsp` | `m2-chacha-rsp` |

这些 synthetic addresses/keys 不是 production endpoints/secrets。Generator：

- 只依赖 pinned primitive crates；不得 import/link `ferrum2-*`、sing-box 或
  shadowsocks-rust；
- 独立构造每个 field、length、header protection、KDF、nonce、ciphertext/tag；
- 记录 generator source SHA-256、source revisions/rights、fixed inputs、
  expected interpretation、每个 fixture SHA-256；
- expected bytes 在 review 后提交，test runtime 不生成 expected output；
- `PROVENANCE.toml` 使用 canonical LF hash；reference 只作最终 black-box
  cross-check，不能称为 fixture oracle 或 official KAT。

## Frozen resource and interoperability profile

| Boundary | M2 profile |
|---|---:|
| client/server session capacity | default 4,096；range 1..=65,535 |
| global user-space buffered bytes | default 16 MiB；range 1 MiB..=256 MiB |
| per-session queue | 每 direction 固定 4 datagrams |
| complete Shadowsocks wire datagram | hard maximum 65,507 bytes |
| session idle timeout | default 300s；range 60..=86,400s |
| session-ID collision draws | 最多 8 次 |

12-case 顺序按 method-major 固定：

1. ferrum2 protocol example → sing-box server；
2. ferrum2 protocol example → shadowsocks-rust server；
3. sing-box client → ferrum2 server；
4. shadowsocks-rust client → ferrum2 server。

AES-128 使用 `M2-UDP-INT-001`～`004`，AES-256 使用 `005`～`008`，
ChaCha 使用 `009`～`012`。每案在一个 UDP session 内发送三条 distinct
request/reply datagrams，比较 payload 和 observed source address；只有同一
exact SHA/run/attempt 的 12/12 + cleanup 才是 release PASS。

## Primary sources

- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [XChaCha20-Poly1305 draft-02](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-02)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- `docs/research/M0-upstream-baseline.md`
- `docs/research/M1-tcp-method-baseline.md`
- `tests/interop/versions.toml`
