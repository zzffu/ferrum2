# M1 三方法 TCP 与 fixture 基线

- **Status:** Reviewed planning baseline
- **Date:** 2026-07-28
- **Milestone:** M1
- **Related decisions:** `ADR-0018`、`ADR-0019`

## 结论

M1 沿用 M0 固定的 SIP022 revision、两个 reference 版本和 hosted evidence
边界，只增加 AES-256-GCM、ChaCha20-Poly1305 以及 IPv6/domain target。以下来源和
选择在 Engineer 开始前冻结：

1. SIP022 规范仍固定为
   `shadowsocks/shadowsocks-org@34598d65054dad975d330ff9d7317b0d41cf1efd`，
   `docs/doc/sip022.md` Git blob
   `f6b203facf219fe47bfe2913c2e576240d2bf1f9`。
2. AES-256-GCM primitive fixture 选 McGrew/Viega GCM proposal test cases
   13、14；其归属、rights 和 archive policy 与 ADR-0008 相同。
3. ChaCha20-Poly1305 primitive fixture 选 RFC 8439 §2.8.2 的完整 AEAD vector。
4. SIP022 没有官方 protocol KAT。两个新方法的 wire fixture 是 repository-owned
   synthetic input，必须由不链接任何 `ferrum2-*` crate 的独立 generator 产生。
5. reference 仍是 sing-box `1.13.14` 与 shadowsocks-rust `1.24.0`；
   `tests/interop/versions.toml` 的 commit、asset、size、SHA-256 和 license review
   不变。

## 规范与兼容性解释

固定 SIP022 对 AES-128/AES-256 明列的 key/salt 长度分别为 16/32 bytes，并说明
TCP ChaCha20-Poly1305 只替换 AES-GCM。该表没有单独列出 ChaCha 长度。因此 M1
把 ChaCha 的 32-byte PSK、salt 和 derived subkey 记录为**兼容性解释**：

- RFC 8439 的 ChaCha20-Poly1305 key 是 32 bytes；
- SIP022 令 salt 长度等于 method key 长度；
- 两个已固定 reference 都使用 32-byte ChaCha key/salt；
- 最终仍需 repository-owned fixture 和 12-cell 双向 interop 共同验证。

这不是对 SIP022 原文的虚构引用，也不允许 method negotiation、fallback 或
reduced-round ChaCha。

## AES-256-GCM primitive fixture

沿用 ADR-0008 固定的 submitter-supplied bundle：

- archived raw URL：
  `https://web.archive.org/web/20170830120738id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz`
- size：`5879` bytes
- SHA-256：
  `511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0`
- classification：
  `McGrew/Viega GCM proposal test cases, submitter-supplied and historically
  hosted by NIST; not NIST CAVP or NIST-authored validation vectors`
- source license：`NOASSERTION`
- rights evidence：ADR-0008 固定的 specification/IPR hashes
- external artifact policy：不提交或再分发 archive/PDF，只提交选中 numeric
  text 和 provenance metadata。

固定选中行：

| Case | Entry / SHA-256 | Key / IV / AAD / plaintext | Ciphertext / tag |
|---|---|---|---|
| AES-256 empty | `gcm-test-vectors/vec-13.txt` / `a7a76fd69b964918daa559ef5301e1ece5545c1fde61d1039d035bf261a5f8ab` | 32-byte zero key；12-byte zero IV；empty AAD/plaintext | empty / `530f8afbc74536b9a963b4f1c4cb738b` |
| AES-256 zero block | `gcm-test-vectors/vec-14.txt` / `9c94ab4c7de60597968cf6131d0d1402be035e66832420da76741ba9a0927305` | 32-byte zero key；12-byte zero IV；empty AAD；16-byte zero plaintext | `cea7403d4d606b6e074ec5d3baf39d18` / `d0d1c8a799996bf0265b98b5d48ab919` |

同一 table 必须把第二案 tag 的一个 bit 翻转并验证 authentication failure。

## ChaCha20-Poly1305 primitive fixture 与依赖

primitive source 固定为
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.txt) §2.8.2：

- downloaded text size：`88847` bytes
- SHA-256：
  `25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c`
- selected vector：32-byte key `80..9f`、12-byte nonce
  `070000004041424344454647`、12-byte AAD `50515253c0c1c2c3c4c5c6c7`、
  RFC 段落中的 114-byte plaintext/ciphertext、tag
  `1ae10b594f09e26a7e902ecbd0600691`
- rights：IETF Trust Legal Provisions；fixture metadata 使用 `NOASSERTION`
  而不是臆造 SPDX。

M1 依赖选择固定为：

- crate：`chacha20poly1305 = "=0.11.0"`
- upstream tag commit：
  `RustCrypto/AEADs@e37a978ccf0992d9053fbc039470d6527108e393`
- `rust-version = "1.85"`；license `Apache-2.0 OR MIT`
- `default-features = false`，只启用 `bytes,zeroize`
- 不启用 `alloc`、`getrandom`、`rand_core`、`arrayvec` 或 `reduced-round`；
  randomness 继续走 ferrum2 已批准的 entropy boundary。

Cargo registry checksum、resolved package IDs、feature graph 和 lock delta 由
M1-T01 在 `Cargo.lock` 与 workspace policy evidence 中固定；版本或 feature
变化需要重新做 dependency review。

## Repository-owned SIP022 wire fixtures

新增 fixture 采用 schema v2 或兼容扩展；以下输入不可由 Engineer 自行替换：

| Field | AES-256 fixture | ChaCha20-Poly1305 fixture |
|---|---|---|
| PSK | bytes `00..1f` | bytes `a0..bf` |
| request salt | bytes `20..3f` | bytes `c0..df` |
| response salt | bytes `40..5f` | bytes `e0..ff` |
| timestamp | `1700000000` | `1700000000` |
| target | IPv6 `2001:db8::1:443` | ASCII domain `example.test:8443` |
| padding | `a1b2c3` | `b1b2` |
| request initial payload | UTF-8 bytes `m1-aes256` | UTF-8 bytes `m1-chacha20` |
| response initial payload | UTF-8 bytes `ok-aes256` | UTF-8 bytes `ok-chacha20` |
| nonce start | 12 zero bytes；u96 little-endian increment | 同左 |

generator contract：

- 只使用 pinned `blake3` 与对应 RustCrypto primitive API；不得 import 或链接
  `ferrum2-crypto`、`ferrum2-shadowsocks`、reference source/code。
- 记录完整 BLAKE3 output、选择后的 16/32-byte subkey、每个 nonce、plaintext、
  ciphertext、tag、request/response binding 和完整 wire bytes。
- expected bytes 必须提交到 fixture；测试运行时不得重新生成 expected output。
- `PROVENANCE.toml` 必须记录 generator source SHA-256、fixture SHA-256、所有
  source revisions/rights、固定输入与 expected interpretation。
- AES-128 既有 fixture 不变；新 generator 不得改变其 numeric output。
- 两个 reference 只用于最终黑盒互操作交叉验证，不是 fixture oracle，也不得被
  称为官方 KAT。

## 12-cell reference baseline

每个 method 的 case 顺序固定为：

1. ferrum2 client → sing-box server；
2. ferrum2 client → shadowsocks-rust server；
3. sing-box client → ferrum2 server；
4. shadowsocks-rust client → ferrum2 server。

AES-128 使用 `M1-INT-001`～`004`，AES-256 使用 `005`～`008`，
ChaCha20-Poly1305 使用 `009`～`012`。每案沿用 ADR-0014 的 pre-FIN 双向 bytes
与 ordered clean-EOF convergence 边界；ferrum2-owned local tests 继续承担更强的
post-FIN reverse-drain 与 lifecycle 证明。

## Primary sources

- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RustCrypto ChaCha20-Poly1305 0.11.0 manifest](https://github.com/RustCrypto/AEADs/blob/e37a978ccf0992d9053fbc039470d6527108e393/chacha20poly1305/Cargo.toml)
- `docs/adr/ADR-0008-m0-aes-gcm-kat-provenance-correction.md`
- `docs/research/M0-upstream-baseline.md`
- `tests/interop/versions.toml`
