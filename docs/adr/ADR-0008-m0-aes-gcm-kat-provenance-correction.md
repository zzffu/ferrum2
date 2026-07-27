# ADR-0008: M0 AES-GCM primitive KAT 来源归属窄勘误

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T02、M0-T08；仅取代 ADR-0004 的 AES-GCM primitive KAT 来源归属条款

## Context and problem

ADR-0004 为 M0-CRYPTO-002 固定了两个 AES-128-GCM numeric cases，但把它们归属
到 NIST CAVP `gcmtestvectors.zip`。对固定 archive
`f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`
解包并穷举检索后，六个 `.rsp` 文件均不含 ADR-0004 明列的 tag/ciphertext。

相同 numeric cases 实际来自 David McGrew 与 John Viega 的 GCM proposal test
cases 1 和 2。该 submitter-supplied artifact 曾由 NIST Modes Development 页面
托管；NIST 当前页面也明确说明 proposal 文档由 submitter 自愿提供，页面收录不
构成 NIST endorsement 或 approval。

这是来源与供应链证据缺陷，不是 AES-GCM 数值或实现缺陷。用户已明确授权本窄
勘误；不得借此改变任何向量、密码行为、协议行为或产品范围。

## Decision drivers and invariants

- 两个已批准 case 的 key、IV、AAD、plaintext、ciphertext 和 tag 必须逐 byte
  保持不变。
- case 2 tag 最低 bit 翻转的 required decrypt-failure case 保持不变。
- fixture 不能声称这些 case 是 NIST CAVP、NIST-authored 或 NIST validation
  vectors。
- source archive、选中 entry、补充 specification 与 IPR statement 必须有可复核
  URL、size/SHA-256 或 SHA-256。
- 不提交外部 archive、PDF 或其他二进制；仓库只提交选中的 numeric fixture 和
  provenance metadata。
- 不臆造 SPDX license；无法从 source 得出标准 license expression 时必须记录
  `NOASSERTION`，同时保留 submitter/IPR 与 historical-hosting notice。

## Options considered

### Option A：保留数值，改为实际 proposal source

固定实际 archive、entry hashes、case IDs、classification 和 rights metadata。
这能修复 provenance，同时不改变测试或产品行为。

### Option B：换成 `gcmtestvectors.zip` 中的 CAVP rows

来源名称可以维持，但会改变已批准的 numeric cases、fixture bytes 与验证合同，
超出本勘误授权。

### Option C：只改 fixture 注释，不新增 ADR

ADR-0004、ticket 与 TEST-0001 仍会保留错误的规范性归属，并违反 accepted ADR
必须显式 supersede 的仓库规则。

## Decision

选择 Option A。本 ADR **仅**取代 ADR-0004 `### KAT 与 fixture` 下以
“AES-GCM primitive source固定为NIST CAVP”开头的整项来源归属条款。ADR-0004
中的两个 numeric cases、corrupted-tag negative case、BLAKE3 选择、SIP022
fixture、generator、密码状态机以及其他所有决定继续有效。

### Normative provenance

M0-CRYPTO-002 的两个 case 分类固定为：

> McGrew/Viega GCM proposal test cases 1 and 2, submitter-supplied and
> historically hosted by NIST; not NIST CAVP or NIST-authored validation
> vectors.

固定 source evidence 为：

- original hosted path：
  `http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz`
- archived raw URL：
  `https://web.archive.org/web/20170830120738id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz`
- archive size：`5879` bytes
- archive SHA-256：
  `511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0`
- `gcm-test-vectors/vec-01.txt` SHA-256：
  `4fffe6ba6272443855d24dcb8deb00e23dddad6da510d57201ffa4560e5137f1`
- `gcm-test-vectors/vec-02.txt` SHA-256：
  `6ceba9c631dac0d4fc5015dc002d37c340af174429213c0afb6f51c76088436a`

选中值仍精确为：

1. proposal test case 1：all-zero AES-128 key、96-bit all-zero IV、empty AAD、
   empty plaintext/ciphertext、tag
   `58e2fccefa7e3061367f1d57a4e7455a`；
2. proposal test case 2：all-zero AES-128 key、96-bit all-zero IV、empty AAD、
   16-byte zero plaintext、ciphertext
   `0388dace60b6a392f328c2b971b2fe78`、tag
   `ab6e47d42cec13bdf53a67b21257bddf`。

McGrew/Viega revised specification Appendix B 可作交叉证据；固定 archived URL
`https://web.archive.org/web/20170811123217id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf`
及 SHA-256
`327e3c9363c268fae64e285e2f56f882bb6e3e04f81ef8098521f44c8e2b6c37`。

rights metadata 固定引用 McGrew/Viega GCM IPR statement：
`https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/gcm/gcm-nist-ipr.pdf`，
SHA-256
`01708680027b2141cc4f976f2c6e854571cc840737c275da2afb42a48b93813d`。
fixture 的 `source_license` 记录 `NOASSERTION`，并以独立字段记录上述
classification、IPR URL/hash、historical NIST hosting 与 no-endorsement notice；
不得把 NIST copyright notice 或 proposal hosting 解释成 source license。

### Repository representation

`tests/fixtures/crypto/aes128-gcm-v1.json` 只更正 source vector IDs/classification，
不改变任何 hex value。`PROVENANCE.toml` 必须记录 archive、entry、spec 与 IPR
证据并重算 fixture SHA-256。测试名、assertion message 和 expected
interpretation 必须移除 “official NIST”/“CAVP” 归属，但 cryptographic assertion
保持相同。

## Consequences and tradeoffs

### Positive

- M0-CRYPTO-002 与 AC-12 的来源声明可复核且不再夸大 NIST 身份。
- 已批准 AES-GCM positive/negative behavior 和所有 downstream protocol fixture
  保持稳定。

### Negative

- historical source 依赖 Internet Archive；因此同时固定 archive、entry hashes
  与仍在线的 IPR evidence。
- source 没有可安全推断的 SPDX license expression，审计必须处理
  `NOASSERTION` 与附带 rights evidence，不能只看单一 license 字段。

## Compatibility and upstream divergence

本 ADR 不改变 AES-GCM API、加解密结果、nonce、AAD、key ownership、SIP022
framing、wire bytes、错误语义、互操作行为或平台范围。它只纠正 test-input
provenance。proposal test cases 不能被用来声称 ferrum2 通过 NIST CAVP validation。

## Migration and rollback

M0-T02 尚无实现 commit；Engineer 在保留 dirty worktree 的前提下只更新 fixture
metadata、vector IDs/test wording并重算 fixture hash，然后运行原 ticket gates。
不下载或提交 source archive/PDF。

回滚本 ADR 会恢复已证伪的来源声明，因此不作为正常 rollback。若未来要更换 numeric
cases、rights policy 或 source artifact，必须另立 ADR/spec amendment；不能把它
伪装成本勘误。

## Verification plan

- static provenance audit：archive size/hash、两个 entry hash、spec hash、IPR hash、
  classification 与 no-external-artifact policy 精确匹配。
- M0-CRYPTO-002：原两个 positive cases 和 case 2 corrupted-tag reject 均通过。
- fixture diff audit：除 source IDs/classification/metadata 与派生 fixture hash 外，
  key/IV/AAD/plaintext/ciphertext/tag 无变化。
- repository audit：current normative docs、fixture 与测试不再把这两个 case 称为
  NIST CAVP、NIST-authored 或 official NIST vectors；ADR-0004 的历史错误文字只以
  明确 superseded 的记录形式保留。
- M0-SCOPE-001/AC-12：不提交 archive/PDF，rights/provenance 证据完整。

## References

- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- [NIST Modes Development](https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development)
- [Archived McGrew/Viega GCM test-vector bundle](https://web.archive.org/web/20170830120738id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz)
- [Archived McGrew/Viega revised GCM specification](https://web.archive.org/web/20170811123217id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf)
- [McGrew/Viega GCM IPR statement](https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/gcm/gcm-nist-ipr.pdf)
- [NIST CAVP GCM page used to disprove the prior attribution](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES)
