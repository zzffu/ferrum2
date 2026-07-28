# ADR-0014: M0 external half-close evidence boundary

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`ADR-0005`、`ADR-0006`、`ADR-0007`；
  `SPEC-0001`；`TEST-0001`；M0-T07、M0-T08；部分取代 ADR-0006 对 external
  interop half-close sequence 的未细化表述；ADR-0016将具体external evidence
  sequence定义为selected profile并保留同等或更强替换路径，不改变 ferrum2
  half-close behavior；ADR-0017进一步取代本ADR的libtest ignored/filter实现与
  exact 11-job close allocation，但保留四案独立结果及wire/EOF/cleanup语义

## Context and problem

ADR-0006 要求四项 pinned external interoperability case 都验证双向 bytes、
TCP half-close 与 cleanup，但没有规定双向 payload 与 FIN 的先后顺序。T08
checkpoint `14343d2`选择了更强的时序：application client先
`Shutdown::Write`，target观察EOF后才产生全部reverse payload。

对exact pinned sing-box 1.13.14的诊断证明：

- 原时序在两个sing-box方向都得到reverse `0/16386`；
- reverse 1 byte在FIN前到达时，两方向均通过，response fixed header、request
  salt binding、length与nonce 0/1 authentication均有效；
- 1 byte在FIN前、余下16385 bytes在FIN后时，两方向都只收到前1 byte；
- sing-box client方向中，ferrum2在FIN后发出的完整16529-byte authenticated
  response可被独立recorder逐frame验证，但转交sing-box时写入失败；
- exact pinned shadowsocks-rust 1.24.0在两个方向均通过原有更强时序。

因此失败来自sing-box 1.13.14在peer FIN后关闭Shadowsocks leg的lifecycle行为，
不是已发现的ferrum2 SIP022 wire、authentication、binding、nonce或T03 duplex
缺陷。用harness timing悄悄规避会改写既有contract；重新选择pin则需要新的
version/hash/provenance/license与双方向实测，当前没有该证据。

## Decision drivers and invariants

- 四个reference/direction结果仍是独立required gates，缺一即M0 BLOCKED。
- exact versions、source commits、asset names/sizes/SHA-256、version output与
  license boundary保持不变。
- external interop必须证明pre-FIN双向wire/data compatibility以及ordered
  clean-EOF convergence；不得
  skip、xfail、缩短payload、放宽deadline、复用case或隐藏child failure。
- ferrum2在peer FIN后继续drain新reverse application bytes的产品要求不得削弱；
  它继续由同一最终SHA上的M0-E2E-001和M0-LIFE-003独立阻塞。
- 不修改protocol/runtime/T03/T07生产代码、wire、API、config、operator behavior、
  dependency、pin或产品范围。

## Options considered

### Option A: split external compatibility and ferrum-owned drain evidence

external cases先完整比较双向payload，再依次观察application write shutdown后的
target clean EOF与target write shutdown后的application clean EOF；
ferrum-owned local/runtime tests继续验证FIN后产生的reverse bytes仍被drain。

### Option B: replace the sing-box pin

只有named release在两个方向通过原强时序，并完成exact artifacts、checksums、
source commit、license与CLI review后才可选择；当前没有可接受候选证据。

### Option C: retain the original implicit sequence

合同不变且M0保持BLOCKED。该选项诚实，但把已隔离的第三方lifecycle限制错误地
作为ferrum2 wire正确性的唯一退出路径。

## Decision

选择Option A。M0-INT-001～004每个case必须使用独立processes、temp directory与
ports，并按以下顺序执行：

1. application client发送固定16386-byte forward payload；target不等待EOF，
   读取exact length并逐byte比较。
2. target发送与forward不同的固定16386-byte reverse payload；application client
   读取exact length并逐byte比较。
3. 只有两次byte equality都成功后，application client才调用
   `Shutdown::Write`。
4. target必须在I/O deadline内观察clean `Ok(0)`，然后成功调用
   `Shutdown::Write`。
5. application client必须在I/O deadline内观察clean `Ok(0)`；expected reverse
   payload后若出现任何额外byte，或以reset/error代替clean EOF，也失败。

任何truncation、extra byte、premature EOF、mismatch、timeout、child early exit、
unchecked exit status或cleanup失败均使case失败。readiness 10秒、I/O 10秒、
case 60秒、stdout/stderr各256 KiB cap、sanitized diagnostics、kill-on-drop、
pin/version/archive checks与clean current-SHA binary build保持blocking。

external interop据此只声明：

- pinned reference与ferrum2之间的pre-FIN双向SIP022 data compatibility；
- application write shutdown后观察到target clean EOF；
- target write shutdown后观察到application client clean EOF，形成ordered
  clean-EOF convergence。

该black-box顺序不证明reference在第一次FIN后仍保持reverse leg，也不证明target
FIN导致client EOF；client EOF可能已由reference的更早full-close挂起。

它不声明sing-box 1.13.14能够在peer FIN后交付新产生的reverse application bytes。
ferrum2自身的该项要求继续由未修改的：

- M0-E2E-001：两个真实ferrum2 binaries在client write-half close后仍收到target
  reverse payload与EOF；
- M0-LIFE-003：runtime one-way EOF后的reverse drain；

在同一个最终integration SHA上证明。两项任一失败都阻塞M0，external四项PASS
不能替代。

## Consequences and tradeoffs

### Positive

- compatibility claim与实际pinned reference能力精确一致，不把第三方close policy
  误判为ferrum2 wire defect。
- 双向16386-byte equality、ordered clean-EOF convergence与cleanup仍为四个
  hard gates。
- 产品最强half-close行为由ferrum-owned real-process和runtime seams双重保留。
- 无pin、wire、production code、API或产品范围变化。

### Negative

- external matrix不再独立证明peer FIN之后新产生的reverse bytes能穿过每个
  reference。
- M0 close evidence必须同时阅读external compatibility与local/runtime drain
  两组结果，不能用单个interop case概括全部half-close语义。
- 若pre-FIN完整16386-byte reverse transfer仍失败，本决策不能把该失败降级；
  gate必须回到Option B或C。

## Compatibility and upstream divergence

sing-box 1.13.14的已观察限制只作为固定pin的evidence边界记录，不进入ferrum2
production compatibility shim，也不改写SIP022。shadowsocks-rust 1.24.0通过
原强时序是诊断control，不允许替代任何sing-box required case。

M1/M2不得从本决策推断其他method、address或UDP compatibility；M3也不得把M0
smoke提升为完整native lifecycle qualification。

## Migration and rollback

无wire、persisted state、config或operator migration。回滚本决策会恢复原未细化
external half-close解释并使sing-box两项重新BLOCKED；不得只回滚test wording而
保留较弱implementation。改pin仍须新ADR/spec revision。

## Verification plan

- 四个exact M0-INT cases分别证明：
  - forward exact 16386/16386；
  - reverse exact 16386/16386且payload distinct；
  - byte equality完成前调用`Shutdown::Write`的mutation失败；
  - target未见clean `Ok(0)`、target write shutdown失败、client未见clean
    `Ok(0)`、reset/error、extra byte、premature EOF与timeout mutations分别失败；
  - child status、deadline、bounded sanitized capture、port/temp cleanup/rebind
    全部有结构化evidence。
- 同一最终SHA上重跑且通过：

```text
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked success
cargo test -p ferrum2-runtime --test half_close --locked
```

- 经ADR-0017取代后，一个hosted-only Cargo-managed qualification entry运行并
  固定报告四个case；不使用libtest `#[ignore]`、filter或test-count guard。四案
  仍是独立结果，任一案不能替代另一案。
- final gate采用ADR-0017 selected profile：local quick/full、Architect、QA，
  以及同一run/attempt对exact pushed SHA的六个rendered results全部success。

## References

- `ADR-0005`：ferrum2 direction-local close与reverse drain。
- `ADR-0006`：fixed references、four-case matrix与process evidence。
- `ADR-0007`：GitHub Actions provider与exact-SHA close contract。
- `SPEC-0001` AC-07/08/10。
- `TEST-0001` M0-E2E-001、M0-LIFE-003、M0-INT-001～004。
