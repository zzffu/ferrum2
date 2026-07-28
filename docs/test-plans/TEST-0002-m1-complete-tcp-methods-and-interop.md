# TEST-0002: M1 完整三方法 TCP 与 12 项互操作

- **Status:** Approved
- **Milestone:** M1
- **Spec:** `docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md`
- **Gate profile:** strict

## Risk summary and cheapest reliable seams

M1 的最高风险是 method/key-width 错配、复制安全 state machine、partial IPv6/domain
conversion、认证前 resolution/dial/replay mutation、deadline 被每个 candidate
重置，以及 12-cell hosted aggregation 假 PASS。

测试只扩展现有 parameterized seams：

- crypto/config 使用一个 method-profile table；
- Shadowsocks 使用一个 shared-flow method table；
- address path 使用 recording resolver/dialer/replay table；
- process/lifecycle 只增加能证明跨 ticket interaction 的小 method/address matrix；
- qualification 复用既有 fail-closed state/driver，固定 12 rows。

不按 method × layer 复制 test file，不测试 private helper，也不为 CI YAML 建第二套
parser。

## MUST-to-primary-evidence matrix

| MUST / invariant | Primary evidence | Gate | Distinct uncovered failure mode |
|---|---|---|---|
| M1-AC-01 method/config | 现有 config + secret suites 的三方法 accepted/cross-pair table | product | binary offline zero-resource 由既有 process seam证明 |
| M1-AC-02 primitive/KDF | reviewed primitive/KDF fixture table；同表 corrupted tag | product | provenance/feature graph 由 static policy 独立证明 |
| M1-AC-03 one shared TCP state | 现有 Shadowsocks suites 参数化三 profile，并静态确认没有复制 public flow/state types | product | real adapter interaction 由 AC-06 process seam证明 |
| M1-AC-04 address/order | core→SOCKS5→SIP022→recording resolver/dialer/replay address table | product | real OS domain/IPv6 由 AC-06 小型 process rows证明 |
| M1-AC-05 deadline/reply | paused-time scripted resolution/candidates + actual endpoint/reply observer | product | Windows/Linux mapping 由 hosted platform regression证明 |
| M1-AC-06 lifecycle/observability | 既有 local process/lifecycle suite 的小 method/address matrix与 sentinel scans | integration | post-FIN semantics 不交给 external reference |
| M1-AC-07 12-cell interop | hosted non-test qualification 的固定 12-line report；12/12+cleanup 才 exit 0 | release | setup failure continuation 由 pure aggregation state test证明 |
| M1-AC-08 regression/scope | locked metadata/tree/policy、authoritative full、MSRV、三平台 same-SHA results | integration/release | remote unavailable 是 BLOCKED，不伪造 local替代 |

## Fixture and harness contract

### Primitive and protocol fixtures

`docs/research/M1-tcp-method-baseline.md` 是 normative source-selection companion：

- 保留 AES-128 numeric fixtures；
- AES-256 使用 McGrew/Viega cases 13/14 和 corrupted-tag row；
- ChaCha 使用 RFC 8439 §2.8.2 完整 vector 和 corrupted-tag row；
- AES-256/ChaCha SIP022 wire fixture 使用该文档冻结的 synthetic PSK/salts/time/
  target/padding/payload；
- expected bytes 提交到 repository，不在 test runtime 生成；
- provenance 记录 source/entry/generator/output SHA-256、rights、classification；
- independent generator 只链接 primitive dependencies，不链接 ferrum2/reference。

fixture growth 被 test-budget 排除，但不免除 provenance/license/diff review。

### Recording seams

- existing key-provider/clock/random/transport/buffer/replay seams 继续使用；
- address tests 增加 recording resolver/dialer，记录 candidate count/order、
  absolute deadline、call sequence 和 safe category，不记录 domain bytes；
- negative address rows断言 resolver/dialer/replay/session mutation 全为零；
- paused-time row 让 resolution 消耗部分 budget，再让 sequential candidates消耗
  剩余 budget，杀死 per-stage/per-candidate deadline reset mutant；
- reply observer 只记录 `SocketAddr` family/bytes。

不引入 public test hook、release flag、global allocator 或 production-only observer。

## Product gate commands

每张 ticket 先运行自身 commands；Windows 上 test-budget 固定 UTF-8 mode，避免
Python/PowerShell 对 Git UTF-8 diff 的 GBK decoding failure。

```powershell
# M1-T01
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-m0-harness --test architecture --test workspace_policy --locked
cargo metadata --locked --format-version 1
cargo tree -p ferrum2-crypto -e features --locked

# M1-T02
cargo test -p ferrum2-core -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-runtime --locked
cargo clippy -p ferrum2-core -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings

# M1-T03
cargo test -p ferrum2-config -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test cli_contract --test config_cli --test local_e2e --test lifecycle_cycles --test detection_probe --locked

# M1-T04 local/pure only
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo metadata --no-deps --format-version 1 --locked

# Every ticket
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

focused diagnostic 可使用 exact test name，但不能替代完整 target。
`m0-qualification` 是现有 binary 名，不是 M1 永久 interface；local commands 只能
build/lint，绝不执行它。

## Integration gate commands

Team Lead 在 exact integrated candidate 运行 `workflow.toml` authoritative full：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate milestone --base <m1-planning-base-sha>
git diff --check
```

integration review 还检查：

- exact ticket ownership diff，无 overlapping/unknown paths；
- Cargo lock/package/feature/license/unsafe/zeroize policy；
- AES-128/IPv4 M0 regression；
- no UDP/reduced-round/deferred scope、generated artifacts、secret/endpoints；
- Architect 与 QA 各一次 exact-SHA full review；BLOCK 后至多一次 substantive repair
  和 targeted re-review。

## Stable 12-case interoperability matrix

| Case ID | Method | Reference role | Ferrum role |
|---|---|---|---|
| M1-INT-001 | AES-128 | sing-box server | ferrum2 client |
| M1-INT-002 | AES-128 | shadowsocks-rust server | ferrum2 client |
| M1-INT-003 | AES-128 | sing-box client | ferrum2 server |
| M1-INT-004 | AES-128 | shadowsocks-rust client | ferrum2 server |
| M1-INT-005 | AES-256 | sing-box server | ferrum2 client |
| M1-INT-006 | AES-256 | shadowsocks-rust server | ferrum2 client |
| M1-INT-007 | AES-256 | sing-box client | ferrum2 server |
| M1-INT-008 | AES-256 | shadowsocks-rust client | ferrum2 server |
| M1-INT-009 | ChaCha20-Poly1305 | sing-box server | ferrum2 client |
| M1-INT-010 | ChaCha20-Poly1305 | shadowsocks-rust server | ferrum2 client |
| M1-INT-011 | ChaCha20-Poly1305 | sing-box client | ferrum2 server |
| M1-INT-012 | ChaCha20-Poly1305 | shadowsocks-rust client | ferrum2 server |

每案：

- 使用 synthetic method-correct PSK、local echo target 与独立 temp/port/child owner；
- 比较 distinct bidirectional payload，沿用 ADR-0014 pre-FIN/ordered EOF boundary；
- 有 fixed absolute operation deadline、bounded redacted capture 和 cleanup；
- summary 只输出 case ID、PASS/FAIL、可选 canonical root；
- case failure 后继续其他 runnable cases。

一个 reference provision/setup failure 将其六行以同一 root 标为 FAIL，不声称案已
执行；另一 reference 六案继续。global exact-SHA/build guard failure 可终止 plan，
但必须产生明确共同 root，不能得到 zero-case success。

## Release qualification

另行授权 push 后，由 thin hosted profile 在 clean exact `GITHUB_SHA` 运行：

1. `quality`：build workspace binaries 后运行 authoritative full 一次；
2. `msrv`：Rust 1.85.0 all-target check 与 workspace tests；
3. `platform`：Windows MSVC、Linux GNU、Linux musl locked release build/config
   smoke；这是 M1 regression，不冒充 M3 final qualification；
4. `interop`：一个 hosted driver 明确报告 M1-INT-001～012，12/12+cleanup。

所有 required results 必须属于同一 run ID/attempt/exact SHA。旧 M0 success 只作
entry baseline；不同 SHA/run 不拼接。missing、skipped、cancelled、neutral、
timed-out、11/12、provider unavailable 都是 FAIL/BLOCKED。

release-only provider failure 不自动 reopen product ticket；只有证明 product
defect 时才回到 owning ticket。plan/execute 本身不授予 push、rerun、PR、tag 或
release 权限。

## Test-budget expectation

当前 baseline：

- code `7,031` lines；
- tests `14,707` lines；
- ratio `2.091737`；
- ratchet `max_regression = 0.0`，target `1.0`；
- ticket delta allowance：`new_tests <= new_code + 120`；
- milestone delta ≥200 lines 时预期 ratio 至多约 `2.042`。

执行优先扩展现有 tables/suites；fixture lines 不计 ratio，但不能用无意义 production
code 改善 ratio。每票 integration 前跑 ticket gate，close 跑 milestone gate。

## Exit conditions and accepted gaps

Blocking：

- 任一 M1-AC 未映射/未通过；
- fixture source/generator/output provenance 不完整；
- method/address ownership partial conversion 或认证前副作用；
- local full/test-budget/review failure；
- hosted required result 非同一 exact SHA/run/attempt 或非 12/12。

Accepted/deferred：

- configured endpoints 继续 IPv4；
- system resolver 顺序、无 Happy Eyeballs/cache；
- UDP 到 M2，final platform/lifecycle 到 M3，performance 到 M4。

规划阶段没有 M1 product/hosted PASS evidence；上述 gaps 只能由 execute/close
产生的 exact-SHA evidence 关闭。
