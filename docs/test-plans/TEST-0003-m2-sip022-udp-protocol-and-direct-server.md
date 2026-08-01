# TEST-0003: M2 SIP022 UDP protocol API 与 direct server

- **Status:** Approved
- **Milestone:** M2
- **Spec:** `docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md`
- **Gate profile:** strict

## Risk summary and cheapest reliable seams

最高风险是method-specific envelope错误、replay/association在完整校验或capacity
前mutation、source-address identity、generation ABA、allocated-capacity漏记、
逐candidate deadline reset、dual-bind partial startup，以及12-cell false PASS。

测试只增加按failure domain分层的parameterized seams：

- crypto：一个profile/primitive/header table；
- protocol：packet、replay、session三张table；
- runtime：一个generic datagram reservation/lifecycle table；
- process：一个小型UDP composition matrix；
- qualification：固定case_id-keyed 12-row set和既有fail-closed aggregator。

不按method × direction × layer复制test，不测试private helper，不测试test
harness本身，也不为CI YAML建第二套parser。

## MUST-to-primary-evidence matrix

| MUST / invariant | Primary evidence | Gate | Distinct second layer |
|---|---|---|---|
| M2-AC-01 crypto/profile | crypto profile + AES header/KDF + XChaCha primitive/negative fixture table | product T01 | composite layout由AC-02 |
| M2-AC-02 packet semantics | `udp_packets`三方法/address/boundary/negative table消费committed wire | product T02 | real socket interaction由AC-06 |
| M2-AC-03 replay/session | `udp_replay` boundary/concurrency + paused-time `udp_sessions` association/roaming/generation table | product T02 | runtime rollback由AC-04 |
| M2-AC-04 resources/lifecycle | generic runtime reservation/queue/expiry/cancel/owner snapshot table | product T03 | one stalled real socket row由AC-06 |
| M2-AC-05 config/server/obs | config defaults/ranges/no-resource + dual-bind rollback + telemetry series/sentinel tables | integration T04 | platform socket smoke属AC-08 |
| M2-AC-06 local product | bounded three-method UDP echo + focused IPv6/domain/failure/backpressure/shutdown process matrix | integration T04 | 不复制codec/resource tables |
| M2-AC-07 external | hosted case_id-keyed 12-row set；12/12+cleanup/exact SHA/run/attempt | release T05 | pure aggregator只证明false-PASS防护 |
| M2-AC-08 regression | exact candidate authoritative full + ratchet + same-run MSRV/platform jobs | integration/release | hosted unavailable为BLOCKED |

每条MUST只有一个primary evidence；第二层只覆盖primary seam无法观察的命名failure
mode，不能因reviewer偏好复制同一claim。

## Fixture and provenance contract

`docs/research/M2-udp-baseline.md`是source-selection companion：

- 保留SIP022 commit/blob和M1 reference pins；
- XChaCha使用draft-02 Appendix A.1/A.3.1 numeric vector和corrupted tag；
- AES增加block/header/session-subkey/nonce rows；
- composite fixture固定三方法PSK、session/packet IDs、ChaCha nonces、timestamp、
  address、padding、payload和完整request/response wire；
- expected bytes提交仓库，test runtime不生成；
- `PROVENANCE.toml`记录source revision/row/rights、generator和output SHA-256、
  canonical-LF规则和interpretation；
- independent generator只依赖primitive crates，不import/link ferrum或reference；
- references只是black-box cross-check，不是official KAT/fixture oracle。

Fixtures虽被test-budget排除，仍需license/provenance/diff review。

## Product evidence

### T01 crypto

扩展现有`primitive_vectors.rs`、`secret_entropy.rs`、`sip022_vectors.rs`：

- three profiles、wrong widths、`MethodProfile`/`TcpMethodProfile` compatibility；
- AES-128/256 separate-header encrypt/decrypt、KDF、nonce slice、tag failure；
- XChaCha pinned positive/corrupted-tag rows；
- 0～8 collision draws、packet counter `0/1/MAX/exhausted`；
- errors/redaction/zeroize/dependency features。

不得用round-trip作为唯一numeric evidence。

### T02 protocol

复用`tests/common/mod.rs` clock/entropy/recording seams，集中新增：

- `udp_packets.rs`：三方法request/response fixtures，IPv4/IPv6/domain，65507
  exact/over bound，checked overhead，tamper/truncate/type/timestamp/binding/
  padding/address/trailing negative；
- `udp_replay.rs`：highest、±1、-8128、-8129、duplicate、large jump、overflow，
  64-way same-ID race恰一accepted；
- `udp_sessions.rs`：same-ID roaming、same-source/new-ID、generation stale handle，
  current+old、third-ID、59.999/60.000 seconds；
- 所有negative rows记录zero replay/peer/activity/session/queue/resolve/send。

### T03 core/runtime

Core contract直接inspection和existing architecture policy；runtime以fake packet
handler证明：

- defaults/ranges由validated limits构造；
- 4,096/65,535 sessions、allocated-capacity byte permits、depth-4 queues；
- reserve/move/release/no-double-count/shared-backing accounting；
- full with expired-oldest purge、active-only reject、concurrent exactly-one admit；
- resolver 0/1/16/17 candidates和one absolute deadline；
- idle/cancel/target failure/shutdown下owner/task/socket/queue/byte snapshot归零。

不按client/server/method重复generic resource table。

## Integration evidence

### T04 config/composition/observability

- 扩展config table覆盖omitted defaults、min/max、below/above、unknown、UDP disabled；
- `--check-config`通过existing CLI zero-resource seam证明无TCP/UDP/metrics/task；
- dual bind全部成功后才启动；TCP或UDP第二bind failure回滚；restart/rebind；
- local process matrix：三个methods各一条IPv4三-datagram echo，另加focused IPv6、
  domain、stalled consumer/backpressure、invalid zero-target-side-effect；
- UDP disabled只跑TCP regression；shutdown/idle后owner snapshot回baseline；
- metrics/tracing tables检查七个families、closed series和secret/session/target/
  source sentinels；既有TCP families byte-identical。

Windows local IPv6/port policy若受host环境限制必须记录为未执行，不能称PASS；
same-SHA hosted platform evidence在release补齐。

### Milestone regression

Exact integration candidate运行`workflow.toml` authoritative full、M0/M1 local
regression、workspace architecture/unsafe/license policy和milestone ratchet。
External entry只能build/lint，local不得运行、下载reference、spawn external
process或打开qualification sockets。

## Hosted qualification

固定case table：

| ID | Method | Direction |
|---|---|---|
| M2-UDP-INT-001 | AES-128 | ferrum example → sing-box server |
| M2-UDP-INT-002 | AES-128 | ferrum example → shadowsocks-rust server |
| M2-UDP-INT-003 | AES-128 | sing-box client → ferrum server |
| M2-UDP-INT-004 | AES-128 | shadowsocks-rust client → ferrum server |
| M2-UDP-INT-005 | AES-256 | ferrum example → sing-box server |
| M2-UDP-INT-006 | AES-256 | ferrum example → shadowsocks-rust server |
| M2-UDP-INT-007 | AES-256 | sing-box client → ferrum server |
| M2-UDP-INT-008 | AES-256 | shadowsocks-rust client → ferrum server |
| M2-UDP-INT-009 | ChaCha | ferrum example → sing-box server |
| M2-UDP-INT-010 | ChaCha | ferrum example → shadowsocks-rust server |
| M2-UDP-INT-011 | ChaCha | sing-box client → ferrum server |
| M2-UDP-INT-012 | ChaCha | shadowsocks-rust client → ferrum server |

该表冻结唯一的case_id→transport/method/reference/direction mapping，而不冻结表格
呈现、case执行或summary行顺序。providers ready时12案各执行恰好一次；测试按
case_id集合验证完整性和唯一性。

每案：

- independent temp/ports/children/absolute deadline/bounded capture/cleanup；
- one session，三条distinct payload，逐条比较echo bytes和source address；
- ferrum direction只spawn Cargo example；harness manifest不依赖ferrum crates；
- setup root只合并同reference六个derivative rows，另一reference继续；
- panic/timeout/missing/skipped/mismatch/cleanup/nonzero不可PASS；
- checkout guard要求clean GitHub Actions Linux和exact `GITHUB_SHA`；
- exit 0需要恰12条PASS、12/12 summary和cleanup，同一run/attempt/SHA。

Hosted执行、push和rerun不在plan/execute隐含权限内。Provider/setup unavailable是
release blocker；只有raw log证明specific product defect才reopen相应product票。

## Exact validation commands

### Ticket commands

```powershell
# M2-T01
cargo test -p ferrum2-crypto --locked
cargo test -p ferrum2-m0-harness --test architecture --test workspace_policy --locked
cargo metadata --locked --format-version 1
cargo tree -p ferrum2-crypto -e features --locked

# M2-T03
cargo test -p ferrum2-core -p ferrum2-runtime --locked
cargo clippy -p ferrum2-core -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings

# M2-T02
cargo test -p ferrum2-shadowsocks --locked
cargo clippy -p ferrum2-shadowsocks --all-targets --all-features --locked -- -D warnings

# M2-T04
cargo test -p ferrum2-config -p ferrum2-observability -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test config_cli --test detection_probe --test udp_local_e2e --locked

# M2-T05: build/pure only; never run external qualification locally
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo metadata --no-deps --format-version 1 --locked
```

每票追加：

```powershell
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

### Milestone integration

```powershell
cargo build --workspace --bins --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py validate
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate milestone --base 589970c5b15023a2f184e41a839253a7685b222b
git diff --check
```

Focused exact-test diagnostics不能替代完整target。Authoritative quick/full仍以
`workflow.toml`为准。

## Test budget

Planning baseline：

- code `7720`；
- tests `15759`；
- ratio `2.041321`；
- mode `ratchet`。

Material M2 close的当前required ratio是不高于`1.991321`
（baseline减`ratchet_step=0.05`）；script结果是authoritative。

- 每票必须满足ticket gate；当前公式等价于
  `new test lines <= new production lines + 120`。
- 五票的`+120`不能累加为设计预算。
- Milestone建议aggregate Rust test delta不大于aggregate production delta；
  不得用无意义production code改善ratio。
- packet/replay/session/resource各一张参数表；三条echo属于一个case而非三项test；
  fixture排除计数不意味着可以复制或免除review。

## Stop and pass rules

- Product/integration gate失败回到owning ticket，不能以hosted result掩盖。
- Hosted unavailable/unauthorized为BLOCKED，不使用旧run、本机或不同SHA替代。
- Full review每role一次；blocker/major才阻断，一次substantive repair后仅做
  original IDs + delta targeted re-review；第二次blocking为ESCALATE。
- `PASS_WITH_NOTES` integration并把advisory写入`docs/review-debt.md`。
- M2只有在AC-01～08、test-budget、full、same-SHA hosted/platform evidence全部
  满足后才ready-to-close；plan完成不声称任何implementation或interop PASS。
