# M9 — multi-upstream 能力核验与零代码关闭

- **Status:** closed
- **Baseline:** `5b0a8020e5dac1a915dc64c8229ddd129dd4da4a`
- **Qualified exact:** `5b0a8020e5dac1a915dc64c8229ddd129dd4da4a`
- **Qualified product ancestor:** `926843d61fcfac094765b5d1032b7239e3d9370c`
- **Strategy:** drain
- **Owner:** primary thread

## Outcome

确认 M7 tagged multi-outbound 与 M8 first-match routing 已满足 multi-upstream：一个
client process 可配置多个 concrete Shadowsocks server，并通过 static binding 或 route
为真实 TCP flow、UDP datagram 选择不同 server。M9 不修改产品或测试代码，也不增加
upstream group。

## Non-goals

- Upstream group、load balancing、health check、fallback/failover 或 chaining。
- Per-upstream method/PSK、自动重试、随机/轮询选择或新的配置字段。
- 新 test harness、依赖、remote run、push、PR、release 或 publication。

## Exit criteria

- [x] 配置层可预先解析多个 concrete client outbounds，并由 static 或 routed table 返回
      各自的 resolved identity。
- [x] 真实 TCP 进程矩阵使用同一 client process 的两个 upstream；同一 SOCKS UDP
      association 可按 target 在两个真实 upstream 间 A/B/A 选择。
- [x] Selected failure 不尝试 sibling；response source/leg binding 保持，group 与 load
      balancing 明确为不同且未交付的策略能力。
- [x] M8 qualified product 到 M9 accepted exact 之间无 product、test、Cargo 或 toolchain
      变更；M9 新增 product/test LOC 为零。
- [x] Accepted exact 通过 serial Full、100+ lifecycle、docs、schema 3 footprint 和独立
      Architect/QA review；blocking findings 为零。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M9-T01 | 核验并记录现有 multi-upstream 能力，不增加产品代码 | M8 closed | done |

## Close evidence

- Config、client TCP、client UDP focused tests 各 `1/1`；真实 TCP/UDP focused tests各
  `1/1`。第一次真实 TCP 测试仅因未先构建 required binaries 而 setup failure；执行
  authoritative workspace bin build 后原命令通过，产品未修改。
- Accepted exact 的 format、Clippy、workspace binaries、all-features Full、ignored
  lifecycle `1/1`（`130.03s`）及 docs 均 exit `0`。
- Schema 3 milestone footprint `PASS`：code/tests `15996/26916`、ratio `1.682671`、
  case/support/fixture `22369/3950/597`，三类 delta 均为 `0`。
- Architect `PASS`，QA `PASS`。`ARCH-M9-MU-001` 由 glossary/AGENTS 更正关闭；
  `M9-QA-001` 由记录完整 Rust test path 关闭；`M9-QA-002` 由本合同关闭。无剩余
  blocker、major、minor 或 numeric `REVIEW_REQUIRED`。
- M8 automatic run `30848182146/1` 的同产品树 MSRV、Windows/GNU/musl、TCP/UDP
  `12/12`+cleanup 证据继续有效；M9 不声明新的 platform、interop 或 performance 结果。
  未执行或授权 remote action。
