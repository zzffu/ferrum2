# M15 — Windows Wintun TUN data plane

- **Status:** executing
- **Qualified M14 product:** `bc6963472d9ae8e3c84d82851fd64d78c9f2a65f`
- **Qualified M14 product tree:** `a5533723d251b62529daa767dd083404fa0a30bc`
- **Planning baseline:** `bd374c6ec47470020bfcf908aa1a3475f0b3dbf0`
- **Planning tree / parent:** `9a6f10f07495ad45ab24cb07368a6b14d9998377` /
  `bc6963472d9ae8e3c84d82851fd64d78c9f2a65f`
- **Strategy:** drain；all tickets integrate serially
- **Owner:** primary thread
- **Target:** Windows NT 10.0+ AMD64 through `x86_64-pc-windows-msvc`
- **MSRV:** raise to exact Rust `1.97.1`，the latest stable release on the 2026-08-09 planning date
- **Performance:** required — Wintun、the userspace TCP/IP stack、bounded bridges and
  flow/mapping ownership enter a transport hot path

## Outcome

在 Windows AMD64 client 上交付一个显式、可选、手动路由的 Wintun TUN inbound。Ferrum2 创建并
独占 adapter，配置 IPv4/IPv6 interface address 与 MTU，在一个同步 owner thread 内运行有界
TCP/UDP userspace stack，并把 flow-level I/O 交给现有 M14 route/sniff、`DnsProxy::answer`、
`ClientEgressEngine`、`ClientUdpAssociation` 和 relay lifecycle。外部控制器或运维系统负责把
窄范围流量导入 adapter；Ferrum2 不调用 Windows route/DNS/WFP mutation API，不认领外部 route。

本计划复核并替代外部讨论稿
`C:\Users\ZZZ\Downloads\ferrum2-M15-tun-data-plane-plan-v1.md` 的 ticket 切分。该文件是
owner-provided design input，不是仓库证据。上游事实与纠正记录在
[`M15-wintun-smoltcp-windows-baseline.md`](../research/M15-wintun-smoltcp-windows-baseline.md)。

## Planning corrections

- `[tun]` 是 additive client shape，使用现有 `schema_version = 2`；无 breaking semantic 支持
  schema 3。Presence enables the inbound；删除冗余 `enabled` 与固定值 `tunnel_type`。
- 复用 lockfile 中 exact `windows-sys 0.61.2`，不引入草案的 `0.61.1` identity。按 owner 决策选择
  exact no-default `smoltcp 0.13.1`；SPEC-0016 冻结 windows-sys direct-edge literal 8-feature declaration、
  pre-existing unified graph 中不越过其 Cargo feature closure 的 delta，以及 smoltcp literal 10-feature
  set/单一 0.13.1 identity。`smoltcp 0.13.1` 最低需要 Rust 1.91；M15 不停在最低值，而是把
  workspace、CI 和 policy MSRV 精确提升到规划日最新 stable `1.97.1`。现有 `rust-toolchain.toml`
  已是 `1.97.1`；未来 stable 发布不自动漂移，升级需新的 control amendment。
- M15 的 packet boundary 是 IPv4 IHL=5/no fragment 与 IPv6 base-header direct TCP/UDP；不遍历任何
  IPv6 extension chain，不启用或声称 IPv4/IPv6 reassembly。草案的 `no-auto-icmp-echo-reply` feature
  不存在；`0.13.1` 的正向 `auto-icmp-echo-reply` feature 明确不启用。smoltcp AnyIP 只使用两条
  有界 in-memory default routes，不调用 Windows route API。
- 只增加 `ferrum2-wintun` 与 `ferrum2-tun` 两个 deep modules。最小 address/MTU Win32 owner 与
  Wintun adapter 同生命周期，故不建立独立 `ferrum2-windows-net` crate。
- `--check-config` 仍无 DLL、driver、admin、thread 或 OS mutation。`ProcessRoot::prepare` 先启动最终
  owner thread，由该线程独占完成并回滚 DLL/adapter/MTU/address/session/DAD/smoltcp setup；session
  仅先使 Wintun media online，creation rows不请求optimistic DAD，且两行自然到达Preferred前不
  poll packet；停止时该
  线程先醒出 wait、结束 session、清理并退出，async root 最后 join。同步 `activate` 只发送
  non-blocking admission signal，不修改 `ProcessSupervisor` interface。
- 配置 address/prefix 可能产生 Windows-managed connected/local route rows。合同只禁止产品显式
  创建/拥有 capture、default、bypass route；E2E 必须证明预期 system rows 随 adapter cleanup 消失。
- 草案默认 TCP buffers 在 metadata 之前已达到约 2 GiB。M15 冻结每个字段范围与 checked aggregate
  公式；default exact `53,995,616` bytes，TUN-owned hard ceiling `256 MiB`，internal queue counts不
  成为 operator surface。`DadState == IpDadStatePreferred` 才可 ready。
- `[[inbounds]]` 保持 declaration-order ordinary IDs，singleton TUN 总是追加为 ID N；TUN-only 是 0，
  添加/删除 TUN 不重排 SOCKS。UDP 采用 provisional candidate → client-owned opaque terminal token/bound
  → owner commit；route/hijack/reject plan 不进入 `ferrum2-tun`，bound 通过前不创建 mapping。
- 首选 ephemeral GitHub-hosted Windows administrator runner 进行 privileged evidence；Hyper-V/
  self-hosted guest 只在 direct capability probe 证明不可用后再规划。

## Existing seams and minimum deepening

- `OrderedRouteProgram`/`CompiledRoute`、`ferrum2_sniff::sniff`、
  `collect_sniff_prefix`、`DnsProxy::answer`、`relay_lifecycle` 已可复用。
- `ClientEgressEngine` 与 `ClientUdpAssociation` 保持 client binary-private；TUN sibling module 已有
  所需 visibility，不增加 public factory/trait。
- `ClientRouting::select_terminal` 从 SOCKS-local 位置移动到一个 run-local shared module；TUN TCP
  只组合现有 route/sniff primitives。DNS-over-TCP framing generalize once for SOCKS/TUN。
- `ClientUdpAssociation` 的 ingress-neutral request/response mutation ordering deepens once，避免
  SOCKS、DNS、TUN 各自维护一份 SIP022 UDP choreography。
- `ferrum2-tun` 只公开 flow-level TCP stream / UDP datagram interface 和一个 required process root；
  Wintun handles、smoltcp objects、packet pointers、queue commands and test adapter remain hidden。

## Non-goals

- Automatic/default/capture routes、endpoint bypass、route-change monitoring、system/interface DNS、
  WFP/strict-route/kill-switch or network-change migration。
- Linux/macOS TUN、Windows ARM64/x86 qualification、ICMP proxy/echo、IP fragment reassembly、
  Fake-IP、process routing、QUIC/HTTP3 or raw-packet plugin/filter interfaces。
- Installer、service、UAC elevation、bundled/committed Wintun binary、package、release or publication。
- A second route engine、DNS parser/resolver、SIP022 implementation、UDP association engine、generic
  Endpoint registry、public packet-device factory or preparatory future route module。
- Throughput improvement or minimum performance threshold claim。

## Exit criteria

- [ ] Exact M14 product and planning HEAD/tree/parent resolve；their diff is tracked documentation only。
- [ ] Official Wintun `0.14.1` ZIP hash
      `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` and AMD64 DLL hash
      `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`、PE architecture、
      Authenticode、license member and required ABI exports are verified before use。
- [ ] Runtime loads only the exact executable-sibling DLL through an absolute path and System32-only
      dependency search，holds a non-write/non-delete-shared handle across hash/load，checks exact size/hash
      and the eleven allowlisted symbols，and fails closed otherwise。
- [ ] `windows-sys = 0.61.2` reuses the existing identity with the direct-edge literal eight features and no
      resolved-feature delta outside their Cargo feature closure；one exact
      `smoltcp = 0.13.1` uses the literal ten no-default features，omits `auto-icmp-echo-reply` and configures
      exactly two internal AnyIP routes。
- [ ] Official latest-stable evidence freezes Rust `1.97.1` for this plan；workspace `rust-version`、selected
      toolchain、all CI MSRV selectors and workspace-policy assertions resolve exactly to `1.97.1`。No
      floating `stable`/`latest`/nightly selector or residual implementation/qualification `+1.88.0` gate
      remains；T01's pre-change 1.88 baseline probe stays historical control evidence only。
- [ ] One audited `ferrum2-wintun` unsafe exception contains all Wintun/Win32 calls and raw pointers；
      all other product sources remain unsafe-forbidden。
- [ ] Schema-v2 `[tun]` supports TUN-only and SOCKS+TUN client graphs、static binding or the existing
      ordered program；ordinary SOCKS indices stay declaration-ordered and TUN appends last；schema-v1 and
      server TUN fail closed；TUN omission preserves M0～M14 exactly。
- [ ] `--check-config` validates tags、addresses、bounds and checked memory with no runtime/OS side effect；
      exact default budget is `53,995,616` bytes；unsupported target、OS、DLL、ABI、privilege and driver
      failures occur before public service。
- [ ] Prepare starts the final owner thread and that thread creates/reverses adapter/per-family MTU/address/
      session/DAD/smoltcp state；session precedes DAD only as media-liveness prerequisite，optimistic DAD is
      not requested，and activate is non-blocking；both DAD rows naturally reach exactly Preferred before ready；
      cleanup finishes on-thread before join，and every partial failure、later-root failure、panic、graceful
      and forced stop reaps all flow/mapping/thread/HANDLE/buffer owners。
- [ ] Product calls no explicit route/DNS/WFP mutation API；privileged snapshots prove only expected
      address-derived system rows appear and all Ferrum2-owned interface state disappears after stop。
- [ ] Invalid、fragmented、oversize、IPv4-option、non-TCP/UDP or any IPv6 extension input cannot create a
      flow、mapping、route metadata、egress/session state or unbounded allocation；no such packet reaches TX。
- [ ] IPv4/IPv6 TUN TCP route/sniff/hijack/reject、prefix exact replay、eager local handshake/reset on
      selected-open failure、half-close、backpressure and forced drain pass without policy fallback。
- [ ] IPv4/IPv6 TUN UDP selects one terminal mode/plan at the first classification-eligible datagram；
      provisional candidates remain mapping-free until the caller decision，over-limit candidates commit
      nothing，later valid candidates re-read selector state，live mappings never re-enter ordinary policy，
      and expiry permits reselection。
- [ ] TUN UDP route uses the existing `ClientUdpAssociation` transitions and exact response binding；DNS
      hijack uses the existing `DnsProxy::answer`；reject/hijack create no Shadowsocks owner。
- [ ] No target、packet、adapter identity、route、tag、SNI、Host、qname or secret enters errors、logs、traces
      or metric labels；new telemetry is fixed and low-cardinality only。
- [ ] One exact integration SHA passes focused、Full、Rust 1.97.1、100+ lifecycle、Windows/GNU/musl
      non-driver、SIP022/CoreDNS/BIND、architecture、footprint、privileged Windows TUN E2E and bounded
      Architect/QA review with zero blocking findings；the required job marker reports `functional=16/16`、
      `cycles=100/100`、cleanup and matching SHA/run/attempt。
- [ ] After explicit remote authorization，the same SHA passes an independent Windows TUN
      `windows-tun-performance` job with `witnesses=2/2`、cleanup and matching SHA/run/attempt；no threshold
      or improvement claim is implied。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M15-T01 | Freeze corrected contracts、dependency dispositions and footprint control | M14 closed | done |
| M15-T02 | Prove M14 classification-eligible UDP commit ordering and selector re-read | M15-T01 | done |
| M15-T03 | Prove config → Wintun/MTU/address/session/DAD → bounded stack → rollback | M15-T02 | done |
| M15-T04 | Compose IPv4/IPv6 TUN TCP through the existing policy/DNS/egress/relay seams | M15-T03 | done |
| M15-T05 | Compose IPv4/IPv6 TUN UDP mapping and DNS hijack through existing association seams | M15-T04 | done |
| M15-T06 | Close failure、lifecycle、architecture、privileged and performance evidence | M15-T05 | active |
| M15-T07 | Qualify and close one exact M15 integration SHA | M15-T06 | planned |

```text
M15-T01 contracts/control
  -> M15-T02 existing UDP commit-order proof
  -> M15-T03 privileged Wintun-to-stack foundation
  -> M15-T04 TCP vertical slice
  -> M15-T05 UDP/DNS vertical slice
  -> M15-T06 integrated evidence/tooling
  -> M15-T07 exact-SHA qualification
```

The graph drains serially。T03～T05 intentionally overlap the stack owner、client process root、shared
policy/egress seams and shutdown；no concurrent writer receives those paths。Each ticket uses one branch、
worktree、writer and accepted exact base。

## Test-footprint and remote boundary

Planning baseline is code/tests `25586/45009`、ratio `1.759126` and
case/support/fixture `39260/5152/597`。TEST-0016 forecasts `2630..4140 / 520..930 / 0` growth。
Numeric `REVIEW_REQUIRED` is expected for some transport/security tickets；integrity remains blocking and
independent evidence must not be compressed or deleted to improve the signal。Use existing crate tests、
`m0-harness` and one Windows platform controller；no second Rust harness or committed packet/binary fixture。

The plan itself authorized no remote action。The 2026-08-09 execute request now authorizes every required
non-force push、the direct hosted probe and the independent same-SHA performance dispatch。A failed run is
not rerun without fresh authorization；force-push、PR、tag、package、release and publication remain
unauthorized。The Wintun custom prebuilt license permits alongside-API use textually，but GPL-3.0-only
combined redistribution is a release/legal decision；M15 downloads it ephemerally or requires an operator-
supplied exact DLL and does not redistribute it。

## Blocker / next action

No current blocker。Exact T05 `da38170947b8c708d230d14970c4a63f802accf3` passed local gates and hosted
run [`31360570556/1`](https://github.com/zzffu/ferrum2/actions/runs/31360570556)，including the exact
`profile=transport functional=16/16 cleanup=PASS` marker；its Windows-equivalent parent also passed a fresh
isolated-VM `16/16` run with zero residue before final review。T06 is active on this serial base and owns the
integrated full/lifecycle/performance evidence only；product paths remain read-only unless a concrete defect
requires a narrow amendment。Required non-force pushes and the exact performance dispatch remain authorized；
rerun、force-push、PR、tag、package、release and publication remain unauthorized。Redistribution remains
blocked pending the responsible license decision。
