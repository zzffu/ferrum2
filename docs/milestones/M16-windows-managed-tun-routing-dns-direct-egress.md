# M16 — Windows managed TUN routing, DNS and direct egress

- **Status:** executing
- **Qualified M15 product:** `7ba6268ffa3c5ecc7ba2b91e3ebcae8f596ecbb9`
- **Qualified M15 product tree:** `72a3cfb5c881a35b1416cbf9ffea593973cc3570`
- **Planning baseline:** `fcef80dcc7e62bbca63ffbf7832df369dd418abd`
- **Planning tree / parent:** `ddeb8afba64729f08a334d9c8a56e17e92c1d224` /
  `ba637e08287cbb623d4b604123f27e9e8b2df537`
- **Strategy:** drain；all tickets integrate serially
- **Owner:** primary thread
- **Runtime target:** Windows NT 10.0 build 19041+ AMD64 through `x86_64-pc-windows-msvc`
- **Privileged qualification VM:** `Windows 10 MSIX packaging environment`
- **Qualification checkpoint:** `M15-T04-before-2b0c25b-20260810`；actual guest product、edition、architecture
  and full version/build recorded after restore
- **MSRV:** exact Rust `1.97.1` unchanged
- **Performance:** required — client socket creation and TUN route/DNS/lifecycle ownership enter transport and
  resource paths

## Outcome

在 schema-v2 Windows client 中，把原先分开的“自动路由/DNS”和“direct outbound”合成一个可独立
验收的 M16：operator 可声明 `[[outbounds]] type = "direct"`，现有 static/ordered route/selector/DNS
detour 选择后，TUN 或 SOCKS TCP/UDP 直接访问原 target 而不创建 SIP022 state；显式 opt-in 的
`auto_route` 以 bounded include-minus-exclude `/1` capture rows 把流量导入既有 M15 Wintun data plane，
并在每个 IPv4 proxy/direct/DNS physical socket connect/send 前绑定 capture 前冻结的 underlay；可选
`auto_dns` 只给该 Wintun interface 设置 synthetic IPv4 resolver address，并把 exact TCP/UDP port 53
交给既有 `DnsProxy`。M16-new managed route、DNS、pinning、change evidence and privileged qualification are
IPv4-only；既有 M15 manual-route IPv6 adapter/data plane、SIP022 IPv6 与 non-managed/SOCKS direct IPv6
保持不变。所有 owned route/DNS/interface state 与 adapter 同生命周期回读、回滚和审计。

This plan supersedes the owner-provided discussion draft
`C:\Users\ZZZ\Downloads\ferrum2-M16-windows-routing-dns-plan-draft-v1.md`，uses
`C:\Users\ZZZ\Desktop\Windows-TUN-路由配置经验.md` and
`C:\Users\ZZZ\Desktop\Hyper-V-VM-测试经验总结.md` as operational input，and incorporates the separate
direct-egress milestone request。Those external files are design input，not repository evidence。Primary-
source corrections and sing-box comparison are recorded in
[`M16-windows-auto-route-dns-direct-reference.md`](../research/M16-windows-auto-route-dns-direct-reference.md)。

## Planning decisions and corrections

- Existing missing outbound `type` remains Shadowsocks；explicit `shadowsocks` is accepted。Direct is a
  client-only closed variant with no server/method/PSK，can be selected by static/rule/final/selector/DNS
  detour，and is rejected inside a fixed proxy chain。Direct-only tagged clients may omit meaningless global
  Shadowsocks credentials。
- Core keeps one opaque `EgressPlanSnapshot` of concrete indices。A direct snapshot is singleton；client
  egress，not TUN/route/core callers，dispatches Direct versus Shadowsocks。TCP reuses the existing dialer；UDP
  reuses the existing bounded resolver/socket/session owners。No new route action、crate、registry or public
  factory is planned。
- Direct means “traffic entered TUN，then physical egress without SIP022”。`route_exclude_address` means the
  prefix never entered TUN。`CONTEXT.md` replaces the ambiguous historical “direct action” with one-hop proxy
  plan and client direct outbound。
- While auto-route is active，fixed IPv4 Shadowsocks/DNS physical endpoints use endpoint-specific capture-
  before interface binding，and arbitrary IPv4 direct targets use one frozen physical default interface。This is intentionally not full
  per-target multihomed Windows route fidelity；LAN/VPN/non-default prefixes must be excluded from capture。
- TUN+direct also publishes only the read-only IPv4 physical-default binder when `auto_route = false`；the M15
  external controller adds its manual capture only after Ready。Windows TUN-selected direct IPv6 fails before
  physical socket creation for either auto-route state，with no unpinned fallback。No-direct/manual-route
  configurations retain exact M15 socket and host-state behavior。
- `GetBestRoute2` cannot discover an interface by destination alone。Fixed IPv4 endpoints use
  `GetBestInterfaceEx`，then validated index/LUID，then interface-constrained `GetBestRoute2`。Every direct
  socket uses the already frozen policy after capture；there is no unpinned fallback or per-flow bypass route。
- Capture is canonical bounded IPv4 `route_address − route_exclude_address`，with `0.0.0.0/0` split to two `/1`
  rows and all IPv6 inputs rejected。Ferrum2
  creates only Wintun capture rows，prechecks absence，sets every required row field，reads ActiveStore back，
  journals only exact success and reverses only still-owned rows。It never flushes routes or records
  address-derived rows。
- Auto-DNS is Wintun per-interface resolver steering，not global DNS ownership or anti-leak。No physical DNS、
  WFP、off-TUN port-53 block、browser DoH/DoQ claim or strict-route mode is included。
- Exact restored-VM preflight found one usable IPv4 physical default but no IPv6 physical default、non-link-
  local physical IPv6 address or owned off-link dual-stack endpoint。This is a planning input，not PASS。It
  narrows the new managed contract without adding a VM、committed endpoint、knob or weakening M15 IPv6 regressions。
- A later planning preflight proved guest reachability to one transient host-owned IPv4 TCP/UDP echo listener
  and audited its process absent afterward without host network mutation。T01 may reproduce only that bounded
  support endpoint：the qualifier/product and every route、address、firewall、adapter、TUN、capture、DNS and
  pinning mutation stay in the restored guest；the listener's exact address、ports、PID and owner extend the
  existing local identity ledger/hash，and it auto-exits or is stopped and audited absent after every attempt。
  Existing host policy must admit it without a firewall exception or T01 is blocked。This is not PASS and adds
  no second VM、harness、helper or committed endpoint；the pinned/unpinned Wintun A/B remains mandatory。
- `ferrum2-wintun` remains the single audited Windows unsafe Adapter。Route/DNS/socket/notification operations
  share the owned adapter lifetime，so the draft's new `ferrum2-windows-net` crate is not justified yet。
- Existing `ProcessSupervisor` and synchronous non-blocking activation remain。Non-TUN roots prepare first；
  managed TUN prepares last，subscribes before snapshot，adds capture as its last host mutation and revalidates
  the physical generation before ready。Network invalidation removes capture and terminates；no live flow
  migration or fail-closed claim。
- The current planning baseline includes the post-M15 test-only DNS cancellation commit `fcef80d…`。It is the
  exact M16 footprint/comparison base；the qualified M15 product identity remains unchanged。

## Entry feasibility gate

M16-T01 is a product stop gate，not implementation scaffolding。After restoring the exact current qualification
VM/checkpoint above，the probe must record its actual product、edition、architecture and full version/build，
freeze exact IPv4 route next-hop/metric/interface-metric disposition，prove fixed-first-hop and dynamic-direct
IPv4 pinned TCP/UDP positive versus unpinned Wintun-captured negative controls，prove IPv4 Wintun resolver UDP/
TCP steering and the capture-before-
admission interval，and externally prove zero residue
after partial apply、normal stop and `TerminateProcess`。The host may run only the identity-ledger-bound transient
TCP/UDP echo listener above，never the qualifier/product or any host network mutation；listener residue or a
required firewall exception blocks T01。An inaccessible/mismatched asset or any failed
capability leaves M16 blocked for contract replanning；T02 cannot paper over it with another VM、fakes、new
knobs、a service or watchdog。M16 makes no independent cross-version Windows qualification claim。

M16-T01 passed this entry gate on candidate `cc26aba03d816dfd29e8e04177a6f70a9d009b37` with probe SHA-256
`58b18f2d33da8f065f8f572acf252b64d6a503ecc61e59b1cd45843796f5ca90`。The restored guest was Windows
10 Enterprise Evaluation、`EnterpriseEval`、AMD64、version `10.0.19044.0`、build `19044.1288`，with one
IPv4 default and zero IPv6 defaults。The exact capture rows were `0.0.0.0/1` and `128.0.0.0/1` with next hop
`0.0.0.0` and row metric `1`；the interface metric remained unchanged。Fixed binding uses
`GetBestInterfaceEx(destination)` → validated physical index → interface-constrained `GetBestRoute2` →
frozen preferred source/route fingerprint，while dynamic direct freezes the one unique pre-capture IPv4
physical default。The measured underlay rows had prefix length `0` and row metric `0` and agreed on physical
interface/source/next hop without committing their identities。Pinned/unpinned、DNS、`768 ms` capture window、
hard-kill and cleanup rows all passed，so T02 is ready；the result remains limited to this exact asset/build。

## Planning/control isolation

The isolated control-plus-Markdown M16 plan is accepted at
`a9619ef8269424fd345403de8d3bb033b0d5f9d8`，and its single-VM evidence-scope amendment is accepted at
`a8205c2bee31283294fdd5ca47349c74b3195cad`。The Markdown-only IPv4 contract amendment and review repair are
accepted at `451edcbe04bc4abe7950f64dd10c1c25c7a692b0`，the exact base bound by T01。T01 added only the
existing qualifier probe plus Markdown evidence amendments；it did not reopen the protected footprint control。

## Existing seams and minimum deepening

- Keep `EgressPlanSnapshot`、route/final/static/selector compilation and selection lifetime unchanged。
- Change private `ClientOutboundContext` into the Direct/Shadowsocks sum and deepen `ClientEgressEngine` once。
  Its closed binary-private `Socks`/`Tun`/`Dns` request origin plus selected plan/original target controls the
  binding obligation；callers remain outbound-kind agnostic and are not socket owners。Do not infer policy
  from process-wide TUN presence。
- Reuse runtime `TcpDialer`/bounded resolver and `DirectUdpSocketFactory`/`DirectUdpRuntime` ownership。Do not
  retain the current DNS no-detour raw system connect/bind path when auto-route is active。
- Extend the existing `ferrum2-wintun::Adapter` owner with safe route/DNS/binding/notification operations;
  raw NetIO/Winsock values remain private to its Windows module。Split a private source file only if file
  review needs it；do not create a crate boundary without a second lifetime/consumer。
- Reuse the existing TUN owner thread and `tests/platform/qualify_windows_tun.ps1`。No second stack、DNS
  responder、UDP association engine、process supervisor or equivalent platform harness is added。

## Non-goals

- WFP strict-route、kill switch、DNS anti-leak/global exclusivity、physical adapter DNS or deleting/adopting
  third-party routes。
- Target-specific multi-interface direct routing、live underlay recomputation/migration、hot reload、active
  flow migration or automatic failover。
- Physical endpoint bypass routes as the recursion mechanism、`/0` capture rows、opening/reusing an existing
  Wintun adapter or broad route flush/delete。
- Linux/macOS managed TUN、Windows ARM64/x86、service/watchdog/installer/UAC automation、Fake-IP、process/
  Geo/rule-set routing、DoQ/DoH3、QUIC sniff、ICMP、fragments/options/extensions unsupported by M15。
- Independent Windows release/build qualification beyond the exact current VM/checkpoint；no Windows
  10-versus-11 compatibility claim is inferred from the single privileged evidence asset。
- M16-managed IPv6 capture、DNS steering、physical pinning or physical-network change qualification；this
  does not remove the M15 IPv6 adapter address/manual-route data plane or existing IPv6 regression rows。
- A new crate/dependency/endpoint registry/public egress trait，performance improvement threshold，Wintun
  redistribution，package、release or publication。
- The unrelated M15 Wintun ring-full observability repair from the external draft；it remains a separate
  maintenance item unless T01 proves it blocks M16 capability evidence。

## Exit criteria

- [x] T01 restores the exact current VM/checkpoint，records actual product、edition、architecture and full
      version/build，and freezes route values；pinned/unpinned、DNS、capture interval and hard-kill cleanup all
      pass，or the milestone stops before product work。
- [ ] `--check-config` remains side-effect-free；old outbounds default to Shadowsocks；direct closed fields、
      direct-only credentials、chain rejection and every managed-TUN bound/relationship fail closed correctly。
- [ ] Static/rule/final/selector can choose direct for SOCKS and non-Windows TUN IPv4/IPv6 TCP/UDP；Windows
      TUN-selected direct qualifies IPv4 only and rejects original IPv6 before any physical socket。DNS
      detour/no-detour can use the same direct mode；raw application payload returns and no SIP022 owner exists。
- [ ] Direct/proxy selected failure retains current no-fallback and selector snapshot semantics；TUN original
      target and UDP mapping selection lifetime remain unchanged。
- [ ] Auto-route rejects IPv6 prefixes，compiles exact bounded IPv4 prefix subtraction，creates no `/0` or
      physical bypass row，performs
      absent precheck/exact readback/reverse conditional cleanup and never adopts OS/third-party rows。
- [ ] While auto-route is active，every reachable IPv4 proxy、direct and DNS physical socket is bound before
      connect/first send；negative unpinned sockets are captured while positive pinned sockets do not enter
      Wintun。IPv6 concrete proxy or direct/no-detour DNS physical endpoints fail before mutation；an IPv6
      logical bootstrap behind an IPv4 proxy first hop remains allowed。With auto-route off，the exact M15-
      compatible IPv6 no-detour/direct DNS omission case remains unchanged。
- [ ] Manual-route TUN+direct publishes the IPv4 binding before Ready and survives a controller route added afterward；
      no-direct `auto_route=false` makes no new managed-network state query/mutation and preserves M15 exactly，
      including IPv6 proxy and absent/direct-detour DNS egress。
- [ ] Auto-DNS requires only `ipv4_dns_address`、rejects `ipv6_dns_address` and changes only owned Wintun IPv4
      DNS；system resolver UDP/TCP reaches the exact synthetic IPv4 address and existing DnsProxy；direct/proxy
      UDP/TCP/DoT/DoH upstreams use the correct pinned IPv4 first hop，while the M15 IPv6 adapter address remains。
- [ ] All setup ordinals、change invalidation、later composition failure、graceful/forced stop and 100 cycles
      return OS and process-private owners to baseline。External hard kill separately proves process absence
      and zero adapter/address/route/DNS residue before controller remediation，without claiming internal drain。
- [ ] The current qualification VM proves the real IPv4 route、physical interface and IPv4 unicast-address
      callback paths independently revoke admission/capture/DNS，terminate and leave zero owned residue；M15
      `16/16` transport and its IPv6 rows remain regression evidence。
- [ ] New errors/logs/traces/metrics use fixed redacted categories and contain no target、endpoint、prefix、
      interface/adapter identity、DNS name、tag、packet or secret。
- [ ] One exact SHA passes focused、Full、Rust 1.97.1、three non-driver targets、existing interop、footprint、
      current-VM privileged full/cleanup、independent performance and bounded Architect/QA review with zero
      blocking findings；hosted results are regression evidence，not a second OS qualification baseline。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M16-T01 | Prove IPv4 Windows host-network capabilities and freeze measured contracts | accepted Markdown-only IPv4 scope amendment atop `a8205c2…` | done |
| M16-T02 | Compile the closed direct outbound and managed-TUN configuration | M16-T01 | ready |
| M16-T03 | Compose shared client direct TCP/UDP egress without managed capture | M16-T02 | planned |
| M16-T04 | Own compatible capture routes and pre-connect physical socket binding | M16-T03 | planned |
| M16-T05 | Steer Wintun DNS and exact synthetic TCP/UDP DNS traffic | M16-T04 | planned |
| M16-T06 | Close network-change、failure、hard-kill and current-VM lifecycle evidence | M16-T05 | planned |
| M16-T07 | Qualify and close one exact M16 integration SHA | M16-T06 | planned |

```text
M16-T01 capability/contracts/control
  -> M16-T02 config and compiled graph
  -> M16-T03 direct TCP/UDP egress
  -> M16-T04 capture routes and socket pinning
  -> M16-T05 Wintun DNS steering
  -> M16-T06 integrated lifecycle/VM evidence
  -> M16-T07 exact-SHA qualification
```

The graph drains serially。T02～T06 overlap config、client egress、Wintun ownership and composition，so the
plan does not claim false parallelism。Each ticket uses one branch、one worktree、one writer and the accepted
exact integration base；workflow/control files remain read-only during product tickets。

## Test-footprint and remote boundary

Planning baseline is code/tests `29771/50323`，ratio `1.690336`，case/support/fixture
`44574/5152/597`。Forecast Rust test growth is `+2250..3650 / +160..460 / +0` and existing PowerShell
qualifier growth is `+450..850` non-Rust lines。No second harness or fixture is planned；table-driven cases and
existing helpers are mandatory first choices。Ticket/file numeric `REVIEW_REQUIRED` findings need an explicit
review disposition，while integrity remains a hard gate。

No push、workflow dispatch、PR、tag、package、release or publication is authorized by this plan。T01 VM work is
local isolated-guest evidence。Any later hosted push or independent performance dispatch requires explicit
user authorization and must bind the accepted exact SHA。

## Blocker / next action

The M16-T01 capability gate is complete and its frozen IPv4 route、metric、binding、DNS、capture-window and
hard-kill results are recorded。M16-T02 is the next serial frontier and may compile the approved closed direct/
managed-TUN configuration from the accepted T01 descendant。Independent T01 Architect/QA evidence review is
still pending；it must not be reported as passed until completed。No push、dispatch or product work beyond T02
is authorized by this status transition。
