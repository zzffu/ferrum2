# M12 — tagged DNS resolution and proxy

- **Status:** executing
- **Baseline:** `c733e0dd03e711c045c0b7a4ee189277fbe37698`
- **Strategy:** drain
- **Owner:** primary thread
- **Performance:** required — DNS adds UDP/TCP hot paths、DoT/DoH connection owners and independent
  process roots

## Outcome

基于exact latest Hickory 0.26.1，在schema v1中增加optional tagged DNS graph。Client可公开同地址
UDP/TCP DNS proxy，server可为authenticated domain target独立选择UDP、TCP、DoT或DoH server。
DNS route复用既有inbound/network/exact-target条件和唯一first-match实现，但action只命名DNS
server tag。每个DNS server另可用sing-box-style `detour`引用existing outbound action作为其
egress；路径A和路径B都使用该字段。`[dns]`缺失时全部既有行为exact；不重写DNS协议、传输、
Shadowsocks数据面或规则引擎。

最新`hickory-resolver`/`hickory-proto`的MSRV是Rust 1.88，因此M12把workspace
`rust-version`和MSRV CI从1.85.0升至1.88.0；selected build toolchain仍为1.97.1。

## Baseline evidence

- Workspace：root `Cargo.toml:18-23`声明edition 2024、Rust 1.85.0；CI和
  `workspace_policy.rs`显式固定1.85.0，`rust-toolchain.toml`固定1.97.1。
- Core：`RouteRule::matches`和`RouteTable::select_plan`是唯一
  inbound/network/pre-resolution exact-target first-match路径
  (`crates/ferrum2-core/src/lib.rs:440-590`)。Domain已ASCII case-insensitive且terminal dot exact。
- Config：`load_client/load_server`在runtime前解析最多1 MiB typed TOML；route tags/actions已全部
  resolve (`crates/ferrum2-config/src/lib.rs:330-1008`)。没有`[dns]` shape。
- Runtime：`TcpResolver`/`UdpResolver`与system实现已限制最多16 candidates
  (`connector.rs:49-79`、`udp.rs:755-783`)；`BoundedSupervisor`及
  `ProcessRoot/ProcessSupervisor`已拥有连接admission和事务式生命周期。
- Product：client把SOCKS domain保留到SIP022 wire；server direct在authentication和route selection
  后通过system resolver解析。没有public DNS listener、tagged DNS upstream或TLS/HTTP DNS路径。
- Hickory 0.26.1：resolver/proto/server均声明Rust 1.88；resolver提供UDP/TCP/DoT/DoH和bounded
  request options。Stock server TCP accept未暴露ferrum2所需connection ceiling，故只复用其
  message types，framing通过Hickory net under existing supervisor。
- Footprint：current code/tests `16023/32456`、ratio `2.025588`、
  case/support/fixture `27788/4071/597`；largest test file为client `run.rs` 7,018行。

## Decisions fixed by ADR-0031

- Exact `hickory-resolver/proto/server =0.26.1`；resolver no-default with Tokio、ring DoT/DoH and
  WebPKI roots。MSRV exact 1.88.0，build toolchain不变。
- 新`ferrum2-dns` deep module承载Hickory integration；core只抽取已有generic first-match action
  table。Ordinary outbound action与DNS `server` action保持独立。
- Client `[[dns.inbounds]]`每个tag同地址公开UDP/TCP；server不公开DNS listener，而为direct
  domain target选择tagged resolver。`[dns]` absent保留system resolver。
- `dns.servers[].detour` optional引用同一配置中的existing outbound/chain/selector action；缺失为
  direct。Client可经existing Shadowsocks plan访问四种DNS transport；server当前只能引用existing
  direct outbound。Detour不执行ordinary route、不fallback，且作为outbound reachability root。
- DNS server `address`必须numeric SocketAddr并作为bootstrap/dial endpoint；DoT/DoH另需verified
  `server_name`，DoH path默认`/dns-query`。无hostname bootstrap、insecure TLS或custom CA product
  field。
- CoreDNS encrypted positive qualification只可用default-off `ferrum2-dns/__interop-test-root`隔离
  build内嵌reviewed M12 test CA；chain/time/name验证保持，feature不接受runtime trust input，normal/
  default/release artifacts保持WebPKI-only且qualification target run后删除。
- Client proxy rule context是DNS inbound + query transport + absolute qname:53；server resolver
  context是authenticated inbound + application network + original target/port。
- Selected failure不试later rule/final/other tag；only UDP truncation可同tag同address升级TCP。
  Hickory retry/cache为0。
- Global `max_inflight`、absolute `timeout_ms`、aggregate DNS TCP connection count、4,096-byte UDP、
  65,535-byte TCP and bounded queue/task owners fail closed。Hickory background tasks由ferrum owner
  追踪并awaited shutdown。
- CoreDNS 1.14.6 four transports和BIND dig 9.20.26 client为external selected profile；performance/
  resource required但无threshold或claim。

## Non-goals

- Recursive/authoritative DNS、zone/update/transfer、DNSSEC、mDNS、DoQ/DoH3、cache或general retry。
- DNS server group、DNS-server selector、health、load balancing、fallback/failover，或suffix/wildcard/regex、
  CIDR、qtype、client-IP、Geo/sniff response policy。
- Hostname bootstrap、new server-side proxy outbound、custom CA/insecure TLS、DoH auth/headers或
  system roots。
- Client提前解析SOCKS target、SIP022 wire变化、rule engine replacement或standalone DNS binary。
- Hot reload、management API、transparent/TUN、package、release或publication。

## Exit criteria

- [ ] Exact Hickory 0.26.1 dependency/features/license graph和Rust 1.88.0 MSRV通过；1.97.1 build
      toolchain及existing packages保持。
- [ ] Legacy/M7/M8/M10/M11 schema cohort在`[dns]` absent时exact；所有DNS count/tag/role/
      transport/bootstrap/TLS/path/rule/detour/loop错误在side effect前closed/redacted fail。
- [ ] Outbound与DNS两种action通过同一core first-match实现；existing route/selector结果exact，
      client qname:53与server original target contexts按first/final选择且failure no fallback。
- [ ] Path A client proxy和Path B server resolver都按selected DNS server的optional `detour`使用
      configured egress action；absence direct、tag reachability、selector/flow snapshot、UDP TC
      same-plan upgrade及detour failure no-fallback通过。
- [ ] Tagged UDP/TCP/DoT/DoH处理positive/NXDOMAIN/NODATA、UDP TC same-server upgrade、TLS/HTTP
      validation、deadline和negative transport matrix；不复制DNS parser/framer。
- [ ] Client真实UDP/TCP proxy与server真实TCP/UDP domain direct paths通过；malformed/error codes、
      client direct/detoured UDP/TCP/DoT/DoH、internal UDP不隐式开放SOCKS UDP ASSOCIATE、server
      detour、16 candidates、pre-resolution route order、IP bypass和SIP022 domain preservation通过。
- [ ] Saturation/indirect loop/idle/cancel/graceful/forced cases保持固定connection/query/session/task/
      buffer ceiling，Hickory/detour tasks归零并exact listener/hop/upstream rebind；无destination
      telemetry泄漏。
- [ ] 一个exact SHA通过Full、Rust 1.88、100+ lifecycle、three native targets、existing SIP022
      TCP/UDP各`12/12`+cleanup、CoreDNS/BIND DNS interop、schema 3 footprint、blocking reviews及
      separate authorized performance/resource job。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M12-T01 | Pin Hickory 0.26.1 and raise the workspace MSRV to 1.88.0 | — | done |
| M12-T02 | Compile DNS config、detour roots and one shared first-match action table | M12-T01 | done |
| M12-T03 | Implement tagged Hickory upstreams over bounded direct/detour runtime adapters | M12-T02 | done |
| M12-T04 | Expose client UDP/TCP DNS proxy with real Shadowsocks detours | M12-T03 | done |
| M12-T05 | Compose server resolution/detours and prove external interoperability | M12-T04 | active |
| M12-T06 | Qualify one exact M12 integration SHA | M12-T05 | planned |

~~~text
M12-T01 exact dependency/MSRV
  -> M12-T02 config + shared action matcher + detour roots
  -> M12-T03 tagged upstream transport + direct/detour owner
  -> M12-T04 client UDP/TCP proxy + Shadowsocks detour
  -> M12-T05 server resolver/detour + CoreDNS/BIND interop
  -> M12-T06 exact-SHA qualification
~~~

Tickets drain serially because T02 establishes the action/config identities consumed by T03，T03/T04
share the new DNS crate and T05 must prove the integrated client/server path. Each writer uses one
ticket branch/worktree；workflow documents remain read-only during product work。

## Test-footprint forecast

Schema 3 resets at baseline code/tests `16023/32456`、ratio `2.025588`、
case/support/fixture `27788/4071/597`. Revised `TEST-0013` forecasts `1160/240/0` new
case/support/fixture LOC. Milestone numeric `REVIEW_REQUIRED` is expected；T02～T05 expect ticket
`WARN`，and existing client `run.rs` remains file `REVIEW_REQUIRED` if touched。Signals require
Architect/QA disposition but do not weaken evidence。New DNS test files should stay below 800 semantic
test LOC；no second harness、copied DNS codec或second SIP022 UDP data plane is planned。

## Execution / remote boundary

M12-T01 is integrated at exact product `d874865f4a66db8d7c50abad85e6092a16f52fb6`。M12-T02 candidate
`c2e922d0e4d29e7398ebb0cd3da0dce1516a8a54` is integrated at exact
`bf26d1587517fe80e701d73abfb45a340f4caa6c`；initial blockers were closed by one bounded repair and
targeted Architect/QA both returned `PASS`。Focused、Quick、integration and footprint integrity gates
pass；numeric `REVIEW_REQUIRED` is accepted。M12-T03 starts from the exact T02 integration product；its
isolated `30352074bdf7352d33a00cfc9f04da70fabbaec6` commit closes the three inherited server Rust-1.88
Clippy warnings and restores workspace Clippy。Two independent xhigh analyses of its encrypted-fixture
blocker selected exact workspace-pinned `h2/rustls/tokio-rustls` declarations、dev-only Hickory server
internal `__https`、reviewed static test DER and one ferrum-owned exclusive DNS runtime；normal product
WebPKI and 222 package identities remain exact。T03 final candidate
`10b7c31fea92691b94cae1fb16032aac20e65d27` is integrated at exact
`e1a9ae379a0c9363d7694fc99dbfcad602162d34`。Initial lifecycle review blockers were closed by one
bounded repair；the remaining pre-first-poll counter and blocking-Drop findings each followed the user's
required two-independent-`gpt-5.6-sol/xhigh` diagnosis path。The selected owned-guard、closed-TaskSet and
`TaggedResolverOwner` repair passed deterministic 100-cycle and 50-cycle checks，then final Architect/QA
both returned `PASS`。Integration focused、Full、Rust 1.88、ignored lifecycle `1/1` (`130.71s`) and docs
pass。Footprint integrity passes；numeric `REVIEW_REQUIRED` (`+2326/0/0`、code `+813`、ratio `2.026931`)
is accepted。M12-T04 final candidate `289c58428fabfb0ae362fc3c15234c3082f64201` is integrated at
exact `7d2cadabef8d558ac6d8ee52be1fa7d6183dc6d6`。Its initial Architect/QA blockers were closed by
exactly one bounded repair；targeted Architect/QA both returned `PASS`，so no post-review dual-agent
diagnosis was required。Integration core/client/DNS tests、workspace policy `21/21`、Full、Rust 1.88、
ignored lifecycle `1/1` (`130.37s`)、docs and locked offline metadata pass。Footprint integrity passes；
numeric `REVIEW_REQUIRED` (`+2260/0/0`、code `+433`、ratio `2.104062`) is accepted。M12-T05 is active
from that exact integration product。Before product edits，its ownership was completed with the existing
server manifest、lock row and workspace-policy assertion required for the already-declared local
`ferrum2-dns` edge；no new package identity or `main.rs` change is authorized。The existing external
qualification provider and its contract test are also owned so CoreDNS/BIND do not create a second
harness。Hosted provisioning may change `m0.yml` only through an isolated single-parent control-only
commit before product work，without changing triggers、manual-performance semantics or unrelated jobs。
That commit may be amended before the first product commit to enable the exact default-off
`ferrum2-dns/__interop-test-root` feature in the isolated DNS qualification build；T05 additionally owns
only the DNS manifest/resolver paths needed to embed the reviewed root without product config/runtime
input。Later product commits inherit the amended control blob unchanged。
Before formal T05 review，hosted and isolated Linux repetition exposed that a completed DNS command
woke its caller before releasing the shared `max_inflight` permit；a bounded T05 lease now owns only
`runtime_owner.rs` to reverse those two completion operations after registered-task cleanup。Admission
limits、deadlines、fallback and lifecycle ownership remain unchanged。
The user authorized remote pushes；none has run yet。Manual workflow dispatch remains separately
unauthorized；no hosted run、PR、tag、package、release or publication has occurred。
