# ADR-0034 — M15 Windows TUN ownership and policy seams

- **Status:** Proposed
- **Date:** 2026-08-09
- **Related:** `SPEC-0016`、`TEST-0016`、M15-T01～T07；preserves ADR-0023、ADR-0024、
  ADR-0031、ADR-0032 and ADR-0033

## Context

Wintun delivers borrowed IP packets through a synchronous Win32 ABI，while Ferrum2 policy、DNS and SIP022
egress are Tokio-owned and already have one accepted implementation。A TUN data plane therefore needs a
real ownership seam without moving Wintun pointers or smoltcp state across an await，duplicating route/DNS/
SIP022 behavior，or redesigning the process lifecycle。

The external proposal split Wintun、Windows network setup and the userspace stack into three preparatory
crates，placed blocking/fallible OS setup in synchronous activation，introduced schema version 3 and exposed
many internal queue knobs。Repository inspection shows that address/MTU work shares the exact lifetime of
the created adapter，`PreparedProcessRoot` already permits rollbackable setup during prepare，and `[tun]` is
an optional additive client shape。The upstream review also proves that interface addresses can create
Windows-managed connected/local routes even when the product calls no route-creation API。

## Decision

### Manual-route product boundary

M15 supports one optional Windows NT 10.0+ AMD64 TUN inbound。Ferrum2 creates a new adapter and owns only
that adapter、its two interface addresses、per-family MTU changes、session、wait/control handles、stack thread
and in-process flows/mappings。It never opens an existing adapter of the same name。

Ferrum2 does not call、own or delete explicit Windows capture/default/bypass route、system DNS or WFP state。
An external owner adds and removes any narrow route needed to direct application traffic。Windows-managed
connected/local rows derived from the Ferrum2-owned address/prefix are expected system state，not explicit
Ferrum2 route ownership；qualification snapshots them and proves they disappear with cleanup。

### Two deep modules and one caller adapter

`ferrum2-wintun` is the sole audited unsafe exception。It owns secure DLL loading、the fixed Wintun ABI、
RAII packet/session/adapter lifetimes and the minimal Win32 address/per-family-MTU transaction。This is one
true-external Adapter；a separate `ferrum2-windows-net` crate would expose the same lifetime through a
shallower seam and is not added。

`ferrum2-tun` is safe product code。One synchronous owner thread exclusively owns the Wintun device、
smoltcp `Interface`/`SocketSet`、packet staging、flow/mapping tables、timers and queues。The public outcome
interface is flow-oriented：a TUN TCP flow behaves as one bounded Tokio `AsyncRead + AsyncWrite` stream；a
TUN UDP candidate yields one bounded owned datagram and immutable tuple to the caller，then commits a
mapping only after the caller returns an opaque client-owned terminal token and selected-plan bound。The
client keeps route/hijack/reject mode and plan state behind that token；`ferrum2-tun` uses it only to correlate
bounded datagram delivery and never interprets policy。Internal command/event
enums、IDs、handles、packet views、smoltcp sockets and the deterministic packet-device test Adapter remain
private。No public Endpoint、route owner、factory or plugin registry is added。

The client binary owns the sole policy Adapter。It maps those flows through one shared run-local terminal
selection module and the existing `ClientEgressEngine`、`ClientUdpAssociation`、`DnsProxy::answer` and
`relay_lifecycle`。No policy、DNS、credential or SIP022 type enters `ferrum2-tun`。

The DLL loader assumes the executable installation directory is a trusted local boundary；a principal able to
rewrite that directory can replace the executable itself and is outside M15。Runtime still rejects UNC/network
or reparse-backed executable/DLL paths，holds every checked directory component without delete sharing，and
holds the exact non-reparse DLL without write/delete sharing across hash and load。This makes the remaining
trust premise explicit and prevents a path component from being retargeted during startup。

### Existing process lifecycle remains authoritative

Configuration parsing and `--check-config` remain free of DLL、driver、privilege、thread and OS resources。
During async `prepare`，the TUN `ProcessRoot` first starts the final synchronous owner thread。That same
thread secure-loads/verifies the DLL，creates the adapter，snapshots/configures addresses and per-family MTU，
waits bounded DAD，starts the Wintun session and constructs smoltcp，then sends one prepared acknowledgement。
On any setup failure it runs its own reverse journal before reporting failure and exiting；the async root
reaps the exited thread without blocking a Tokio worker。

Synchronous `activate` only sends a non-blocking admission signal。`run` owns every flow task and the owner-
thread join handle；quiesce stops new admission while existing TCP may drain。At final or forced stop，the
owner thread is woken out of its wait，stops all Wintun polling，ends the session，reverses address/MTU/
adapter/DLL ownership，reports cleanup，and exits；only then does the async root join it。Rollback uses the
same thread-owned cleanup path。No `ProcessSupervisor` interface change is planned。

### Schema and packet boundary

`[tun]` is accepted only by schema version 2 client configuration；omission preserves both existing versions。
Presence enables it，and its tag joins the existing ordinary inbound/DNS identity namespace。TUN-only and
SOCKS+TUN tagged graphs use the same static binding or ordered program；no dummy SOCKS listener is required。

M15 supports only complete、unfragmented IPv4/IPv6 TCP and UDP packets within the configured MTU。IPv4 has
an exact 20-byte header with no options；IPv6's base `Next Header` must be TCP or UDP directly，so no IPv6
extension header is accepted。Both the ingress side before a smoltcp `RxToken` and the egress side after
`TxToken::consume` enforce this same boundary。M15 pins no-default `smoltcp 0.13.1` and deliberately omits
its positive `auto-icmp-echo-reply` feature；the two filters remain a defense-in-depth owner invariant and
make every ICMP path unobservable。Allowing ICMP、IP options、extensions or fragments later requires a new
dependency/memory/security decision。AnyIP uses exactly two bounded in-memory smoltcp default routes via the
configured IPv4/IPv6 interface addresses；these are not Windows routes。

### Exact current-stable Rust contract

The 2026-08-09 planning decision pins Rust `1.97.1`，the then-current official stable release，as both the
workspace MSRV and selected build toolchain。`smoltcp 0.13.1` itself requires only Rust 1.91，but the owner
explicitly chooses the latest stable compiler rather than the dependency minimum。T03 atomically updates the
workspace `rust-version`、CI MSRV selectors and workspace-policy assertions；`rust-toolchain.toml` already
selects `1.97.1`。The word “latest” is provenance，not a floating selector：a later stable release requires a
new control amendment、dependency/CI review and exact pin。

### Flow selection lifetime

One TUN TCP five-tuple becomes one local TCP connection。The local userspace stack completes the application
handshake before upstream selection/open；a later terminal rejection or selected-open failure resets/closes
the local flow and never returns to a later rule/final/member。Sniff reads bounded application bytes and
replays them exactly once through the selected route or DNS path。

One TUN UDP five-tuple becomes one bounded mapping only after its first classification-eligible datagram。
Validation may temporarily evaluate route/selector to compute the selected plan's exact payload bound，but
an over-limit candidate commits no terminal mode、mapping、association、session、activity or send。The next
valid candidate evaluates current policy/selector again。After commitment，route/reject/hijack mode and any
egress snapshot remain fixed until expiry；ordinary routing never re-enters。

## Consequences

- The unsafe and platform-specific surface is reviewable in one small external Adapter；the userspace stack
  and all callers remain safe。
- The stack module is deep：callers handle flows，not polling、packet pointers、socket sets、queues or cleanup。
- Address/MTU and Wintun teardown are one transaction，but final adapter deletion is an E2E postcondition
  because `WintunCloseAdapter` returns no status。
- Operator-managed routes keep M15 bounded and avoid a premature bypass/route owner。Full-tunnel operation is
  not claimed；external owners must avoid recapturing Shadowsocks and DNS bootstrap endpoints。
- Eager local TCP handshake is simple and permits sniffing，but upstream-open failure appears as local reset
  rather than a delayed handshake failure。
- Dropping fragments limits UDP payloads to one MTU-sized IP packet and deliberately defers reassembly risk。
- Exact `windows-sys 0.61.2` adds no package identity；exact smoltcp `0.13.1` adds one 0BSD identity and the
  workspace intentionally drops Rust 1.88 compatibility by raising its MSRV to 1.97.1。Because MSRV now
  equals the selected build compiler，the former older-compiler compatibility signal no longer exists。The
  exact Wintun binary license remains a release/redistribution decision。

## Rejected alternatives

- **Three Wintun/Windows-net/TUN crates:** address and MTU have no independent M15 consumer or lifetime；the
  extra public seam would be shallow。
- **One client-local monolith:** would mix audited FFI and reusable packet/flow ownership with policy and
  make deterministic stack tests depend on the binary。
- **Public command/event protocol:** leaks owner-thread mechanics and makes the client responsible for byte
  retention、generation IDs and shutdown ordering。
- **Async activation redesign:** unnecessary when all fallible setup is rollbackable in prepare and
  activation is only an admission gate。
- **Schema version 3:** no existing accepted field is reinterpreted，so ADR-0023's additive rule applies。
- **smoltcp 0.12.0 to preserve the former MSRV:** technically viable behind the same filters，but rejected by
  the owner's explicit `0.13.1` and latest-stable Rust requirement；`0.13.1` also provides the positive echo
  feature boundary that M15 can explicitly prove absent。
- **Floating `stable`/`latest` or nightly Rust:** not reproducible。M15 records why `1.97.1` was selected and
  pins the number everywhere；future releases require a reviewed control change。
- **IPv4-only or partial fragment support:** contradicts the required dual-stack outcome or creates an
  asymmetric dynamically allocated reassembly surface；M15 drops all fragments instead。
- **Automatic route/bypass owner:** materially expands host-network risk and remains a later milestone。
