# ADR-0030 — M11 fixed client proxy chains and per-outbound credentials

- **Status:** Accepted
- **Date:** 2026-08-04
- **Related:** `SPEC-0012`、`TEST-0012`、M11-T01～T05；extends ADR-0027～0029

## Context

M7～M10 let one client process select several concrete Shadowsocks servers through static bindings、
first-match routes and manual selectors。Every selected leaf still uses one process-wide method/PSK and
opens exactly one SIP022 hop。M11 needs a fixed ordered client chain whose hops can use different
credentials，without turning the chain into an upstream group or adding retry/failover policy。

The normative [SIP022 specification](https://shadowsocks.org/doc/sip022.html) already defines independent
method-bound TCP streams and UDP sessions plus an optional relay role；M11 composes those existing wire
messages and does not define another wire format。The baseline has the required deep pieces：config validates a complete tagged graph before
`main` starts runtime work；`RouteTable` centralizes static/route/selector choice；
`ClientTcpOutbound` and `UdpClientSession` own the existing SIP022 state machines；and server direct TCP/
UDP can carry another Shadowsocks packet or connection as ordinary target traffic。The missing work is
bounded plan compilation and client composition，not a second protocol core。

## Decision

### Additive client credentials

The root `[shadowsocks]` section remains mandatory for every schema v1 client and server document。
Legacy client/server documents and tagged client outbounds without credential fields keep the exact
global method/PSK behavior。

Tagged client `[[outbounds]]` gains an optional pair of fields：

```toml
[[outbounds]]
tag = "hop-a"
server = "127.0.0.1:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
```

`method` and `psk` MUST either both be absent or both be present。When both are absent，the effective
credential is the existing global `[shadowsocks]` pair。When both are present，the same closed method、
canonical base64 and exact key-width validation applies independently to that outbound。Method without
PSK fails at `outbounds.psk`；PSK without method or an unsupported method fails at
`outbounds.method`；bad base64、canonical form or key width fails at `outbounds.psk`。Errors retain no
source value or secret。

Server outbounds remain direct and accept neither method nor PSK。M11 does not add server per-inbound or
multi-user key selection。The public `ferrum2-crypto` method-bound PSK/provider seam and the existing
SIP022 TCP/UDP state machines remain the only crypto/protocol implementations。

### Fixed tagged chains

Schema v1 gains a client-only tagged root `[[chains]]`：

```toml
schema_version = 1

[[inbounds]]
tag = "socks"
listen = "127.0.0.1:1080"
outbound = "via-a-b"

[[outbounds]]
tag = "hop-a"
server = "127.0.0.1:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[[outbounds]]
tag = "hop-b"
server = "127.0.0.1:8389"

[[chains]]
tag = "via-a-b"
hops = ["hop-a", "hop-b"]

[shadowsocks]
method = "2022-blake3-chacha20-poly1305"
psk = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
```

Chains are accepted only in a tagged client document with `[[inbounds]]` and `[[outbounds]]`。A present
collection contains `1..=64` chains；each chain has `2..=8` unique ordered hop tags。Every hop must name
a concrete client outbound exactly；an inbound、selector、chain、unknown or duplicate hop fails closed。
The two-hop minimum avoids a redundant alias for the existing direct action，and the eight-hop ceiling
bounds nested protocol owners、UDP work and total failure latency。

Inbound、concrete outbound、chain and selector tags share the existing case-sensitive global namespace
and `1..=64` ASCII grammar。New closed fields are `chains`、`chains.tag` and `chains.hops`。Collection/
shape/count failures use `chains`；invalid、duplicate、colliding or unreachable chain identities use
`chains.tag`；hop count/reference/duplicate failures use `chains.hops`。No field error displays a tag、
endpoint、method value or PSK。

Client static `inbounds[].outbound`、`route.rules[].outbound` and `route.final` may name a concrete
outbound、chain or selector。Client selector members may name concrete outbounds、chains or selectors；
their existing explicit-default、bounded DAG and atomic current-member behavior is unchanged。A chain's
hop list is immutable and cannot contain a selector，so switching a selector may choose another complete
fixed plan but can never mutate a plan in place。

Every chain and selector must be reachable from a static/route root。Every concrete outbound must be
reachable either as a direct selected action or as a hop of a reachable chain，following all selector
member edges rather than only configured defaults。Accepted inert credentials or chains remain forbidden。

### Compile one immutable egress plan

Config compiles every selectable concrete outbound as a one-hop plan and every chain as an ordered
multi-hop plan of concrete outbound identities。The existing route/selector graph chooses one terminal
plan；it does not interpret credentials or hop order。A selection call returns or indexes the whole
immutable plan before network work starts。Binaries never retain operator tags or rebuild hop lists。

Existing direct-only constructors and direct-only schema values keep their exact numeric results。
Chain-aware composition gains one path-aware selection seam；an old one-hop accessor MUST NOT be used in
the stock client in a way that silently truncates a chain。The precise private index/newtype spelling is
implementation freedom。`ValidatedClientConfig.server` remains the first server endpoint of the
configured-default plan as a legacy startup snapshot；it is not live route or chain state。

For a selector-valued action，one selection observes one complete current member and then one complete
fixed plan。Later selector switches affect only later selection calls。A failure never switches a
selector、tries a sibling、evaluates a later route rule or uses `route.final` as fallback。

### TCP hop order and ownership

For plan `[A, B, ..., N]` the client opens one raw TCP socket only to `A.server`。It creates the A
request with A's credential and target `B.server`，then sends the B request through the authenticated A
flow with target C，continuing until N's request names the application target。Each layer is the existing
SIP022 client state machine with that concrete outbound's effective method/PSK。

The connection owner retains the raw socket and every nested protocol layer as one bounded flow。No hop
gets an independent detached relay task、retry loop or alternate dial。Cancellation、timeout、write/read
failure、authentication failure and nonce exhaustion close the complete stack；all already-created inner
and outer layers are dropped and zeroized through their existing owners。Per-layer fixed buffers are
bounded by the eight-hop ceiling。

M11 does not add a successful-connect acknowledgement to SIP022。As at baseline，an intermediate dial
failure is terminal as soon as it becomes observable on the stream；the client does not infer success、
retry or reroute it。

### UDP layering, binding and bounds

For the same plan，the client encodes the innermost N request for the application target，then wraps it
from N-1 back to A；each outer request targets the next concrete server and carries the already encoded
inner packet as payload。Only the outer A packet is sent to `A.server`。Responses are authenticated and
opened A through N。Every intermediate response target must exactly equal the next configured server
before its payload is treated as the next-layer packet；the final opened target/payload becomes the SOCKS
response。

Each selected UDP plan has an isolated ordered set of SIP022 client sessions and response associations。
Plans or credentials sharing the same first-hop socket address MUST NOT accept each other's responses。
Implementation may use a bounded authenticated dispatch or lazily separated sockets，but it may not try
another outbound as a send fallback。All layers must authenticate and pass type、timestamp、session、
replay、intermediate-target and length checks before any application forwarding or accepted replay/
association mutation。A rejected inner layer must not poison an outer layer's accepted state。

Before reservation、session creation or encode mutation，the client computes the exact nested request
wire bound from the selected hop methods、fixed IPv4 intermediate targets and validated final target。
Payloads that would make any layer exceed `MAX_UDP_WIRE_LEN` are dropped with the existing bounded
failure taxonomy。Encoding/decoding may ping-pong existing fixed-capacity buffers；it must not allocate one
maximum-size packet buffer per hop or accept peer-controlled growth。

Static UDP keeps its association-setup plan snapshot。Routed UDP selects once per validated SOCKS
datagram；the resulting plan、per-hop sessions and in-flight response binding remain fixed even if a
selector later switches。All plan/session/socket state is lazy and bounded by configured action and
eight-hop ceilings，owned by the existing SOCKS association and reaped with it。

### Compatibility, observability and qualification

Complete global/outbound credential、chain、route and selector validation finishes in `load_client`
before subscriber、runtime、listener、socket、task or DNS side effects。All baseline schema v1 documents
accepted at `7a3c876681255b88492b3608af4fa52497435efc` remain accepted with the same effective behavior
when the new fields are absent。

PSKs、derived material、wire IDs、hop/chain tags and endpoints do not enter errors、panic text、traces or
metric labels。No per-hop metric family is added；existing low-cardinality client stage/reason outcomes
cover terminal failures。Different hop methods are operator configuration，not telemetry identity。

Performance is required for M11 because nested TCP/UDP processing changes transport hot paths and
per-flow/session resource ownership。It remains a reproducible regression/resource result，not a new
throughput threshold or product performance claim，and requires a separately authorized exact-SHA
`workflow_dispatch`。

## Rejected options

### Put selectors or chains inside `chains[].hops`

That makes one flow's hop list mutable or recursively composable and introduces cycle/snapshot policy。
Selecting among complete immutable plans already covers the requested control point with one graph。

### Retry the failed hop or fall back to another member

Retry changes side-effect ordering、replay/session ownership and traffic destination。M11 is fixed
chaining only；health、failover and load balancing require a later upstream-policy contract。

### Give each hop a new protocol implementation or relay task

It duplicates SIP022 state machines or multiplies cancellation owners。The existing protocol owners can
be nested by one narrow composition seam and remain under the connection/association owner。

### Add server per-inbound credentials

That is multi-user/server identity selection and is explicitly outside M11。Servers continue to use the
single global method/PSK for every inbound。

## Consequences and rollback

- Positive：route and selector still choose one thing；the thing is now an immutable one-or-many-hop plan。
- Positive：credentials stay bound to concrete outbounds and reuse the existing move-only secret owner。
- Negative：TCP buffer/crypto state grows linearly with hop count；UDP nested overhead reduces maximum
  application payload and requires path-bound response state。
- Negative：the eight-hop ceiling is an operator-visible limit；raise it only with new footprint/resource
  evidence and review。

Rollback removes `[[chains]]` and outbound credential parsing plus client layering，restoring every
direct plan。It must reject chain/partial-credential documents rather than accept them inertly。No push、
release or publication is authorized by this decision。
