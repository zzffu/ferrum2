# ADR-0029 — M10 manual outbound selector

- **Status:** Accepted
- **Date:** 2026-08-04
- **Related:** `SPEC-0011`、`TEST-0011`、M10-T01～T03；extends ADR-0027/0028

## Context

M7/M8 already compile static inbound bindings and first-match routes into one runtime-neutral
`RouteTable`，but every action names a concrete outbound forever。M10 needs a logical outbound whose
operator-selected member can change without rebuilding config or interrupting work that already
captured a concrete egress identity。

The sing-box selector concept uses a typed outbound with a required member list，a default member and
an optional connection-interruption policy。Ferrum2 only adopts the manual fixed-member concept；its
preserved schema v1 already has two incompatible role-specific concrete outbound shapes，and M10 has
no external controller or interruption behavior。Reference：
<https://sing-box.sagernet.org/configuration/outbound/selector/>。

## Decision

### Additive tagged-only selector graph

Schema v1 gains an optional root `[[selectors]]` array for tagged documents：

```toml
schema_version = 1

[[inbounds]]
tag = "socks-a"
listen = "127.0.0.1:1080"
outbound = "manual"

[[outbounds]]
tag = "ss-a"
server = "127.0.0.1:8388"

[[outbounds]]
tag = "ss-b"
server = "127.0.0.1:8389"

[[selectors]]
tag = "manual"
outbounds = ["ss-a", "ss-b"]
default = "ss-a"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
```

Selectors are allowed only when tagged `[[inbounds]]` and concrete `[[outbounds]]` are both present。
Legacy `[client]`/`[server]` mixed with `[[selectors]]` is rejected。Omitting `selectors` preserves
every legacy/M7/M8 normalized value and concrete numeric identity。

Inbound、concrete outbound and selector tags share the existing process-local case-sensitive global
namespace and `1..=64` ASCII grammar。A present selector collection contains `1..=64` entries；each
selector contains `1..=64` unique immediate member tags and one mandatory `default` that must be an
immediate member。The mandatory default deliberately avoids an order-dependent implicit choice。

Members may name concrete outbounds or selectors。Every reference resolves before a validated config
is returned；all selector edges，not only current/default edges，form one bounded directed acyclic graph。
Self、two-node and longer cycles fail closed even when the cycle is not initially selected。

Static `inbounds[].outbound`、`route.rules[].outbound` and `route.final` resolve against the union of
concrete outbound and selector tags。Every configured concrete outbound and selector must be reachable
from at least one static binding or route action，following every selector member edge；accepted inert
graphs remain forbidden。

New closed non-value config fields are `selectors`、`selectors.tag`、`selectors.outbounds` and
`selectors.default`。Collection/mixing/count uses `selectors`；tag collision/unreachable selector uses
`selectors.tag`；empty/duplicate/unknown/cyclic member data uses `selectors.outbounds`；missing、unknown
or non-member default uses `selectors.default`。Existing dangling action errors keep their existing
binding/route field。No index、tag or source value appears in Display/Debug。

### One deep runtime-neutral module

`ferrum2-core` owns one concrete selector module adjacent to `route`。It stores the immutable resolved
graph and one atomic current-member slot per selector；there is no trait、adapter、Tokio primitive、new
crate or dependency。Config constructs it only after validating the complete graph，and `RouteTable`
shares the same process-local state。

Existing public `RouteRule::new`、`RouteTable::static_bindings` and `RouteTable::routed` remain
concrete-only constructors with their current `usize` meaning and selector-free numeric results。One new
public selector-aware compile entry accepts tagged concrete identities、selector definitions and tagged
static/routed actions instead of undifferentiated logical indexes。It validates every member、default and
action before returning a `RouteTable` and control handle that share one state；failure returns neither。
Logical selector identities remain private and can never cross `select` as a concrete outbound index。
The external core integration test constructs selector state only through this entry point。

The control interface is one cloneable `Send + Sync` handle with behavior equivalent to：

```rust
control.selected(selector_tag) -> Result<&str, SelectorError>
control.switch(selector_tag, member_tag) -> Result<(), SelectorError>
```

`selected` returns the immediate current member tag，not a recursively resolved concrete leaf。
`switch` accepts only an immediate configured member；selecting the already-current member succeeds as
a no-op。Unknown/concrete-as-selector tags return `UnknownSelector`；unknown、case-mismatched、non-member
or descendant-only tags return `UnknownMember`。Errors are closed/value-free and failed operations do
not modify any selector。Both validated config roles expose an additive accessor that clones this public
handle from the route-owned state；no new public config field duplicates the state。

Each query/switch is linearizable。A racing query observes a complete old or new member；a successful
switch is visible to later synchronized queries。Concurrent valid switches are last-writer-wins。
There is no compare-and-swap、revision、watcher or multi-selector transaction。Nested resolution loads
each visited selector once；M10 does not claim a graph-wide atomic snapshot across concurrent switches。

The fixed ceiling permits bounded linear tag/member lookup and at most 64 selector hops。An index、map、
CAS generation or lock is justified only by a later larger bound or measured control-path cost。

### Selection and snapshot behavior

`RouteTable::select` keeps its total interface：one static/routed selection returns one concrete outbound
index。It resolves a selector chain internally after the existing route action is chosen；binaries do not
look up tags or interpret selector graph nodes。Selected member failure never changes current state and
never tries a sibling、later rule or final。

Existing `is_routed()` and concrete-only construction behavior remain exact。`final_outbound()` remains
the concrete configured-default no-match leaf captured during compilation，including when `route.final`
names a selector；it never exposes a logical selector index and does not change after a switch。The public
`ValidatedClientConfig.server` field remains that same configured-default compatibility snapshot。It is
not live routing state，and composition MUST use `RouteTable::select` for every runtime choice。

M10 preserves the existing call-site granularity instead of defining a second notion of UDP flow：

- client TCP resolves after valid SOCKS target and before Shadowsocks connect/write；
- client static UDP resolves at association setup，as it does today；
- client routed UDP resolves each validated datagram before outbound-specific leg/state/send mutation；
- server TCP resolves after authenticated acceptance and before direct connect/prefix forwarding；
- server UDP resolves each authenticated bounded pending request before reserve/commit/send mutation。

Once a call returns a concrete index，the caller's copied endpoint、socket、protocol leg、direct handle
or in-flight response keeps that identity。A later switch affects only a later call to the same existing
selection interface。No connection/session is cancelled or migrated。

Both roles support selectors so the schema and route interface remain total。Server members are still
only concrete direct identities；M10 does not introduce another server adapter or pretend that switching
equivalent direct adapters is load balancing。

### Preserved safety and operator behavior

Selector construction and control perform no I/O、DNS、task creation or peer-sized allocation。All
existing method/PSK、authentication、replay、source/inbound binding、aggregate admission/session/byte/
ID limits、process transaction and shutdown/reap semantics remain exact。

Selector/member tags are intentionally visible only through the public Rust control interface。They do
not enter config errors、panic text、trace fields or metric labels；no selector telemetry is added。
Restart reconstructs configured defaults。Current state is not serialized or persisted。

## Rejected options

### Polymorphic `[[outbounds]]` with `type = "selector"`

This more closely copies sing-box but forces both existing role-specific concrete outbound parsers into
one polymorphic shape。A separate additive array preserves the accepted schema and yields the same
logical outbound namespace with less parser and compatibility surface。

### One selector implementation in each binary or protocol module

It would duplicate graph validation、atomic semantics and nested resolution，and would place routing
policy beside concrete protocols。One core module gives locality and one public integration-test seam。

### Snapshot or interrupt every active UDP/TCP owner on switch

This adds owner enumeration、cancellation and migration policy not requested by M10。Existing callers
already have explicit safe selection points；work past that point remains untouched。

### Automatic fallback、health choice or retry

Those policies create side effects and failure-order questions beyond manual selection。They remain a
future upstream-group milestone，not behavior hidden inside selector resolution。

## Consequences and rollback

- Positive：one small control interface hides validation、nesting、atomic state and concrete resolution
  from all callers，while existing data-plane selection interfaces remain unchanged。
- Positive：no-selector configs and all wire/protocol/runtime owners remain exact。
- Negative：only Rust callers inside the process can control selectors；stock binaries expose no remote
  management entry。
- Negative：nested concurrent switches are atomic per selector，not one transaction across the graph。

Rollback removes `[[selectors]]` parsing and the core selector state，restoring concrete-only route
actions。It must reject selector documents rather than accept inert state。No push、release or publication
is part of this decision。
