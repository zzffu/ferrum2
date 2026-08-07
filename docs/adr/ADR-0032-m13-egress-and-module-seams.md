# ADR-0032 — M13 owned egress plans and composition-owned execution seams

- **Status:** Accepted
- **Date:** 2026-08-07
- **Related:** `SPEC-0014`、`TEST-0014`、M13-T01～T07；preserves ADR-0024、ADR-0028、
  ADR-0029、ADR-0030 and ADR-0031

## Context

M12 leaves one concrete egress plan represented twice：core exposes borrowed `EgressPlan<'_>` while
DNS copies its hops into public `ferrum2_dns::PlanSnapshot` and the client DNS adapter copies them again
before TCP/UDP execution。The adapter also imports `ClientContext`、`ClientRouting`、
`PreparedClientUdp` and private chain/UDP helpers from the client composition root。Consequently DNS
runtime knows the operator-facing `DnsServerConfig`，and `run.rs` owns policy selection、egress
execution、protocol state and process composition at once。

The existing seams already cover the required behavior：core owns route/selector selection，Hickory is
behind `DnsEgress` with direct/client/test adapters，the client already has one TCP chain and one bounded
UDP implementation，and `ProcessRoot`/`ProcessSupervisor` own lifecycle。M13 therefore needs to move
ownership and remove duplicate representations，not add another protocol、registry or workspace crate。

## Decision

### Core owns the only egress-plan snapshot

`ferrum2-core::route` owns `EgressPlanSnapshot`，an owned cloneable、equatable、hashable immutable
snapshot backed by the graph's existing hop allocation。Selection clones shared ownership and never
copies the hop slice。Its `Debug` output is fixed and redacted。

`EgressPlanHandle::snapshot_owned`、`RouteTable::select_plan_snapshot` and
`RouteTable::final_plan_snapshot` are the product data-plane interface。The existing borrowed
`snapshot`、`select_plan` and `final_plan` remain compatible views；M13 does not remove them。A direct
plan remains one hop，a chain remains `2..=8` ordered concrete hops，and a selected snapshot is unchanged
by later selector switches。

`ferrum2_dns::PlanSnapshot` is deleted。`DnsEgress` receives an optional core
`EgressPlanSnapshot`，so TCP execution、UDP exact-plan reuse and DNS TC upgrade share one identity。

### DNS owns a runtime model，not config DTOs

`ferrum2-dns` owns a small `DnsUpstreamSpec` and closed transport spelling containing only validated
runtime values：numeric address、TLS name/path where applicable and optional `EgressPlanHandle` detour。
`TaggedResolver::{direct,new}` consume these specs and no longer mention `ferrum2-config`。

Client and server composition each perform one pure conversion from already validated
`DnsServerConfig` values before any bind、root creation、socket or task。The conversion does not parse
tags、files or source text。The normal workspace-internal dependency is one-way：

```text
ferrum2-config -> ferrum2-core
ferrum2-dns    -> ferrum2-core
binaries       -> ferrum2-config + ferrum2-dns
```

Neither `ferrum2-config -> ferrum2-dns` nor `ferrum2-dns -> ferrum2-config` is allowed。

### The client binary owns one concrete egress module

The client binary gains one private concrete `ClientEgressEngine` module。It executes a caller-selected
`EgressPlanSnapshot` for TCP or creates one bounded UDP association；it never owns `RouteTable`，reads a
selector，selects policy or depends on `Socks5Inbound`。SOCKS CONNECT、SOCKS UDP and the DNS detour
adapter consume this same module。

The module is concrete because only one product implementation exists。M13 adds no public trait、
factory、plugin/Endpoint registry or workspace crate。The existing `DnsEgress` seam remains because it
already has direct、client and test adapters and lets Hickory retain DNS/TLS/HTTP ownership。

DNS UDP idle reuse is keyed by the numeric first-hop server plus `EgressPlanSnapshot`。Only an exact key
may reuse an association；I/O、authentication、cancellation or partial-state failure discards it。The
existing `UdpSessionManager` remains the capacity/session owner。

### Split by ownership after semantic migration

The client TCP and UDP egress modules are extracted while their consumers migrate，then the remaining
client/server/core/config source is split by ownership。Core/config public paths and all DNS paths except
the explicitly removed `PlanSnapshot` and replaced resolver constructor inputs remain unchanged，as do
schema v1、CLI/error text、SIP022 state machines and process-root semantics。Tests move with their true
module and continue through agreed interfaces；M13 adds no second helper implementation、real-process
harness、DNS codec or SIP022 data plane。

## Consequences

- Route/DNS policy returns one stable identity and egress execution consumes it without copying or
  re-entering policy。
- DNS runtime becomes independent of TOML/config DTO evolution；the two composition roots pay a small
  explicit conversion cost。
- TCP chain and bounded UDP behavior gain locality behind one private client interface while external
  product behavior remains M12-exact。
- The migration touches transport hot paths and lifecycle ownership，so exact-SHA performance/resource
  regression evidence is required even though M13 makes no throughput claim。

## Rejected alternatives

- **Keep both plan snapshot types:** rejected because identity、copying and UDP reuse semantics would
  remain split。
- **Make config depend on DNS:** rejected because operator DTO ownership would still cross into runtime
  and create a reverse layer edge。
- **Add a shared egress crate or public Endpoint interface:** rejected because there is one concrete
  client implementation and no second product adapter requiring that seam。
- **Only split large files:** rejected because moving text without first converging plan identity and
  egress ownership preserves the same shallow interfaces under more module names。
