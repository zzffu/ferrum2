# M13 — behavior-preserving architecture consolidation

- **Status:** executing
- **Qualified product baseline:** `c06386e9344c07d86ea4a3b63dc73f37f20ceb0e`
- **Planning baseline:** `4810ec5c5a1063cb8e60d1b950900c7f38d74548`
- **Planning tree / parent:** `d732eccc2b5b38c91dcccb83d77eba9bfa6ac372` /
  `0b854e7ae2054f4f91b76a7dc705cc20762d9e92`
- **Strategy:** drain；all tickets integrate serially
- **Owner:** primary thread
- **Performance:** required — the migration changes transport-hot-path and resource/lifecycle ownership
  even though behavior and performance claims remain unchanged

## Outcome

Consolidate the M12 implementation without adding product behavior：core provides the only owned egress
plan snapshot；DNS runtime depends on its own model rather than config DTOs；SOCKS TCP、SOCKS UDP and DNS
detours share one private concrete client egress module；client/server/core/config source is then split
by ownership so composition roots no longer contain protocol execution。Schema v1、CLI、SIP022 wire、
DNS/routing/selector/chain semantics、resource ceilings、telemetry and process lifecycle remain exact。

Planning input was `ferrum2-M13-only-architecture-plan.md`。Every source claim was rechecked against the
real repository；the external archive timestamp is not used as Git identity。

## Baseline evidence

- At planning capture，`master` was clean at planning baseline `4810ec5c…`；M12 closeout and two agent-config commits
  are descendants of qualified product `c06386e9…` and do not change Rust product/test sources。
- `ferrum2-dns` directly imports `DnsServerConfig`/`DnsTransport` in `resolver.rs` and
  `runtime_owner.rs`，and its normal manifest edge includes `ferrum2-config`。
- Core stores `Arc<Vec<Box<[usize]>>>` and exposes borrowed `EgressPlan<'_>`；DNS separately exports
  `PlanSnapshot(Arc<[usize]>)`，while client DNS TCP/UDP copies `plan.hops().to_vec()`。
- `bins/ferrum2-client/src/dns_egress.rs` imports `ClientContext`、`ClientRouting`、
  `PreparedClientUdp` and seven TCP/UDP implementation helpers from `run.rs`。
- Source sizes are client `run.rs` 8,829 lines、server `run.rs` 3,777、config `lib.rs` 2,137 and core
  `lib.rs` 1,465。Existing client `run.rs` contains 8,356 semantic test LOC。
- Exact planning footprint is code/tests `18940/39748`、ratio `2.098627` and
  case/support/fixture `33999/5152/597`；largest test file is client `run.rs`。

## Non-goals

- New route/DNS matchers、actions、retry/fallback、server groups、health、load balancing or failover。
- DNS cache、DNSSEC、DoQ/DoH3、hostname bootstrap、custom trust、transparent/TUN or Fake-IP behavior。
- Global typed-ID migration、dynamic graph rebuild、plugin/Endpoint registry、new crate、dependency、
  protocol implementation、harness or fixture。
- Crypto/SIP022 wire or state-machine rewrite，hot reload，management interface，package，release or
  publication。

## Exit criteria

- [ ] Qualified M12 behavior and planning baseline identities remain recorded and reproducible。
- [ ] Core owns one allocation-preserving、redacted `EgressPlanSnapshot`；borrowed APIs remain compatible
      and every product route/DNS-detour call site uses the owned snapshot。
- [ ] `ferrum2_dns::PlanSnapshot` is removed；DNS has no normal dependency on config or binaries，and
      config has no DNS dependency。
- [ ] Client/server composition converts validated config to DNS runtime specs before side effects。
- [ ] SOCKS TCP and DNS TCP detours share one chain executor；SOCKS UDP and DNS UDP detours share one
      bounded association implementation。
- [ ] Exact-plan DNS UDP reuse、TC same-plan upgrade、failure discard and selector snapshot behavior are
      unchanged and bounded by existing owners。
- [ ] Client DNS adapter knows only the existing DNS egress seam plus the private client egress module；
      it does not import SOCKS/process context or TCP/UDP implementation helpers。
- [ ] Client/server `run.rs` contain root composition only；core/config public paths and all M12
      configuration/error/behavior contracts remain exact。
- [ ] Task/session/queue/buffer/replay/admission ceilings、graceful/forced shutdown、zero owners、exact
      rebind and low-cardinality redacted telemetry remain exact。
- [ ] No new workspace crate、third-party dependency、unsafe、fixture、harness or data plane is added。
- [ ] One exact integration SHA passes focused、Full、Rust 1.88、100+ lifecycle、three-platform、SIP022
      and DNS interop、footprint、Architect/QA and authorized performance/resource gates with zero
      blocking findings。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M13-T01 | Freeze exact M12 behavior、M13 contracts and migration guards | M12 closed | done |
| M13-T02 | Add the core owned egress-plan snapshot without breaking borrowed views | M13-T01 | ready |
| M13-T03 | Invert DNS config dependency and converge on the core snapshot | M13-T02 | todo |
| M13-T04 | Extract one client TCP egress interface for SOCKS and DNS | M13-T03 | todo |
| M13-T05 | Extract one bounded client UDP association and exact-plan reuse key | M13-T04 | todo |
| M13-T06 | Split client/server/core/config modules by ownership and enforce architecture | M13-T05 | todo |
| M13-T07 | Qualify one exact M13 integration SHA | M13-T06 | todo |

```text
M13-T01 contract/control
  -> M13-T02 owned plan identity
  -> M13-T03 DNS runtime inversion
  -> M13-T04 TCP egress vertical slice
  -> M13-T05 UDP egress vertical slice
  -> M13-T06 mechanical ownership split
  -> M13-T07 exact-SHA qualification
```

The graph must drain serially。T04/T05 share client composition and owner lifetimes；T06 moves the code
only after both semantic interfaces are green。Overlapping owned paths are therefore serialized rather
than concurrently leased。

## Test-footprint and remote boundary

Schema 3 resets at the planning baseline above。`TEST-0014` forecasts case/support/fixture growth
`550/0/0`：existing M10～M12 behavior evidence moves with its owner，while only owned-snapshot、runtime
conversion and architecture mutation guards are added。Net growth forecasts `WARN`，but new owner files
may trigger file-size `REVIEW_REQUIRED` when moved tests are compared with zero；both are numeric signals，
not correctness results，and are dispositioned without deleting independent evidence。No third helper、
fixture or second harness is planned。

The M13 execute request authorizes all required non-force pushes；the workflow will still push only an
accepted exact SHA/range。Manual performance/resource dispatch remains separately unauthorized。No
force-push、PR、tag、package、release or publication is authorized。

## Blocker / next action

No blocker。T01 is accepted at `d7cce680…` after one bounded repair and targeted Architect/QA PASS。
Record this state，then create `codex/m13-t02` in `.worktrees/m13-t02` from the resulting exact state
commit and bind that exact T02 base。
