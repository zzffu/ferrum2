# SPEC-0008 — M7 tagged multi-inbound/outbound static composition

- **Status:** Approved
- **Milestone:** M7
- **Baseline:** `302fd777f4da62a8c1d4d52d81502056f02089c8`
- **Decision:** `docs/adr/ADR-0027-m7-tagged-static-composition.md`
- **Test plan:** `docs/test-plans/TEST-0008-m7-tagged-static-composition.md`

## Scope

Additive schema v1 tagged documents configure multiple concrete inbounds/outbounds in each
existing binary。Every inbound resolves one outbound before runtime side effects；all required
listeners/resources enter the existing atomic process transaction。Legacy single-instance
documents remain valid and behavior-identical。

## Current baseline

- `crates/ferrum2-config/src/lib.rs::{load_client,load_server,validate_client,validate_server}`
  currently returns one listen/upstream and validates it before `run::run`。
- `bins/ferrum2-client/src/run.rs::run_with_registry_and_metrics` builds one SOCKS5 TCP root；
  client UDP associations are lexical children of that root。
- `bins/ferrum2-server/src/run.rs::run_with_registry` builds one Shadowsocks TCP root、one
  optional same-address UDP root and one optional metrics root。
- `crates/ferrum2-runtime/src/process.rs::ProcessSupervisor::run_until` already prepares every
  `ProcessRoot` before activation and reverses prepared ownership on failure。
- `BoundedSupervisor` currently creates one private TCP semaphore per listener；M7 must retain
  the existing process-wide meaning of `runtime.max_connections` across multiple listeners。

## Requirements

### M7-MUST-01 — legacy schema v1 compatibility

- Every client/server document accepted at baseline MUST remain accepted without edits and MUST
  retain exact normalized values、defaults、TCP/UDP enablement、CLI/check behavior and resource
  choices。
- Legacy `[client]`/`[server]` MUST normalize to exactly one concrete inbound/outbound；synthetic
  identities MUST NOT appear in diagnostics、traces or metrics。
- Tagged arrays and legacy role tables MUST be mutually exclusive。Unknown fields remain
  fail-closed；breaking reinterpretation or heuristic parser fallback is forbidden。

### M7-MUST-02 — bounded unique tags and complete references

- Tagged mode MUST contain `1..=64` inbounds and `1..=64` outbounds。Every tag MUST be
  `1..=64` ASCII bytes from `[A-Za-z0-9._-]` and globally unique across both arrays。
- Every inbound MUST exact-resolve one outbound before `load_client`/`load_server` returns；every
  outbound MUST be referenced。Empty/missing/mixed collections、duplicates、dangling or
  wrong-namespace references and unreferenced outbounds MUST fail as redacted
  `config.semantic` without echoing any tag、endpoint、PSK or source text。
- Graph errors MUST use only the approved non-value fields `inbounds`、`outbounds`、
  `inbounds.tag`、`inbounds.listen`、`inbounds.outbound`、`outbounds.tag` and
  `outbounds.server`；field text MUST contain no index or configured value。
- Inbound listens MUST be unique；metrics MUST differ from every inbound listen；client outbound
  servers MUST differ from every local inbound listen。All validation MUST complete before
  subscriber、runtime、socket、table、channel、buffer or task creation。

### M7-MUST-03 — concrete static adapter semantics

- Client tagged inbounds MUST remain SOCKS5 TCP CONNECT plus existing opt-in UDP ASSOCIATE；client
  outbounds MUST remain Shadowsocks server addresses。Server tagged inbounds MUST remain
  Shadowsocks TCP/UDP；server outbounds MUST remain direct。
- One inbound MAY share an outbound with other inbounds。Each accepted flow/association MUST use
  only its inbound's prevalidated outbound；failure MUST NOT select another configured outbound。
- Tagged mode MUST NOT add route rules、selectors、fallback、round robin、health checks、load
  balancing、chaining or outbound preconnect。
- Product code MUST reuse concrete binary adapters and existing protocol interfaces。It MUST NOT
  introduce an `Endpoint` interface、generic service graph、adapter factory/registry or new
  dependency。

### M7-MUST-04 — shared security and resource ownership

- One validated method/PSK MUST remain process-wide。Server TCP replay capacity/state MUST be
  shared across every inbound；a replay accepted on one listener MUST be rejected on another
  before target connection or forwarding。
- `runtime.max_connections` MUST cap aggregate live TCP admissions across all inbounds；
  `listen_backlog` remains per listener。Existing absolute handshake/connect/idle/shutdown
  deadlines MUST not reset at tag lookup or listener transitions。
- Client UDP session-ID collision ownership and both roles' UDP session/allocated-byte limits
  MUST be aggregate process owners, not multiplied by inbound count。Existing queue、idle、nonce、
  replay、binding and reservation-before-commit rules remain exact。
- A server UDP session MUST bind its local inbound on first accepted request。The same session on
  another local inbound MUST fail before replay/activity/peer/queue/target mutation；responses
  MUST egress the bound inbound。Validated peer roaming within that inbound remains unchanged。

### M7-MUST-05 — atomic prepare, rollback and lifecycle

- Every configured client/server TCP listener、enabled server UDP listener、optional metrics
  listener and fallible activation prerequisite MUST participate in one existing
  `ProcessSupervisor` transaction。
- No public service loop may be polled until all required roots prepare。Failure at every
  first/middle/last TCP、UDP、metrics or activation position MUST reverse-release all acquired
  resources and allow immediate exact-address rebind。
- A terminal required root MUST retain deterministic first cause、cancel every sibling、respect
  the one process grace/forced-reap contract and return all process/root/child/socket/session/
  buffer owners to baseline。Affected-flow failures remain isolated。

### M7-MUST-06 — preserved wire and operator behavior

- Existing three-method TCP/UDP wire、authentication、replay、nonce、request/response binding、
  SOCKS reply/control and direct-target behavior MUST remain unchanged for legacy and tagged
  configurations。
- Existing CLI flags、0/1/2 exits、four config codes、eight run codes、trace keys and fourteen
  metric family identities MUST remain unchanged。Tags MUST NOT become metric labels or
  free-form trace/error fields；metrics continue to expose process aggregates。
- Disabled/check paths MUST own zero proxy/UDP/metrics runtime resources beyond the behavior
  already explicitly enabled by the validated document。

### M7-MUST-07 — local multi-instance acceptance

- A real-process table MUST start at least two client inbounds and two server inbounds, exercise
  both static mappings for TCP and UDP under all three methods without a full tag cross product,
  and prove one inbound sharing one outbound。
- Focused rows MUST prove no fallback when the referenced outbound is unavailable、aggregate TCP
  admission across listeners、cross-listener TCP replay rejection、server UDP inbound binding、
  startup partial-bind rollback、root fatal、signal shutdown and restart/rebind。
- Existing legacy local TCP、server UDP、SOCKS UDP and at-least-100-cycle lifecycle suites MUST
  remain regression gates。

### M7-MUST-08 — exact-SHA qualification

- One accepted integration SHA MUST pass repository Full、Rust 1.85、three native targets、
  existing external TCP `12/12`+cleanup、UDP `12/12`+cleanup、test budget and blocking
  Architect/QA review。
- Native target evidence MUST include tagged offline validation and bounded multi-listener
  startup/rollback/rebind without adding a provider or workflow job。
- Missing、failed、skipped、unavailable、wrong-SHA or unauthorized required evidence MUST block
  M7 close and MUST NOT be spliced with M6 results。

## Non-goals

- Dynamic TCP/UDP routing、DNS、multiple-upstream groups、load balancing、fallback、health
  checking or proxy chaining。
- Per-entry method/PSK、SIP023、多用户/multi-PSK on one inbound or key-selection changes。
- New inbound/outbound kinds、combined `Endpoint` interface、Tailscale、transparent/TUN or
  shared public UDP listener。
- Hot reload、management API、tag-bearing metrics、new dependency、performance threshold、
  package、release or publication。

## Implementation freedom

- Config may retain validated tags or replace references with typed indexes；binary composition
  may use maps、vectors or direct captured contexts。No caller may revalidate raw strings。
- Shared TCP/UDP capacity may use concrete cloneable runtime owner values or an equally small
  implementation。No public trait is required。
- Server UDP may use one aggregate root or multiple prepared roots if shared protocol/budget and
  inbound-binding outcomes remain exact。Tests target the existing process/config interfaces，not
  private helper layout。
