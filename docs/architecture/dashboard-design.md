# Embedded client dashboard

## Decision and product contract

The selected frontend is Bun + React + TypeScript + Vite + React Router in declarative HashRouter mode. Production emits exactly one self-contained `index.html`. The Rust client embeds that document and serves it on an authenticated loopback management endpoint. There is no Node/Bun runtime, companion daemon, second proxy process, SSR, Clash compatibility layer, CDN, service worker, or downloaded executable at runtime.

The dashboard has seven pages: overview, connections, outbounds, routing/RuleSets, DNS, logs/diagnostics, and configuration/settings. It controls the existing Ferrum2 runtime, not an independent approximation of its routing or DNS behavior. Reference projects are MetaCubeXD and Zashboard; their deployment and Clash protocol assumptions are not imported.

This document records the implemented ownership and browser contract. Execution evidence below distinguishes tested behavior from unqualified privileged or cross-platform paths.

## Existing constraints

- Without management flags, `main.rs` prepares configuration and invokes `run::run_prepared`; its command-line behavior remains unchanged.
- `run/generation.rs` owns reusable async proxy generations. Management installs one process-wide subscriber with a dynamic, validated severity source; proxy restarts update the filter rather than attempting to reinstall a global subscriber. `run/error.rs` owns closed runtime error classification.
- `ProcessSupervisor` already owns startup rollback, grace cancellation, root joins and cleanup. It remains authoritative; the dashboard must never cancel its future and abandon cleanup.
- Plain `--check-config` remains offline; even materialized validation must not start a dashboard or TUN.
- Ordinary SOCKS TCP metrics still settle at relay completion. Dashboard counters independently observe successful payload writes during the live relay; failed/pending writes do not inflate them.
- Selectors, route programs, DNS resolvers/cache and RuleSet refresh have existing owners. Management receives generation-bound handles, never creates a competing runtime.
- Ordinary diagnostics exclude addresses, domains, tags, paths and secrets. A separately enabled authenticated local detail channel may expose connection metadata; it must not change ordinary telemetry policy.
- TUN host-network operations retain their existing platform and privilege restrictions. No ordinary test creates an adapter or changes DNS/routes/firewall state.

## Module ownership and seams

### Client management module

`bins/ferrum2-client/src/dashboard/` owns loopback HTTP, authentication, bounded requests, source configuration access, control serialization, runtime-generation lifecycle and static response security headers. It is client-specific: it knows the selected configuration path and invokes client composition.

Its external interface is a single managed run operation. Internal seams separate HTTP request handling from generation commands and configuration transactions. HTTP is an adapter; it cannot mutate network resources directly.

### Dashboard observation module

`crates/ferrum2-dashboard/` owns bounded connection observations, cumulative live counters, cancellation handles, closed history, log retention and serializable snapshots. It has no dependencies on client composition, route execution or DNS transport.

A cloneable `Dashboard` handle is optional at client execution seams. A connection observation lease follows the real TCP flow or UDP association lifetime. Byte updates use atomics; no HTTP, formatting, JSON serialization, file I/O or per-packet global table locking is permitted on the forwarding path. A counted I/O adapter must preserve read/write, flush and half-close behavior.

Cancellation requests signal a connection owner. They do not drop arbitrary OS resources from the HTTP task. Retiring a connection records the actual terminal state; a cancellation request is not proof that cleanup completed.

Connection facts are captured at admission and existing route-decision transitions, not emitted as per-packet events. Original endpoints remain typed in the observation store; concrete hop IDs and compact sniff outcomes replace formatted rule/path strings. Rules and outbound names belong to immutable admission catalogs. Registry locks cover bounded membership capture and retirement; row projection, rate sampling and serialization run after releasing those locks. Retirement seals structured final counters/timing, not JSON. The single sampler publishes cached encoded bytes through `Dashboard::encode_snapshot`; additional HTTP readers do not trigger additional registry walks.

### Client domain-control module

`bins/ferrum2-client/src/run/dashboard_control/` owns the adapter from authenticated operations to the current route/selector, egress, DNS cache/proxy and RuleSet handles. It exposes snapshots and bounded commands to management, with no HTTP dependency.

It reuses route-once and generation semantics. Outbound probes use the actual egress engine. DNS queries use the configured DNS policy. Route trial evaluates the real rule program with explicit input; missing metadata is reported and no network lookup occurs implicitly.

Dashboard and Prometheus responses share a registry-aware metrics projection. UDP gauges
are sampled from the current owner registry for each response, without changing shared
gauges or depending on a previous Prometheus scrape.

### Frontend module

`ui/dashboard/` owns the React application and single-file build. Route-local state stays local. An external subscription store publishes stable immutable snapshot identities through `useSyncExternalStore`; network updates do not cause unrestricted per-event page renders. Native fetch serves the small same-origin protocol. Additional state/cache libraries must earn their dependency through actual behavior, rather than being installed preemptively.

## Lifecycle

The management listener outlives a proxy generation, not the client process. One process-level Tokio runtime and tracing subscriber own:

1. Loopback listener and bounded request tasks.
2. The serialized generation controller.
3. At most one proxy generation.
4. One bounded observation/sampling owner.

Generation states are `stopped`, `starting`, `running`, `stopping`, and `failed`. A generation is `running` only after required runtime roots activate; configuration parsing or resource materialization alone is insufficient.

Start/restart/stop are serialized. Stop sends cooperative shutdown and awaits the existing supervisor and materialization owners. Restart starts a new generation only after the old generation reports cleanup complete. Cleanup failure is terminal for automatic replacement and visible in the dashboard. Old control handles are invalidated; stale commands receive conflict rather than affecting a new generation.

Ctrl+C/Ctrl+Break on Windows, and SIGINT/SIGTERM on Unix, close management admission, cancel bounded diagnostic work, request proxy shutdown and join all managed tasks. Management failure also triggers owned shutdown. Browser disconnect does not affect proxy lifetime. No spawned task is detached.

Management is explicit opt-in through CLI options: `--dashboard-listen` (loopback socket), `--dashboard-token-file` (required private token file), and `--dashboard-details` (optional sensitive connection metadata). These cannot be combined with offline validation flags. They do not alter the schema-v2 network configuration.

## HTTP and authentication

- Serve only the exact configured loopback authority. Reject unexpected Host, foreign Origin and cross-site fetches for private APIs. Public HTML permits cross-site navigation because it contains no state or credential and is protected against framing. Host validation protects against DNS rebinding; loopback binding alone is insufficient.
- HTML contains no authentication secret. Users enter the token once per browser tab; store it in memory, not URL or persistent browser storage. API calls use an Authorization Bearer header. Use constant-time comparison against a bounded token loaded from the configured file. No wildcard CORS.
- Validate the opened token file, not just its contents. It must be a regular file containing 32–256 ASCII graphic characters (optional trailing CR/LF). Unix requires the current owner and no group/other permissions. Windows requires a trusted owner and grants restricted to the current user, owner, SYSTEM and administrators; unfamiliar granting ACEs fail closed.
- Reject unauthenticated reads as well as writes. Static HTML is public but has no private state.
- JSON commands use POST, exact JSON content type and bounded bodies. GET never mutates state. Hyper permits at most 32 clients and 32 headers; headers/bodies have five-second deadlines. The command queue holds 16 entries and expires unstarted work after 30 seconds. Domain operations have a 15-second deadline. HTTP/control waits allow 360 seconds to accommodate the existing configurable shutdown grace (up to 300 seconds); a browser timeout never abandons proxy cleanup.
- Use vetted HTTP parsing rather than a new ad-hoc parser. Errors expose closed codes, not OS errors, config values or secrets. Offline CLI validation retains its more detailed redacted configuration field diagnostics.
- Set no-store on private responses; no-referrer and nosniff; deny framing. Build-generated CSP script/style hashes authorize bundled inline resources without allowing arbitrary inline scripts.
- Assets never contain a token. Downloads use controlled response names, not user-provided filesystem paths.

## Browser protocol

Connection snapshot protocol version is 2. Rust connection/catalog declarations in `wire.rs` also generate the browser types; the old per-row `route`/`outbound` string fields are removed, not retained as aliases. Same-origin endpoints are:

- `GET /`: the embedded single HTML.
- `GET /api/snapshot`: a bounded snapshot of current generation, process/traffic, connections/history, immutable `connection_catalogs`, domain state and recent redacted logs. A row's `catalog_id` resolves only against its captured catalog; shared rule conditions and outbound names are serialized once per referenced catalog, not once per connection.
- `POST /api/command`: `{generation: string, command: {action: ..., ...}}`. `CommandRequest`, `Command`, and `CommandResult` in `crates/ferrum2-dashboard/src/wire.rs` own the closed contract. Successful responses are `{result: {kind: ..., ...}}`; failures are `{error: {code: ...}}` with an appropriate HTTP status. Unknown fields/actions and invalid typed values are rejected. The old flat command envelope is not accepted.
- `GET /api/config`: current bounded source text, available only after explicit sensitive editor action and authentication; never included in ordinary snapshots.

Snapshot polling defaults to one second and pauses while the tab is hidden. A shared backend sample bounds duplicate browser work. Failure marks the last snapshot stale rather than replacing it with zeros. Browser state records receipt time and rejects results from superseded requests. All u64 identifiers and byte totals cross JSON as decimal strings to avoid JavaScript precision loss.

Commands include connection closure, selector selection, egress probe, route trial, RuleSet refresh, DNS cache clear/query, runtime start/stop/restart, config validation/save/apply and diagnostic export. Domain commands are executed only through the current generation's handles. Diagnostic network operations have explicit targets, bounded concurrency and deadlines, are cancelable during generation retirement, and never silently change selector state.

## Feature contract

### Overview

Report runtime generation and lifecycle, client version, uptime, separate inbound/DNS/TUN state, live upload/download, generation totals, active TCP/UDP, process CPU/RSS, bounded recent traffic samples and recent errors. Missing measurements are null/unavailable, never fabricated zeros. No automatic public-IP lookup or remote speed test.

### Connections

Stable generation-qualified IDs, protocol/inbound identity, optional sensitive source/target/requested-domain metadata, duration, live counters/rates and terminal status. `decision` carries the closed action kind, original rule index, captured rule-engine generation when available, concrete hop IDs and sniff evidence. The page displays hop tags in traversal order, never the selector's later choice. Configured rules display one-based numbers and full conditions on demand; compiler-generated rules for configurations without `[route]` display `入口默认出站`, not a fictitious user rule number. Configured target and actual concrete path remain separate. Explicit DNS hijack, TUN synthetic DNS interception, rejection and aborted decisions are distinguished from an unknown outbound.

Each connection captures immutable configuration attribution at admission. Selected paths and retained closed rows are never reinterpreted against a later selector choice or configuration catalog; runtime generation replacement still clears the existing history. Without `--dashboard-details`, endpoints, requested/sniff domains and rule conditions are discarded and sniff detail is explicitly redacted. Unknown IDs remain unknown; there is no current-state fallback, invented selector generation or claim of an exact internal RuleSet entry.

The default table prioritizes target/domain with provenance, transport plus observed application protocol, inbound, actual outbound/rule summary, traffic and duration. Source and diagnostic columns are optional; only safe column preferences persist. Search covers all authorized fields and referenced rules even when their columns are hidden; transport/application/outbound filters and sorting precede 50-row pagination. Counts distinguish matching, collected and omitted observations. `活动连接` / `已关闭记录` switching clears frozen display, selected IDs, pending closure confirmation and pagination while preserving filters. History hides closure controls. Pause freezes display only, not backend history. A responsive side-detail panel groups basic data, endpoints, sniff evidence, route/configured conditions and traffic; raw JSON is opt-in at the end. Both details and frozen lists pin their catalog objects. Confirmed closure retains exact IDs and generation despite intervening refresh.

There are at most 4,096 visible live rows, 512 five-minute history rows and 1,024 log entries. Aggregate TCP/UDP counts include omitted rows. A 65,536-entry weak index supports additional individual cancellations; close-all uses a generation broadcast and reaches even unindexed leases. New admissions after that broadcast are unaffected.

A TCP flow is one connection; UDP is a source-keyed association and the displayed target is its first admitted target, not an immutable five-tuple. TUN TCP obtains the original source IP/port from the stored forward tuple when the accepted flow is published; it never uses the translated socket peer or an OS connection-table lookup. TUN UDP may transition from synthetic-DNS-only admission to its first ordinary frozen decision; later datagrams do not continually rewrite display metadata. A DNS query domain is not attributed to later website connections. No process/PID, GeoIP, QUIC-from-port, reverse DNS or ECH inner domain is inferred. Saturation drops added detailed observations rather than blocking forwarding.

TLS/HTTP evidence reuses the existing TUN TCP prefix collector and parser outcome; no second sniff, new byte collection, changed deadline or new route evaluation is introduced for the UI. Prefix replay is unchanged. Successful protocol detection without a usable domain remains a positive protocol observation. Not-requested, not-executed, no-match, invalid, timeout, length-limit, resource-unavailable, cancelled, read-error and redacted outcomes remain distinct. UDP inspection remains DNS-only and records the admitted candidate, not discarded candidates. Payload-free SOCKS TCP does not gain TLS/HTTP sniffing; a reached sniff action is reported as not executed. Opening the dashboard never enables sniffing.

### Outbounds

Represent concrete Direct/Shadowsocks outbounds, selector immediate members/current choice and chain order. Existing TCP flows retain their frozen route; existing TUN UDP generation fencing may retire associations after selector changes. The UI warns about that interruption rather than claiming seamless migration. Probes report real configured-egress transport-connect time, not ICMP ping or an application round trip. No automatic failover or automatic test on page load.

### Routing and RuleSets

Show configured rule order and default egress, plus actual RuleSet load/generation/refresh state. Refresh failures retain the previous valid runtime snapshot and are visibly degraded. Offline route trial uses the real route evaluator and declares absent DNS/sniff metadata.

### DNS

Show configured listeners/upstreams, current policy and available request/cache observations. Explicit query diagnostics and cache clear operate on the current DNS owner. No default query-history recording. Query input/output remains on the authenticated diagnostic channel.

### Logs and diagnostics

Use the existing closed JSON tracing subscriber with a bounded tee, preserving stderr redaction and configured severity across restarts. Closed supervisor reports are also retained for startup/cleanup diagnosis. Export version, state, fixed-category metrics and closed logs, excluding source configuration, connection details, captures and keys. TUN diagnostics are read-only. Recording shows configured state and per-file budget; recording failures follow the existing explicit-shutdown reporting contract. No capture/file/key browsing or download is added.

The shared subscriber applies its metadata and live-severity predicate as a global filter, before
event fields are evaluated. Per-layer rejection is not the privacy boundary: a dependency can emit
nested tracing events while constructing a field, resetting the outer event's per-layer rejection
state. Foreign events must remain excluded even under nested dispatch and after severity changes.

### Configuration/settings

Read the one configured file, not arbitrary paths. Raw source is a separate explicit sensitive operation. Offline validate reuses the production parser and size limit. Save checks a source revision to detect concurrent external edits, validates first, then atomically replaces the same file using a private temporary file. Preserve restrictive file permissions. Redacted text is never round-tripped into the actual configuration.

Windows creates the temporary file with the protected original DACL atomically, before any handle can observe secret content, then uses `ReplaceFileW` without ignoring ACL merge failures. Unix refuses group/other-access or changed-owner save cases rather than transplanting permission bits onto a different effective ACL. Source revisions are optimistic concurrency checks: an uncooperative external editor can still race the final check/replacement window; no filesystem compare-and-swap guarantee is claimed.

Apply validates before stopping the current generation. Materialization/listener failure after restart is reported as failed; do not promise seamless rollback across exclusive network resources. Disk revision and running revision remain distinct. A failure never displays as applied. CLI management listener/token settings require process restart; network configuration uses a controlled proxy-generation restart.

After save/apply, the editor pairs the submitted source with the revision returned by that
command. A later read may refresh running-revision information but never silently adopts a
different disk revision for the old draft. External edits remain conflicts until explicitly
reloaded. Clearing or unmounting the editor invalidates pending read/save continuations so
sensitive source cannot reappear after it has been hidden.

UI-only settings include theme, table density/columns and refresh interval. These are safe local browser preferences; credentials and sensitive query state are not persisted.

## Build and packaging

The source tree stays modular. Bun installs exactly locked dependencies; Vite compiles React/TypeScript and `vite-plugin-singlefile` inlines JS/CSS. SVGs are inline and fonts use the OS stack. No external public assets, production source maps, PWA manifest/service worker, runtime chunks or separate workers are allowed.

The shipping document is `ui/dashboard/embedded/index.html`, accompanied by compile-time CSP and build identity metadata. These are tracked so ordinary locked Cargo builds need neither Bun nor frontend downloads. `bun run build` regenerates them; `bun run build:check` rebuilds and compares without overwriting shipping files. Transient `dist` and `node_modules` are ignored. The client embeds the document with `include_bytes!`; a missing asset is a compile error, never a placeholder page.

Dependencies for Rust are workspace-inherited and exactly pinned. Frontend dependencies and Bun version are pinned with the committed lockfile. UI updates and the embedded document ship together.

`bun scripts/wire.ts` derives browser command/result declarations from the Rust wire
types. `dev`, `typecheck`, and the build gates reject stale declarations; regenerate
them after changing `wire.rs`. The generator rejects unsupported declarations rather
than widening the browser contract. Generated `src/wire.ts` is not independently formatted.

## Implementation sequence

1. Establish observation and browser protocol contracts, authenticated transport and generation controller.
2. Attach observation leases to real SOCKS/TUN TCP and UDP owners; publish existing domain handles.
3. Implement domain operations with generation fencing, bounded work and correct cleanup.
4. Build all seven React pages against those contracts, then generate the shipping HTML.
5. Wire ordinary CLI/offline-validation behavior, documentation and packaging checks.
6. Run focused Rust/frontend gates and actual unprivileged loopback client/browser scenarios. No privileged TUN scenario is implied by ordinary verification.

## Acceptance and evidence

Required scenarios: one shipping HTML with no external asset fetches; authenticated reads and writes; cross-site API rejection without blocking public navigation; live SOCKS counters before completion; individual/all closure; selector new-flow behavior; real route/DNS diagnostics; RuleSet failure retaining the valid generation; invalid config preserving runtime; revision conflicts; restart retaining management availability; owned shutdown; redacted exports; bounded lists.

Format/lint/test affected packages once integration is settled. The client test binary remains compile-only in ordinary gates. Run safe shared-crate tests and a real loopback process/browser smoke instead. Privileged TUN correctness requires its existing dedicated host runner and explicit authorization; report that verification limitation.

### Executed evidence

#### Structured connections V2 (2026-09-10)

- Safe suites passed: 15 dashboard tests and 167 TUN library tests, including original-source recovery through translated accept, sealed history, catalog replacement, redaction and sampling/retirement races. Client test binaries were compiled only; affected Clippy passed.
- A throwaway non-test executable compiled the client implementation with an entry point limited to real route selection over in-memory streams; it never started a TUN or runtime generation. It exercised a generated TLS ClientHello/SNI, HTTP Host, HTTP without domain, timeout, cancellation, read error, prefix length limit, exhausted aggregate prefix budget and payload-free non-execution. Selected prefixes replayed byte-for-byte. All nine cases passed.
- The real isolated loopback client exercised V2 TCP/UDP forwarding, DNS sniff evidence and TCP/UDP DNS hijack, rejection/default routing, frozen selector paths, closed history and config apply to an implicit ingress route. Browser verification covered the actual page plus 56-row fixtures built from the real sniff observations: cross-page hidden-source search, HTTP/domain provenance, catalog pinning across replacement, fixed closure IDs after refresh, pause/history behavior, safe preferences, desktop and 390-pixel cards/details.
- A release observation-library experiment with 4,096 synthetic rows sharing a roughly 1 KiB rule condition compared the preceding string contract with V2. Across 21 encodings, median snapshot generation/encoding was 30.907 ms versus 4.117 ms; wire size was 5,545,273 versus 1,872,470 bytes; allocation count was 241,703 versus 45,066 and requested allocation bytes were 37,442,818 versus 4,132,061. This measures synthetic serialization, not network throughput. Short-rule snapshots may be larger because V2 includes additional facts.
  Timing includes `stats_alloc` allocation-counting overhead in both executables; these figures must not be treated as uninstrumented production sampler latency.
- A local loopback A/B exercised dashboard off, enabled without polling, one poller and two pollers (one-second interval), with 512 idle flows in enabled modes and three rounds per case. Each round checked 128 short TCP lifecycles, four concurrent 64 MiB echo streams and 128 UDP exchanges. Throughput varied substantially; the first enabled-mode pairs showed about 4–6% higher candidate short-lifecycle p50, which was not established as a repeatable regression or improvement. Repeated bursts also encountered SOCKS general-failure replies in both baseline and candidate experiments. These observations are not a throughput/latency non-regression qualification or a zero-overhead claim.
- No privileged/native TUN performance result is inferred. The host correctness runner requires a clean exact candidate commit and separate explicit host-network acknowledgement; ordinary verification of this uncommitted change did not invoke it.

#### Earlier dashboard evidence

- Connection attribution update (2026-09-10): the real isolated loopback client reported named concrete outbounds, matched TCP/UDP rule conditions, default routing, TCP/UDP DNS hijack and TCP rejection. Switching `manual` from `direct-a` to `direct-b` preserved the existing TCP path and its closed-history attribution while a new flow used `direct-b`. Chromium verified the newly embedded page with those live records; a separate 56-row browser fixture verified cross-page search, full long-rule details and the active/history switch at desktop and 390-pixel widths. Dashboard tests, client build/all-feature compile-only tests, affected Clippy, formatting and embedded build parity passed. No privileged TUN runtime was exercised for this update.

- Windows MSVC client/server builds, client all-feature test-binary compilation, affected-package Clippy and workspace formatting checks succeeded. The client test executable was not run.
- Shared dashboard/core/rule/RuleSet/config/DNS/observability and server suites: 388 passing tests. Hosted-safe Windows-platform and TUN suites: 75 and 139 passing tests. Selected M0 process/contracts suites: 52 passing tests, three ignored.
- Locked frontend typechecking, formatting and shipping parity checks succeeded: one 278.35 kB HTML with matching CSP/build identity. Public dashboard/observability Rust documentation generation succeeded.
- Real client + owned loopback TCP/UDP/DNS peers: 110,592 payload bytes appeared in live upload/download counters before the TCP flow closed. Selector switching preserved the old `[0]` TCP path while a new flow used `[1]`; closing the old flow left the second functional.
- Real SOCKS UDP association echoed and recorded 16 payload bytes each direction; selected closure ended its control stream.
- Authenticated domain commands executed a configured-egress TCP probe, rule-zero rejection/default-route trial, policy-routed A lookup, explicit-server AAAA lookup and cache clear.
- A reviewed pinned remote SRS was actually materialized. Manual refresh degradation (including an intentionally unreachable download path) retained RuleSet generation 1 and left the proxy running. No successful WAN refresh or performance claim is inferred from this.
- Invalid initial config was corrected through the management editor. Invalid apply preserved the running source/generation; an external file edit produced conflict rather than overwrite. Restart with a live flow honored the existing 30-second grace, reaped the old flow and retained HTTP management; stale-generation commands returned 409.
- A broadly inherited Windows token file was rejected. A private current-user token was accepted. Secure PowerShell token creation was exercised without an inherited-access window.
- Chromium exercised all seven pages, an actual DNS form submission, dark mode and a narrow viewport. Screenshots confirmed layout; no external script/style/font resources were requested and there was no horizontal page overflow.
- Default HTTP port 80 was exercised in Chromium: canonical Host/Origin without `:80` reached authenticated snapshot and command handling; invalid source still returned `config.invalid` rather than an origin rejection.
- The initial Linux GNU cross-check stopped in `ring` because `x86_64-linux-gnu-gcc` was missing. Later native Linux merge verification is recorded below; no privileged TUN qualification is claimed.

### Review corrections and real HTTP verification

- The post-save revision race was reproduced through Vite and the real Rust HTTP backend:
  an external file edit between save and reread was overwritten by the next save before the
  correction. The corrected editor retained the saved base revision, received HTTP 409 on
  the next save, and preserved the external file.
- A delayed real config response no longer restores a cleared editor. Fractional rates such
  as 0.5 B/s retain the byte unit rather than selecting an undefined unit.
- All seven pages were exercised through the documented Vite development entrypoint.
  A real SOCKS TCP echo exposed 3,200 live bytes in each direction before closure;
  an authenticated individual-close command then closed the actual application socket.
- Actual HTTP checks returned 401 without authentication, 403 for a foreign Origin,
  400 for invalid apply without changing disk/runtime, and 409 for an old-generation
  command after a successful restart.
- The rebuilt embedded HTML repeated revision-conflict and clear-invalidation checks on the
  real Rust HTTP listener, with matching CSP hashes, `no-referrer` and `nosniff` headers.
- The merged Windows build passed workspace/all-target/all-feature Clippy with `-D warnings`,
  33 policy tests, 388 related-package tests, and hosted-safe TUN/Windows-platform suites
  (139/75). Client tests remained compile-only. Locked frontend checks verified the final
  embedded HTML, CSP and build identity.
- Native Linux passed the same full Clippy/build gates, ordinary and hosted-safe suites
  totaling 1,005 passed with two existing ignored tests, client/Rule-qualification test
  compilation, and workspace documentation. Dependencies were prefetched with `cargo fetch
  --locked`; tests retained default concurrency in a temporary unprivileged network namespace
  with its own loopback because the host WSL path dropped large loopback UDP datagrams.
  No host route, DNS, firewall, adapter or WSL networking setting was changed.

## Running the dashboard

Management credentials permit reading source configuration and changing the proxy runtime. Do not share the token or expose this endpoint through an unauthenticated relay. Use the exact numeric loopback URL printed by the client, not an arbitrary Host alias.

Create a private token once. On Windows, this PowerShell command creates the file with a private DACL from the outset (it refuses to overwrite an existing file):

```powershell
$tokenPath = Join-Path $PWD 'dashboard.token'
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'Allow'))
$file = [System.IO.FileSystemAclExtensions]::Create(
    [System.IO.FileInfo]::new($tokenPath),
    [System.IO.FileMode]::CreateNew,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, $acl)
try {
    $token = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $bytes = [Text.Encoding]::UTF8.GetBytes($token)
    $file.Write($bytes, 0, $bytes.Length)
} finally {
    $file.Dispose()
}
```

On Unix, create a current-user-only file atomically:

```sh
python3 -c "import os,secrets; f=os.fdopen(os.open('dashboard.token',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w'); f.write(secrets.token_hex(32)); f.close()"
```

Start with your normal schema-v2 configuration:

```text
cargo run -p ferrum2-client --locked -- --config client.toml --dashboard-listen 127.0.0.1:9090 --dashboard-token-file dashboard.token --dashboard-details
```

Open `http://127.0.0.1:9090/` and enter the file's token. Omitting `--dashboard-details` keeps endpoint identities out of connection snapshots. Closing/locking the page does not stop the proxy. The management flags conflict with `--check-config`; offline validation does not read a token or start a listener. TUN remains restricted to the existing supported/elevated runtime and is never enabled merely by opening the dashboard.

## Frontend development and shipping checks

Use Bun **1.4.2**. From `ui/dashboard`:

```text
bun install --frozen-lockfile
bun run typecheck
bun run format:check
bun run build
bun run build:check
```

`dist` contains exactly `index.html`; `embedded` contains the same document plus compile-time security/build metadata. Commit source, `bun.lock` and shipping assets together. Normal Cargo builds consume only shipping assets and do not execute Bun.

`bun run dev` binds loopback and proxies `/api` to `http://127.0.0.1:9090` by default. Set `FERRUM2_DASHBOARD_BACKEND` to another numeric loopback HTTP origin if needed; the development proxy rewrites Host/Origin for the protected client but still requires the same bearer token. Production has no proxy or CORS exception.

References: [React SPA build guidance](https://react.dev/learn/build-a-react-app-from-scratch), [React Router modes](https://reactrouter.com/start/modes), [single-file Vite plugin](https://github.com/richardtallent/vite-plugin-singlefile), [MetaCubeXD](https://github.com/MetaCubeX/metacubexd), [Zashboard](https://github.com/Zephyruso/zashboard).
