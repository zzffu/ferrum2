# TEST-0016 — M15 Windows Wintun TUN data plane

- **Status:** Approved
- **Milestone:** M15
- **Baseline:** `bd374c6ec47470020bfcf908aa1a3475f0b3dbf0`
- **Performance:** required；diagnostic only，no minimum throughput/improvement claim

## Evidence map

| Requirement | Cheapest primary evidence | Command / selected profile |
|---|---|---|
| Exact baseline、docs-only product diff and control integrity | Git identity + schema-3 footprint control | `git rev-parse HEAD 'HEAD^{tree}' 'HEAD^'`；`bash scripts/test-budget.sh verify` |
| Rust `1.97.1` is the planning-date latest stable and the exact workspace/toolchain/CI/policy MSRV | Official Rust release record + local exact-version probe + workspace-policy mutations | `rustc +1.97.1 --version --verbose`；`cargo test -p ferrum2-m0-harness --test workspace_policy --locked` |
| Schema-v2 TUN-only/coexistence/static/routed/global-tag/index shape；v1/server/unknown/range/exact-memory negatives | Extend the existing config contract table；no new config harness | `cargo test -p ferrum2-config --test config_contract --locked tun_` |
| `--check-config` performs no DLL/device/admin/thread/OS mutation and target gate precedes success | Extend existing CLI trap table plus Windows fake-device call count | `cargo test -p ferrum2-m0-harness --test config_cli --locked tun_` |
| Wintun ZIP/DLL hash、license、PE/signature/exports | `windows-tun-e2e` PowerShell preflight against official ZIP | hosted job invokes `pwsh ... -Mode artifact`；standalone local run is diagnostic |
| Exact `windows-sys 0.61.2` direct eight-feature/default-off edge、no delta outside that list's Cargo feature closure and sole no-default `smoltcp 0.13.1` ten-feature identity without auto echo | Existing workspace lock/feature policy mutation guards | `cargo test -p ferrum2-m0-harness --test workspace_policy --locked`；`cargo tree -i smoltcp@0.13.1 -e features --locked` plus windows-sys inverse tree |
| Trusted local non-reparse sibling/System32-only load、held-path hash/load identity、exact 11-symbol failure and narrow unsafe ABI | `ferrum2-wintun` unit/negative tables + source/lock guards | `cargo test -p ferrum2-wintun --locked`；`cargo test -p ferrum2-m0-harness --test architecture --locked` |
| Adapter/address/per-family MTU/DAD/session prepare and reverse rollback | Direct ephemeral privileged `windows-tun-e2e` smoke with failure at every setup step | hosted job invokes `pwsh ... -Mode lifecycle`；standalone local run is diagnostic |
| Only expected address-derived Windows rows appear；external routes untouched；adapter truly disappears/rebinds | Before/ready/after OS snapshots and controller-owned narrow-route sentinels | same `-Mode lifecycle` |
| Single setup/cleanup owner thread、packet lifetime、bounded queues/generation IDs、zero owners | Private memory device + owner/lifecycle mutation tests | `cargo test -p ferrum2-tun --locked` |
| Exact two smoltcp AnyIP routes and bounded single-packet polling quantum | Route-count/lookup/full and starvation mutations on the private memory device | `cargo test -p ferrum2-tun stack_route --locked` |
| Exact IPv4 bare-header / IPv6 direct-TCP-or-UDP parser；malformed/oversize/fragments/extensions/non-TCP/UDP create no state/TX | Table-driven synthetic IP packet tests on the private memory device | `cargo test -p ferrum2-tun packet_filter --locked` |
| Wintun ring-full、session EOF、wait wake/order and close postcondition | ABI fake failure table plus privileged ring/session rows | `cargo test -p ferrum2-wintun --locked`；Windows controller lifecycle mode |
| TCP route、one/two-hop、sniff、DNS hijack、reject、selected failure no fallback | Client composition tests + real IPv4/IPv6 narrow-route E2E | `cargo test -p ferrum2-client tun_tcp --locked`；controller `-Mode tcp` |
| TCP prefix exact-once、local-handshake/reset、backpressure、half-close、idle/grace/force | Memory-device stream mutations + existing relay/sniff tests | `cargo test -p ferrum2-tun tcp_ --locked`；`cargo test -p ferrum2-runtime --locked` |
| Existing M14 over-limit candidate commits nothing and next candidate observes switched selector | Extend the existing client routed-UDP regression before TUN work | `cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked` |
| TUN UDP route once、selector snapshot、expiry/reselection、over-limit/no-commit、response binding、saturation | Association/mapping tables + real IPv4/IPv6 E2E | `cargo test -p ferrum2-client tun_udp --locked`；controller `-Mode udp` |
| TUN DNS hijack uses the existing answerer and no SS owner/fallback | Existing DNS answerer tests + client composition owner counters | `cargo test -p ferrum2-dns --test proxy_contract --locked`；`cargo test -p ferrum2-client tun_dns --locked` |
| No duplicate route/sniff/DNS/SIP022 path、no route/DNS/WFP product APIs、unsafe only in approved FFI | Extend existing architecture/workspace-policy mutation guards | `cargo test -p ferrum2-m0-harness --test architecture --locked`；`cargo test -p ferrum2-m0-harness --test workspace_policy --locked` |
| Graceful/forced/panic/repeated-start cleanup and exact rebind | Extend existing lifecycle matrix；privileged 100-cycle adapter row | exact repository lifecycle command below；controller `-Mode cycles` |
| TUN absent preserves M0～M14 and non-driver targets | Existing Full/MSRV/native/interoperability profile unchanged | repository gates below + existing workflow matrix |
| Wintun hot-path/resource evidence on the same exact SHA | Independent manual Windows TUN performance/resource job | authorized `.github/workflows/m0.yml` dispatch；record exact run/job/SHA |
| One exact SHA closes all required evidence and reviews | Existing qualification aggregate plus TUN functional result and separate performance result | M15-T07 exact-SHA evidence ledger |

## Required negative and mutation rows

- Config tables MUST cover every default；each numeric minimum-1/minimum/maximum/maximum+1；power-of-two ring
  neighbors；checked product/sum overflow；budget `64 MiB` default and `256 MiB`-1/equal/+1；and the exact
  `53,995,616`-byte default oracle。`tcp_buffer_bytes` mutations MUST prove two directions per flow and
  `max_udp_buffered_bytes` MUST remain one global two-direction pool。
- Dependency/MSRV mutations MUST reject any smoltcp identity other than `0.13.1`、default features、
  `auto-icmp-echo-reply`、a missing/extra literal feature、workspace/toolchain/CI/policy disagreement、a
  residual M15 `1.88.0`/`1.91` selector and any floating Rust channel。A future stable release does not make
  this exact plan stale-green；it requires a control amendment。
- Inbound-index tables MUST cover TUN-only ID 0，zero/one/two SOCKS inbounds followed by TUN ID N，TUN
  add/remove without SOCKS renumbering，SOCKS declaration reorder，ordinary/DNS route lookup by tag and every
  TUN collision with ordinary/DNS inbound、outbound、chain or selector tags。
- DLL rows MUST cover missing/wrong size/hash/architecture/signature/member/license、each of the eleven
  missing/mistyped symbols、unsafe search path and unsupported OS/arch。UNC/network paths、a reparse DLL and a
  reparse executable-directory component MUST fail before `LoadLibraryExW`。Path-component retarget、file
  replacement、truncate、rename and writable-open attempts MUST fail while held directory/file handles and the
  library live and succeed only after cleanup。A mutation MUST fail if load can precede every path check/hash。
- No admin、adapter-name collision、owner-thread spawn、DLL/create/address/IPv4-MTU/IPv6-MTU/DAD/session/
  smoltcp failure at every position；later-root failure after TUN prepare；owner panic/EOF；cleanup conflict
  and close-with-leak。Only `IpDadStatePreferred` passes；Tentative→Preferred、Tentative→timeout and direct
  Duplicate/Invalid/Deprecated rows are required。Every row proves cleanup completes on the owner thread
  before its join and that no wait overlaps `WintunEndSession`。
- IPv4 tables MUST cover every length/header-checksum/transport-checksum/zero-port/TCP-data-offset/UDP-length
  boundary，IHL `4/5/6`，reserved/MF/offset combinations，DF allowed，ICMP/unknown protocol，MTU±1 and trailing
  bytes。IPv6 MUST cover payload-length/checksum/zero-port boundaries and base Next Header `0,43,44,50,51,
  59,60,135,139,140,253,254` with absent、truncated、well-formed and chained bytes；every value is rejected
  before extension parsing。Valid TCP/UDP are direct base-header `6/17` only。Ingress and egress use the same
  table and prove no packet/state/telemetry-cardinality leak。
- smoltcp route tests MUST assert exactly two non-expiring default routes via the two configured interface
  addresses，arbitrary IPv4/IPv6 unicast admission，third-route failure and no product Windows route API。
  Poll mutations MUST show stop/control/timers are observed after at most eight ingress packets。
- TCP SYN/admission saturation、queue-full window closure、partial writes、FIN ordering、RST、sniff timeout/
  limit/invalid、prefix duplication/omission、selected open/DNS failure and cancel/force races。
- UDP mapping full/expired、tuple/generation reuse、first queue-full/over-limit candidate、selector A→drop→B、
  later selector change ignored、expiry observes change、wrong-bound response、DNS malformed/no-fallback and
  UDP/TX saturation recovery。Architecture mutations MUST prove `ferrum2-tun` sees only an opaque terminal
  token/payload bound or drop，while route/hijack/reject plans and modes remain in the client adapter。
- Every architecture/security assertion needs one mutation that would fail if the forbidden second path、
  route API、unsafe location、pointer escape or policy re-entry were introduced。

## Privileged Windows profile

Use one fresh GitHub-hosted Windows AMD64 runner first。It downloads the official ZIP to runner temp，checks
the exact ZIP and DLL identities，copies only the AMD64 DLL beside the exact candidate，uses a unique adapter
name and dedicated test prefixes，and adds only controller-owned `/32`、`/128` or dedicated-prefix routes
after fixed readiness。An `always` cleanup block removes only those exact routes/processes/temp files and
asserts adapter/address/route/HANDLE/process absence and name rebind。

The existing workflow gains exactly one automatic job ID/name `windows-tun-e2e`。At T03 it first runs four
foundation rows（artifact，offline no-side-effect，prepare/ready/valid-packet drop，failure rollback/rebind）
and prints this only after `always` cleanup succeeds：

```text
m15_windows_tun_e2e status=PASS profile=foundation foundation=4/4 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```

T04/T05 expand the same job/controller to this fixed sixteen-row functional manifest，and T06 adds the
integrated lifecycle/aggregate gate：

| ID | Required real-process witness |
|---|---|
| TCP-01 | IPv4 one-hop route、echo and half-close |
| TCP-02 | IPv6 fixed two-hop chain |
| TCP-03 | IPv4 TLS sniff/domain route and exact prefix replay |
| TCP-04 | IPv6 HTTP sniff/Host route and exact prefix replay |
| TCP-05 | IPv4 DNS-over-TCP multiple queries with zero Shadowsocks owner |
| TCP-06 | IPv6 reject with zero egress owner |
| TCP-07 | IPv4 selected-open failure reset and no fallback |
| TCP-08 | IPv6 backpressure、grace and force drain |
| UDP-01 | IPv4 one-hop route and authenticated response binding |
| UDP-02 | IPv6 fixed two-hop chain |
| UDP-03 | IPv4 selector snapshot unchanged for a live mapping |
| UDP-04 | IPv6 expiry and reselection |
| UDP-05 | IPv4 DNS hijack with zero Shadowsocks owner |
| UDP-06 | IPv6 reject tombstone and no policy re-entry |
| UDP-07 | IPv4 over-limit/queue-full no-commit then selector re-read |
| UDP-08 | IPv6 mapping saturation、generation reuse and wrong-response drop |

T04 and T05 hosted descendants emit intermediate post-cleanup markers from that same job：

```text
m15_windows_tun_e2e status=PASS profile=tcp tcp=8/8 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
m15_windows_tun_e2e status=PASS profile=transport functional=16/16 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```

The job is a required aggregate dependency only when this final marker appears after artifact/lifecycle,
`16/16` functional rows，`100/100` adapter cycles and cleanup：

```text
m15_windows_tun_e2e status=PASS profile=full functional=16/16 cycles=100/100 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```

Windows TUN performance/resource is a separate manual required job named `windows-tun-performance`。It
records raw RX/TX、one TCP and one UDP hot-path witness、CPU/RSS/handles/threads/queue peaks、adapter churn、
grace/force drain and cleanup，without a threshold claim，then emits：

```text
m15_windows_tun_performance status=PASS witnesses=2/2 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```

Remote invocation is accepted only after a later authorization names the exact candidate SHA、ref，whether
one non-force push and/or `workflow_dispatch` is allowed，and the permitted attempt count。Automatic evidence
uses the authorized `codex/integration/**` push or PR；manual evidence uses
`gh workflow run m0.yml --ref <authorized-ref>` only within that scope。Readback MUST prove the run head SHA
equals the candidate and the marker's SHA/run ID/attempt equal GitHub context。A rerun changes attempt and
needs fresh authorization。Hyper-V/self-hosted infrastructure is added only if the direct-runner job records
a capability failure and a new control amendment is accepted。

No remote action is authorized by this plan。Failed runs remain evidence and are not rerun or combined with
another SHA without a new authorization and descendant repair。

## Test-footprint forecast

Exact planning footprint is code/tests `25586/45009`、ratio `1.759126`，with
case/support/fixture `39260/5152/597`。Thresholds remain `2.0/2.5`、`240/600` and `800/1200`。

| Ticket | Test-case LOC | Support LOC | Rust fixture LOC | Expected signal |
|---|---:|---:|---:|---|
| M15-T01 | 0 | 0 | 0 | PASS |
| M15-T02 | 80–160 | 0 | 0 | PASS/WARN |
| M15-T03 | 700–1,100 | 180–300 | 0 | REVIEW_REQUIRED likely |
| M15-T04 | 650–950 | 60–120 | 0 | REVIEW_REQUIRED likely |
| M15-T05 | 700–1,050 | 80–160 | 0 | REVIEW_REQUIRED likely |
| M15-T06 | 500–800 | 200–350 | 0 | REVIEW_REQUIRED likely |
| M15-T07 | 0–80 | 0 | 0 | PASS |
| **Total forecast** | **2,630–4,140** | **520–930** | **0** | milestone review expected |

The PowerShell controller and small synthetic TOML are non-Rust support outside the Rustloc categories but
still require provenance/diff review。Use existing crate tests and `m0-harness`；the private in-memory packet
Adapter is the sole new fake seam and is not exported。No packet capture、Wintun binary、second Rust harness
or third equivalent helper is planned。Growing test files should remain below 1,200 semantic test LOC where
practical；numeric review is dispositioned，not hidden by deleting independent evidence。

## Repository gates

Run the authoritative local Full profile serially：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
```

Then run the exact M15 MSRV、footprint and diff gates：

```powershell
rustc +1.97.1 --version --verbose
cargo +1.97.1 check --workspace --all-targets --locked
cargo +1.97.1 build --workspace --bins --locked
cargo +1.97.1 test --workspace --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

Final qualification additionally requires the existing Windows MSVC、Linux GNU、Linux musl、SIP022 TCP/
UDP、CoreDNS/BIND and test-footprint workflow results，the privileged Windows TUN functional result and the
independent same-SHA Windows TUN performance/resource result。
