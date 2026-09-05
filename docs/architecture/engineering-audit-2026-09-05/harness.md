# M0 harness independent engineering audit — 2026-09-05

Scope: tests/m0-harness. All 18 src Rust files were read completely, including local process contract tests. Root, tests, harness and every nearer AGENTS.md were read. Package manifest preserves independence from concrete Ferrum2 Cargo dependencies. Key integration contracts were reviewed at their observable seams; coverage JSON explicitly distinguishes full src coverage from targeted integration review. Product, test and fixture source remain unchanged. No new failure reproducer or external/provider/privileged workload was executed.

## Findings for unified remediation

### HARNESS-1 / P2 — Capture read failures are reported as complete successful output

Locations: src/local_support/process.rs:635; src/external_support/process_guard.rs:80.

Fact: local CaptureOwner handles `Ok(0) | Err(_)` identically and sends OutputSummary with no capture-failure field. External capture_output similarly breaks on any Read error then sends Capture. Process status and thread joining can therefore succeed while the pipe data is incomplete. Local ChildExit.assert_stderr_excludes refuses a truncated capture but cannot detect this read error. External version, config and DNS probe checks likewise interpret partial bytes as full output when truncation is false.

Contract: capture and qualification evidence must fail closed; cleanup/capture failure cannot produce success. This is static confirmed control flow, not a measured occurrence on an OS pipe. Existing process contract covers thread creation, channel loss, worker panic and delayed join, but does not cover a Read implementation returning an error after a prefix.

Fix direction: distinguish EOF from read failure; carry a closed read-failure status through finish and qualification result; handle Interrupted explicitly as appropriate. Never print the underlying reader error. Add a bounded injected-reader regression only in the authorized implementation phase, and verify exclusion checks cannot pass from partial evidence.

### HARNESS-2 / P2 — Qualification diagnostics can format received payload and arbitrary child text

Locations: src/external_support/tcp_case.rs:187; udp_case.rs:217; process_guard.rs:369; provider_artifact.rs:336.

Fact: failed assert_eq(received, reverse) or assert_eq(echoed, payload) includes received wire payload in panic text. HostedOperations catches the panic and emits panic_diagnostic; its sanitizer replaces only the two known synthetic PSK strings and retains up to 4096 characters. sanitize_capture similarly copies all bounded child output, replacing synthetic PSKs and escaping line separators. DNS run_dns_probe failures also embed captured output. This conflicts with scoped instructions that logs must never expose keys or peer data. The normal fixed qualification payloads are synthetic; nevertheless actual received bytes and child diagnostic text are not restricted to those constants.

Impact: qualification failure can leak data into CI logs; no claim that a current successful provider run leaked credentials. Static only.

Fix direction: compare complete bytes but panic with a closed mismatch category, lengths and approved digest, not Debug payload. Replace arbitrary text forwarding with closed capture summaries and allowlisted structured diagnostics. Retain raw captures only under a deliberately authorized evidence policy. Test redaction with existing-style sentinels and preserve row attribution.

### HARNESS-3 / P2 — CLI identity probes escape the bounded process owner

Location: src/bin/m0_qualification.rs:86–99; analogous metadata helper tests/workspace_policy.rs:23–36 and fake profiling wrapper launcher tests/tooling_profile_cpu.rs:97.

Fact: `git(...).output()` waits and buffers stdout/stderr without a time/size cap or child owner. These two git probes run before HostedContext validation and before any CaseDeadline. A stalled git status therefore prevents any row/result output. The qualification binary guide explicitly requires bounded deterministic CLI failures and thin ownership delegation.

Fix direction: use a common bounded harness command owner for fixed git probes, capped UTF-8 stdout, closed failure classification, kill/reap plus capture join. Preserve exact HEAD/clean-check semantics. Metadata/profiling test helpers have a related test-suite hang risk; avoid executing real profiling just to validate the wrapper. Static only; no stalled child injection was run.

### HARNESS-4 / P2 — Some local test socket/worker paths lack complete bounds

Locations: tests/local_e2e_support/mod.rs:67–91, :33–38, :113–159; tests/socks_udp_support/mod.rs:164–180; src/local_support/readiness.rs:14–25.

Fact: EchoWorker accepts with a 5s bound, but read_to_end grows an unbounded Vec and only sets a per-read timeout; write_all has no write timeout. Drop attempts a blocking TcpStream::connect then unconditionally joins the worker. The recording bridge returns a raw JoinHandle and its nested forward worker can detach if the reverse copy panics before join. Datagram echo waits for exact count using its supplied socket without installing its own receive timeout; its drop wakeup is best effort, then join has no deadline. wait_for_listener wraps blocking TcpStream::connect in a nominal 5s outer loop, which does not bound the connect operation itself.

Contract: tests allocate bounded loopback resources and reap/release after failure or panic. Current normal fixtures send finite payloads and local connection refusal is usually fast; this does not prove failure paths are bounded. Some callers install socket timeouts; the helper contract does not enforce them. No hang/resource-exhaustion reproducer was added.

Fix direction: adopt exact expected payload lengths/limits, shared absolute socket deadlines, and cancellable worker ownership with explicit join status. Reuse the existing process/readiness discipline instead of copying it per target. Keep the black-box protocol implementation independent of product crates.

### HARNESS-5 / P3 — Absolute case deadlines are not passed through all UDP control reads

Locations: src/external_support/udp_case.rs:247–316, :198–218.

Fact: open_socks_udp_association sets read/write timeouts once, then multiple read_exact/write_all operations (including domain/address fields) reuse that timeout. read_socks_address accepts generic Read without CaseDeadline, so partial reads can extend total wall time beyond the 60s case end. The datagram loop likewise sets a capped timeout once for all three send/receive exchanges and checks the case only after each exchange. TCP case helpers correctly refresh the remaining absolute deadline on every operation.

Impact: rows can exceed their advertised absolute duration before eventually failing; finite wire lengths still bound the number of field bytes, so do not call this an infinite network read. Fix by using the same absolute-deadline helpers as TCP and passing deadline into address/reply decoding. Verify fragmented replies near deadline later; static only here.

### HARNESS-6 / P3 — Loopback allocator uses unbounded retry/global never-reused port state

Locations: src/local_support/loopback.rs:36–58, :68–78; local_support/mod.rs ISSUED_PORTS.

Fact: ephemeral allocation retries forever if the OS returns a port already present in the never-cleared per-test-executable set; paired TCP/UDP allocation also has no retry ceiling. The registry is bounded by the u16 port space but eventual exhaustion/hit-heavy behavior has no closed failure. External ReservedEndpoint already has a 32-attempt limit. Normal current suite sizes are far below exhausting the port namespace; this is a resilience/maintenance gap, not observed exhaustion.

Fix direction: bounded retries and explicit failure with no port/peer payload in diagnostics; maintain uniqueness and same-policy rebind requirements. Do not replace reservations with fixed globally chosen ports.

## Architecture/rules observations

- local_support/process.rs is 877 lines of one transactional child/capture/reap owner. This is a justified cohesive state machine, but additions should deepen capture and completion ownership rather than accumulate policy. Root recommends separate cohesive owners near 800 lines; preserve adjacent process contracts with extraction.
- qualification/mod.rs is 750 lines: closed plan/report model, hosted context validation, cleanup accounting and TCP synchronization. Keep orchestration cohesive as scoped instructions require. QualificationOps and DnsQualificationOps at :287/:293 lack purpose/implementor-obligation documentation required by root AGENTS; describe bounded execution, row isolation, and cleanup obligations. Their synchronous shape is appropriate; no async-trait issue.
- Some test fixture APIs still use positional booleans (`udp`, `hinted`, `signallable`, `bind_tcp`) and strings for closed choices. Prefer direction/transport enums or named constructors when touching these call sites. Synthetic key helpers may remain test fixtures; no production compatibility API was found here.
- catch_sanitized temporarily replaces the process-wide panic hook. Hosted binary runs serially, but this ambient hook mutation is not safe as a reusable parallel API: concurrent hook replacement can suppress unrelated diagnostics or restore an obsolete hook. Keep serial execution documented or move sanitization to a process/report boundary without temporary global mutation.
- Source pin verification hashes the archive, checks location/executable bit and version, and matches SS archive member allowlists. It does not itself prove extracted executable bytes equal the archive member. Hosted extraction workflow is part of that trust chain; root CI review must validate its closure. No unreviewed provider executable was run here.
- src/external_support/pin_hash.rs implements SHA-256 itself to support the dependency-light qualification binary. Block schedule, partial updates and final padding were read; no algorithm defect found. Consider consuming the already pinned sha2 through an allowed external dependency to reduce hand-maintained primitive code; this is not a finding that hashes are currently wrong.

## Verified boundaries / key target review

- No concrete Ferrum2 Cargo dependency; paths include harness-owned support, not product source. Independent protocol fixture construction is appropriate for black-box tests.
- local process ownership registers immediately, rolls back capture setup, bounds direct child waits, retains unconfirmed child/capture handles, and refuses later spawns when cleanup remains failed. Output cap is 256 KiB. ChildExit normally formats length/hash/truncation rather than raw output. Registration and reaping logic were fully read, including 262-line contract source.
- External ProcessGuard marks child/worker ownership and never declares final cleanup success with pending owners. Drop failures poison CleanupState; finish_cleanup checks both counts and retained handles. These paths retain owners rather than silently detaching as success. The final pending registry is not a background reaper and does not promise native termination after OS failure.
- QualificationReport emits every fixed TCP/UDP case row, isolates provision/case panic failures, checks final cleanup, and records exact commit/run/attempt. DNS matrix deliberately requires both CoreDNS server and BIND client for every row; this is not an incorrect dependency merely because each row has one reference label.
- Hosted validation requires Linux GitHub context, full matching SHA, clean checkout and numeric nonzero run/attempt. Environment is captured once into an injectable context; tests vary the context rather than mutating process globals. Provider executable paths derive from expected RUNNER_TEMP layouts and canonical containment.
- TCP qualification checks forward/reverse bytes and half-close in both directions with a synchronization gate. UDP rows exercise three distinct request/reply datagrams while retaining SOCKS control. DNS includes direct/detoured transports, negative encrypted checks and final TCP/UDP rebind. Cases remain external only; no provider or privileged execution was performed.
- lifecycle_cycles: reviewed readiness, foreign-owner collision classification/retry, cleanup and 1-vs-20-cycle dispatch. Genuine setup failure is not retried unless persistent foreign occupancy is established; full lifecycle is ignored by ordinary discovery. Strong metrics/protocol identity readiness exists here, unlike generic wait_for_listener. Individual scenario bodies were not all fully re-audited in this subtask.
- process_support_contract: complete source review; environment variable is set only on spawned child Command, not global process state. Standalone ordinary invocation of child test returns immediately without its env. No new injection executed.
- qualification_contract: plan uniqueness/cartesian coverage, missing setup, row failure/panic isolation, final cleanup and exact completion lines reviewed; existing pure tests executed as below.
- metrics_exposition: complete current test read; uses spawn_while_holding correctly, asserts unique HELP/TYPE and one EOF plus distinct client flow/owner names. Parent already holds red/green evidence; no redundant execution or repair here.
- local_e2e_support and socks_udp_support: complete façade/helper source review, protocol bytes built independently; worker deadline issues above. CLI/config support uses structured shutdown-report field assertions and redaction checks, not private product function names. Config CLI source and local/UDP E2E entry points were sampled, not claimed fully reviewed.
- workspace_policy: manifest metadata dependency checks and architecture.toml/fixture/unsafe policy seams reviewed; structured parsing and mutation tests own these policy exceptions. Workflow/hosted PE/feature topology submodule implementations were inventoried but not fully reread: root is reviewing CI/controller closure. Do not count this as a complete independent workflow-parser audit.
- tooling_profile_cpu: Linux-only wrapper contract uses fake perf/samply/readelf/readlink/git supplied via child environment, so ordinary execution is not real CPU profiling. Tests check output/metadata and stage status, but the launcher bound needs improvement as HARNESS-3. Not run on this Windows audit.

## Evidence

`cargo test -p ferrum2-m0-harness --test qualification_contract --locked`: exit 0, 16 passed, 0 failed; target/remediation-audit/harness-tests.log. These are existing in-memory orchestration tests; no new abnormal-case reproducer was authored. No client test binary was run, product build/tests were not blindly repeated, and no performance/host/provider gate was executed. Parent's metrics test/package-lint and earlier workspace evidence are separate historical evidence, not newly claimed validation.

All findings are static unless explicitly identified as existing test results. New regression tests and fixes are deferred to the unified design/implementation phase. Previous protocols report remains unchanged.
