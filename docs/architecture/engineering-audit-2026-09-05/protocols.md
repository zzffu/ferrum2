# Protocol / crypto / network engineering audit — 2026-09-05

Scope: ferrum2-{crypto,shadowsocks,socks5,sniff,net}. Product is read-only; no source, vendor or fixture edits. All 35 src Rust files were read (34 production files plus TCP tests module); production coverage is recorded per file in protocols-coverage.json. This is static engineering review plus bounded existing tests and an isolated in-memory API probe, not a complete security scan or performance qualification.

Inputs: root and five scoped AGENTS.md; workspace and package manifests; engineering-remediation-2026-09-05.md; network-model-v2-migration.md; core DomainName validation; server UDP commit and client UDP response composition; package test inventories, full UDP session/replay and TCP internal tests, selected entropy/cache/sniff contracts. Existing integration tests were executed, but not every integration-test source line was individually audited. Historical remediation evidence is context only, not proof that this audit passed.

## Findings to include in unified design

### PROTO-1 / P2 — UDP activity can move backwards and shorten mandatory replay retention

- Locations: crates/ferrum2-shadowsocks/src/udp/server.rs:293; udp/client.rs:289 and :298.
- Rule: scoped guide requires retention of current/old associations and replay/session state for the mandatory interval. Mutex serialization does not order timestamps sampled before acquisition.
- Fact: server assigns `session.last_activity = now`; client similarly assigns current/old `last_valid = now`. Public concurrent commit APIs accept caller-sampled time. A later lock acquisition carrying an older sample overwrites a newer activity value.
- Reproduction: target/remediation-audit/protocols-probe.rs commits valid distinct packets at 10s then 5s. Snapshot reports 5s; remove_session succeeds at 65s, although accepted 10s activity requires retention until 70s. Probe log confirms behavior. Client single/batch paths share the same unguarded helper; that branch was statically traced, not separately executed by the probe.
- Impact: premature session/capability removal or old-association rotation, shortened replay protection. Real production occurrence magnitude remains unmeasured; callers normally sample near commit and runtime locking may serialize some paths. Do not claim an observed remote exploit.
- Fix direction: monotonically retain max(previous, supplied) under the protocol owner lock; keep duplicate rejection mutation-free; test reverse timestamp order for server/current/old and batch atomic rollback, plus 59.999/60s boundaries. Match the already-remediated runtime monotonic activity contract without adding another timer.

### PROTO-2 / P2 — Server UDP commit and response capabilities do not bind their owning server

- Locations: crates/ferrum2-shadowsocks/src/udp/server.rs:52, :65, :127, :205, :392.
- Rule: authentication must precede accepted mutation; generation-bound response capabilities should identify the same live protocol owner. Deep capabilities should prevent crossing independent key/state owners.
- Fact: UdpRequestCommit contains only session ID and packet ID; commit_request never checks which UdpServer authenticated it. ServerResponseCapability contains slot/generation; each server starts next_generation at 1 and slot equals generation. Capabilities collide deterministically across server instances.
- Reproduction: isolated probe authenticates on AES key A and commits the token successfully into server B using a different AES key. Each server's first capability compares equal, and B.session_snapshot(capability_from_A) returns B's session. No socket or external packet is used.
- Impact: in-process routing/composition mistakes can cross authentication domains, mutate another server's replay state, or resolve an unrelated response/expiry capability. Current production callers inspected retain the matching protocol reference; no demonstrated network-triggerable route to cross-owner misuse. Treat as a public API integrity defect, not a remote authentication bypass claim.
- Fix direction: bind request token and response capability to an immutable opaque server owner identity plus generation, or make commit/capability methods operate through an owner-bound handle. Preserve move-only commit, cheap lookup, and redaction. Test wrong server, wrong key, removal/recreation, owner movement and concurrent duplicate winners.

### PROTO-3 / P3 — UDP outbound crypto session can be used by another same-profile key owner

- Locations: crates/ferrum2-crypto/src/udp/aead.rs:228; udp/session.rs:153.
- Fact: seal checks profile only. AES outbound stores a cipher derived with its creator's key, while header encryption uses `self`'s key. Passing an outbound session created under key A to same-profile UdpCrypto B can produce mixed-key wire and advance A's packet counter while returning success. In ChaCha, sealing instead uses B's primitive with A's session lineage.
- Contract nuance: public docs explicitly promise method binding, not creator-instance binding. Thus this is an architectural footgun and consistency gap, not an established violation of a documented key-identity equality promise. Production protocol wrappers store matching crypto/session owners privately, so inspected production use cannot mix them.
- Fix direction: unify outbound sealing into its cryptographic owner or bind the lineage to a stable key capability. Avoid per-packet PSK copies/comparisons; test same-profile different-key rejection without buffer/counter mutation, retain same-key reuse semantics deliberately. Static evidence only; not added to executed probe.

### PROTO-4 / P3 — Known-enum error mapping and positional booleans leave contract maintenance implicit

- Locations: shadowsocks/src/udp/wire.rs:245 and :252 wildcard mappings; :33/:44/:63 response booleans; crypto/src/udp/aead.rs:153 encrypt boolean. Also net model NetworkInterfaceObservation::new operational/connected booleans, RouteNetworkOptions::new automatic-selection boolean.
- Rule: latest root AGENTS requires enumerating known variants and descriptive enum/newtype/named method call sites instead of opaque booleans; literal parameter annotations where needed.
- Impact: a future FrameError or DetectionReason silently maps to Bounds; two-direction packet layout is coupled by u8 message_type and optional binding instead of one validated direction value. No current wire misclassification found.
- Fix direction: explicit exhaustive mappings and cohesive direction/header operation types; remove invalid message-type/binding combinations internally. Preserve exact error classifications with behavioral tests; do not mechanically wrap every getter or split unrelated code.

### PROTO-5 / P3 — Fixture seams and obsolete AES-128 constants broaden production exports

- Locations: shadowsocks/src/tcp/wire.rs:10–13 and tcp/mod.rs/lib.rs reexports; crypto/src/tcp/key.rs:16 and tcp/nonce.rs public standalone fixture methods.
- Rule: minimize public exports, typed method-bound primitive ownership, no obsolete compatibility APIs.
- Fact: TCP_SALT_LEN=16 and fixed first-read lengths=43/59 are AES-128 only, yet publicly named generically; production flow uses MethodProfile widths. In-repo references to those constants and TcpSubkey::from_bytes/standalone NonceCounter are tests, not production consumers. Fixture encoders/open_data_frame are also explicitly documented test seams.
- Fix direction: move pure primitive/fixture construction to crate-owned unit tests or an explicit test-support feature if cross-crate qualification needs them. Use profile-derived dimensions in integration tests. Keep actual wire profile owners stable internally. This is export/API cleanup, not proof that current wider-method flows use the wrong widths.

## Performance hypotheses and structural observations (not measured bottlenecks)

- shadowsocks/udp/server.rs:240–249: new-session collision predicate scans every server session's outbound ID under the global state mutex, on each bounded random retry. Also performs random generation and KDF under that lock. Complexity is O(live sessions) per ordinary insertion, O(N²) aggregate ramp; established per-session crypto locks correctly allow different existing sessions to encode concurrently. Consider an exact outbound-ID index and short reserve/commit section; retain collision checks across both directions. Profile churn at 1/256/4096+ sessions before changing this path.
- shadowsocks/udp/client.rs:218–252: batch commit sorts up to eight owner addresses, allocates multiple short Vecs and clones up to two 129-word replay windows per hop for all-or-nothing commit. Bound is correct; possible chain response allocation cost. Profile then use bounded stack staging or a validate/commit design only if atomic replay semantics stay exact.
- net/model.rs: snapshot identity validation scans pairwise (called twice from from_interfaces); resolve_named allocates a Vec just to examine matches. Snapshot capture is not per-packet; cache is bounded to 256 successful entries and catalog lookup is outside cache lock. Avoid overstating snapshot cost as packet throughput problem.
- sniff/lib.rs: reparses accumulated bytes with a fresh rustls Acceptor/httparse parser each invocation; byte-at-a-time caller accumulation can create repeated parsing work, but bounded max_bytes and caller acquisition policy control cost. Keep stateless ownership unless profiling identifies this as material.
- shadowsocks/tcp/wire.rs:441: rejection sampling for padding is statistically efficient but has no retry ceiling; a broken/injected SecureRandom returning all 0xff spins synchronously. Real OS CSPRNG loop termination is probabilistic with extremely small repeat probability; not an observed production stall. A bounded attempt policy can fail closed without modulo bias.
- Module size: socks5 lib (650 lines), shadowsocks flow/client (588), handshake (561), wire (462), udp/client (472), crypto udp/aead (668 incl tests) mix several cohesive subowners. Prefer extracting SOCKS command/reply vs UDP codec and boxed transport vs client RX when implementing unified design. Do not split solely to hit line counts.

## Verified invariants / rejected false positives

- Typed PSKs/subkeys are private, non-Clone, redacted and zeroizing via owned primitive/Zeroizing state. MethodSalt is intentionally cloneable replay identity, not a cloneable key. TCP nonce reserve commits only on successful AEAD; terminal exhaustion preserves buffer/counter. Locked vendor TCP decrypt_packet zeroizes failed body; wrapper has all-profile behavioral test, so no duplicate cleanup defect is reported.
- TCP first fixed read/write is intentionally one operation for detection prevention; subsequent variable/data frames handle fragmentation, bounded poll work and partial writes. Authentication plus semantic request validation precede replay insertion/session return; full response salt binding precedes payload release. Immutable terminals freeze later I/O. No socket/task ownership was introduced in Tokio adapter.
- TCP replay exact HashMap+FIFO has bounded capacity, atomic one winner, monotonic duration expiry, fail-closed full store. Sampling order can retain some expired entries longer if callers violate ordered epoch assumptions, but no short-retention TCP defect established.
- UDP crypto opens expose identity/plaintext only after authentication, zeroize failed body, cache only successful AES opens, key-bind four cache entries, and bound session-ID collision retries. Packet IDs consume terminal u64 once then fail closed. prepare_* changes scratch/cache only, not accepted replay/association state. Runtime reservation remains caller-owned by contract; no unbounded protocol-server-store finding independent of caller admission is asserted.
- SOCKS greeting/address/frame reads are fixed-bounded; one-shot reply and retained TCP control ownership are present; UDP decode borrows payload and encoder checks full output bounds before mutation. Timeout comes from client run/socks/tcp_command.rs composition, not protocol crate. ASCII/root-only domains match core's deliberately permissive protocol target contract.
- Sniff checks caller byte limit, complete UDP framing, DNS query/section size plausibility, TCP DNS arbitration, transport strictness, duplicate Host handling and redacted Metadata. It reports outer/observable TLS SNI only.
- net preserves explicit/automatic/default/system priority, family/source membership, immutable snapshots and stale-generation cache nonregression. Snapshot equality lacks specific routes: never recommend ignoring all route notifications just because interface snapshots compare equal. Errors are closed; data-model Debug carries interface data intentionally, without source errors.

## Executed evidence and limits

`cargo test -p ferrum2-crypto -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-sniff -p ferrum2-net --all-features --locked`: exit 0; 138 tests passed, including optional Tokio adapter. Raw log protocols-tests.log. First invocation failed to create log because output directory did not exist; no test was started; rerun above succeeded.

`cargo clippy -p ferrum2-crypto -p ferrum2-shadowsocks -p ferrum2-socks5 -p ferrum2-sniff -p ferrum2-net --all-targets --all-features --locked -- -D warnings`: exit 0; raw protocols-clippy.log.

In-memory probe compiled with rustc against exact locked Cargo build artifacts recorded in protocols-artifacts.jsonl; probe executable exited 0 and confirms three current undesirable behaviors in protocols-probe.log. Informational Windows linker import-library warning retained. Product and fixture sources remain unchanged. No formatting change was made; no host qualification, network mutation, CPU profiling or cross-platform execution was done by this audit. Passing tests do not cover the newly demonstrated cross-owner and reverse-time cases and do not prove performance non-regression.

