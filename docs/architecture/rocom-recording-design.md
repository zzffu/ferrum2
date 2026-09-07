# Embedded rocom recording and offline decoding

## Decision and scope

Ferrum2 remains one proxy executable/process. `ferrum2-rocom` is an internal session observation module, not a network outbound. Existing Direct/Shadowsocks routing, TCP relay, half-close, cancellation, DNS and TUN ownership remain authoritative. A separate `ferrum2-rocom-decode` executable operates offline. No sidecar, local SOCKS hop, Dashboard, automation, packet modification, injected heartbeat or retained game session is introduced.

Recording is explicitly enabled by a client-only `[rocom]` configuration containing `record_path`, a **directory**, and optional `max_bytes` (default 268435456, range 65536–1099511627776 inclusive). Every recognized TSF4G connection is saved automatically to its own independently decodable JSONL file in that directory. Ordinary HTTP/plain TCP, UDP and DNS-hijacked streams produce no capture files. Identification uses the existing GCP header parser on the first complete bounded header from either direction, buffering split prefixes in memory. Before identification, a magic mismatch or invalid initial header rejects the candidate connection without queueing evidence or creating a file; an incomplete/unidentified connection produces no file. There is no magic scanning or guessed resynchronization. Once identified, all subsequent observed raw bytes remain evidence even after framing, key extraction or decryption failures. This remains sensitive research capture: use a private directory and controlled application traffic. With `[rocom]` absent there is no recorder, worker, capture file or payload copying.

## Ownership and seams

- Client composition owns one `Recording` worker owner and a cloneable `Recorder` handle, creates the output directory only in normal startup, and explicitly shuts down after connection owners stop. Offline `--check-config`/materialization/finish never create directories, files or workers. Existing directory entries are never overwritten or deleted.
- Each ordinary SOCKS/TUN TCP relay opens a candidate `Capture` from the handle. `Capture::observe(direction, bytes)` receives bytes on successful reads, before parser interpretation. Candidates are classified in memory; only a matching connection submits a connection event and buffered prefix to the writer. Observation does not modify, suppress or delay network data for framing. Existing sniff prefixes and split header bytes are retained exactly once. Captures are read observations, not acknowledgements of successful forwarding.
- The `ObservedIo` adapter wraps each relay endpoint's `AsyncRead`; writes/flush/shutdown are forwarded unchanged. Upload is read from the application endpoint, download from the opened upstream. Explicit `Capture::finish(reason)` records the relay result; drop without finish records cancellation. No new relay implementation or runtime-level game dependency is needed.
- One worker and one bounded queue (256 events, each raw chunk <=32768 bytes) serve the entire directory, not one thread per connection. Oversized supplied chunks are split. Queue overflow stops recording globally, leaves forwarding running, and produces incomplete footers if storage is writable. `max_bytes` applies independently to each connection file: a capped or failed file disables that capture without stopping unrelated files, and reserves footer capacity where possible. Errors/incompleteness are reported at explicit shutdown. No detached tasks or automatic file deletion/rotation.
- The writer owns one file and `KeyTracker` per identified connection. It recognizes GCP framing and SYN/ACK key state in recorded order, without decrypting DATA online. Per-connection parsers use bounded memory; raw data is written before key extraction, so unsupported handshakes/invalid framing after identification never erase evidence. A completed connection writes its end and integrity footer and closes its file immediately; that file can be decoded while the proxy and other connections remain running. Shutdown closes still-active files as incomplete.

The SOCKS seam supplies its actual peer socket address. The current TUN flow interface exposes only the target at this seam, so TUN `source` is null rather than a fabricated loopback address. Capture IDs still separate all flows and key state. Original process/window association is not part of this recording-only change.

## Source record contract (schema 1)

UTF-8 JSONL, one flat object per event, one connection per file. Common fields: `schema_version: 1`, per-file consecutive `event_seq: u64` starting at 1, `elapsed_us: u64`, and `kind`. Each file contains its own started/connection/data/key/end/stopped lifecycle (an incomplete source may lack later events). Numeric IDs/offsets are integers (offline Rust tools retain u64 exactly).

Event variants:

- `started { max_bytes }`
- `connection { connection_id, source: string|null, target: string }`
- `data { connection_id, direction: "upload"|"download", offset, bytes }` — `bytes` is base64 of exact successful-read bytes. Offset is per direction and contiguous from zero.
- `key { connection_id, direction, offset, key_method, enc_method: u8|null, source_sequence, key_hex: string|null }` — snapshot at the observation of a handshake; offset is the start of that GCP packet. Null key means key unavailable/invalidated, not reuse of the previous key. Raw SYN/ACK remains authoritative evidence. The associated data event precedes the derived key event.
- `end { connection_id, reason }` — closed strings such as `completed`, `io`, `idle_timeout`, `cancelled`.
- `stopped { complete, reason }` — `shutdown`, `queue_full`, `size_limit`, `resource_limit`, `open_connections`, or `writer_error`. Missing footer always means incomplete, including process crash/disk error.

`Record` and `RecordEvent` live in `record.rs`; serialized records are shared by online writer and offline reader. New files use create-new/no overwrite. Unix mode is 0600; Windows uses the destination directory's ACL, so use a private user directory. Protocol bytes, keys, paths and peers must not enter normal Ferrum2 telemetry/error chains. Sensitive captures/decrypted outputs are never committed.

## Protocol module contract

Shared `Direction` lives in `record.rs` and derives serde/copy/equality. The protocol owner exports `KeyTracker::new()` and `observe(direction: Direction, bytes: &[u8]) -> Vec<KeySnapshot>`. `KeySnapshot` has `direction`, `offset`, `key_method: u8`, `enc_method: Option<u8>`, `source_sequence: u32`, `key_hex: Option<String>`; Debug is redacted. Offsets start at zero for each direction. It returns each observed SYN/ACK state change, including invalidation, preserves split/coalesced framing, and stops interpretation rather than guessing resynchronization after invalid framing. It never decrypts or buffers complete DATA bodies merely to collect keys.

Reuse/adapt the wire and crypto facts from `C:/Users/ZZZ/Documents/DDD/rocom_tool/crates/{tsf4g_parse,tsf4g_codec}` with attribution. Do not import its FFI, application/business modules or absolute path dependencies. GCP: big-endian magic 0x3366, 21-byte base header, bounded combined head/body length, SYN 0x1001, ACK 0x1002, DATA 0x4013. SYN carries key/encryption methods; ACK method 2 can carry a 16-byte AES key. Existing method 3 is AES-128-CBC zero IV with a decrypted 16-byte prefix and `tsf4g` trailer/trim suffix. Do not infer plaintext from a missing key/method; unsupported state is explicit.

## Offline decoder

The crate's optional `decode` feature builds `ferrum2-rocom-decode --input PATH --output PATH [--proto-dir PATH]`. Binary errors/summary contain closed categories/counts rather than source bytes, keys or paths. Input is read-only; output is create-new and never overwrites input/existing files. Exit 0 requires complete source and fully decoded supported messages; exit 2 indicates usable output with incomplete/failed/unsupported items; exit 1 indicates fatal input/output/CLI-resource failure (CLI parse errors may use clap's exit 2).

The decoder validates source sequence/schema, connection lifecycle, directional offsets, bounds and footer. Reassembles each direction in source event order, shares only same-connection key state, and retires state at end. Packet boundaries remain independent of decryption/body success. Bad ciphertext or unknown inner format yields one diagnostic message and continues at the next trusted GCP boundary. Broken framing yields a failure region, not magic-byte guessing; other connections/directions continue. Unknown GCP commands/bodies remain binary evidence. Missing/truncated source is never reported complete.

For each packet/undecodable region emit one flat object: connection/direction, stream offset, source event reference, GCP fields, key reference, decode/decryption status, failure stage/code/offset where applicable, and raw/plaintext evidence. Do not emit nested `gcp { data { value {} } }` protocol envelopes. A successful business payload may occupy one `payload` field with its real message nesting retained. Decrypted bytes must survive an application-header or payload-decoder failure. Never turn arbitrary binary into guessed UTF-8/Protobuf. Standard C2S, compact/short C2S and S2C headers from the source tool are supported. Optional legacy `.proto` schemas allow named protobuf decoding; without schemas use a bounded wire-field representation with raw length-delimited bytes, not guessed nested messages. Non-Protobuf payloads receive an explicit unsupported status plus exact plaintext/payload bytes, suitable for later library extensions.

Each output begins with decoder/schema identity and input content digest and ends with summary counts/integrity. Sources remain immutable, so future library versions can replay the same evidence. Synthetic regressions defend split/coalesced frames, key isolation/rotation/invalidation, malformed ciphertext followed by valid packet, nonstandard headers/non-Protobuf bodies, unknown fields, truncation/offset gaps and output non-overwrite. Real user captures/keys are not test fixtures.

## Usage

Build from the repository root (the decoder feature does not introduce a second running proxy):

```text
cargo build -p ferrum2-client -p ferrum2-rocom --features ferrum2-rocom/decode --bins --locked
```

Append this table to an otherwise valid schema-v2 **client** configuration:

```toml
[rocom]
record_path = 'C:/Users/ZZZ/Documents/private-captures'
max_bytes = 268435456
```

Choose a private output directory; normal startup creates it if absent. Paths are used as provided;
relative paths resolve against the process working directory. Offline `--check-config` and config
finish do not touch storage. Every matching flow gets a new uniquely named file, including after a
restart into the same directory; existing captures and unrelated entries are untouched. There is
no need to choose each connection or supply a filename. `max_bytes` caps each file separately,
not the directory/session total. The server rejects `[rocom]`.

On Windows:

```text
target/debug/ferrum2-client.exe --config client.toml --check-config
target/debug/ferrum2-client.exe --config client.toml
```

A normally completed connection closes its file with an integrity footer immediately, so decode
that finalized file without stopping the proxy. Active Windows capture handles may exclude
concurrent access: wait for connection completion rather than reading an unfinished file.
Normal shutdown drains the queue and closes still-active captures as incomplete. The network
continues if recording reaches a resource limit; a per-file cap does not stop other captures,
but proxy shutdown reports recording incompleteness. Remove `[rocom]` to disable capture entirely.

```text
target/debug/ferrum2-rocom-decode.exe --input C:/Users/ZZZ/Documents/private-captures/SELECTED-FINALIZED-FILE.jsonl --output C:/Users/ZZZ/Documents/private-captures/decoded-output.jsonl
```

Optionally append `--proto-dir C:/Users/ZZZ/Documents/DDD/rocom_tool/proto_v2` to supply named
message definitions. They are read at decode time, not embedded in the proxy. Without definitions,
payloads use a lossless wire-field representation. Unknown/non-Protobuf payloads retain their raw
and decrypted bytes with a partial status. Do not mistake that for successful business decoding.
On Unix, omit `.exe` and use private local paths.

The output's `message` records contain the GCP metadata and decode outcome at the same level.
`raw`, `plaintext` and `payload_raw` are base64; `key_hex` is hexadecimal. A `payload` may preserve
the business message's own arrays/objects; there is no nested outer/inner protocol result wrapper.
`source_event` and `completed_event` locate message assembly in the original records.
`failure_stage`, `failure_code` and `failure_offset` identify decoding failures; framing offsets
are directional stream offsets, while crypto/application/payload errors refer to the indicated
packet/body stage. The final summary separates source completeness from successful decoding:
a complete recording can legitimately produce exit 2 because an identified connection later
contains malformed framing, unsupported ciphertext or unknown business data.

Keep the source file unchanged when iterating on the library. Write each re-decode to a fresh
filename and compare decoder/input/schema identities, failure codes, and recovered payloads.

## Verification and risk

Verification plan for the directory/selection contract (not a claim of executed validation):

- Exercise real local SOCKS-to-TCP traffic with at least two overlapping TSF4G connections,
  distinct synthetic keys, split initial headers and malformed bytes after identification.
  Compare forwarded and captured bytes, directional offsets, key isolation, file-local sequence
  and lifecycle; read the first finalized file while another connection and the proxy stay live.
- Send HTTP/plain TCP, invalid GCP headers and incomplete prefixes through the same proxy.
  Require unchanged forwarding and no files for those connections. Verify recognition from
  either direction and no guessing/resynchronization in focused recorder regressions.
- Check that offline preparation/finish/`--check-config` never create the directory, normal
  startup does, and a restart into an existing directory neither overwrites captures nor
  modifies an unrelated sentinel. Prove one capped file does not stop other captures.
- Run the standalone decoder against each finalized connection file in a separate smoke
  experiment. The ordinary harness regression needs only the proxy, not a prebuilt decoder.
  Cover encrypted messages, malformed then valid messages, non-Protobuf plaintext and disabled
  recording with synthetic keys/loopback only.
- Compile TUN/client tests under repository safe-host rules; do not execute privileged host
  networking. Run affected tests, formatting and clippy after edits settle. Recording is bounded,
  not zero-copy. A disk error cannot guarantee a footer; missing footer is an integrity failure.

### Directory/selection implementation evidence (2026-09-08, Windows x86_64)

- `cargo test -p ferrum2-rocom -p ferrum2-config --features ferrum2-rocom/decode --locked`
  passed 103 tests across eight suites. Focused recorder coverage includes split prefixes,
  recognition from either direction, invalid/incomplete/non-game exclusion, preserved malformed
  tails, per-file cap isolation, directory/file rejection, bounded queue failure, independent
  finalization, and preservation of existing files across runs.
- `cargo test -p ferrum2-m0-harness --test rocom_recording_e2e --test workspace_policy --locked`
  passed 21 tests. The real SOCKS regression exercises two overlapping keyed connections,
  HTTP/plain/invalid/incomplete traffic exclusion, finalized-file readability while another
  connection remains live, and restart uniqueness without changing an unrelated sentinel.
- A separate real proxy smoke created a previously absent nested capture directory. HTTP
  forwarded unchanged and produced no file. Partial GCP prefixes produced no files until
  identification. Two game sessions then produced exactly two independent JSONL captures,
  preserving both directions, complete prefix bytes, distinct keys and malformed tails.
- Both files were decoded by `ferrum2-rocom-decode` while the proxy was still running. Each
  recovered its expected encrypted application value (42 and 43 respectively), reported zero
  source-integrity errors and a complete source, and retained later malformed bytes as failure
  evidence. Exit 2 was expected for those deliberately malformed tails.
- The actual `--check-config` invocation created no directory. The proxy and synthetic server
  exited normally; temporary scripts, capture files and decoded evidence were removed afterward.
- Locked binary build, compile-only client all-feature tests, affected-package all-target/
  all-feature Clippy with `-D warnings`, and `cargo fmt --all -- --check` passed. No real game
  traffic or privileged TUN/route/DNS/WFP operation was performed.

### Historical implementation evidence (2026-09-08, Windows x86_64)

The following results predate the directory/TSF4G-only correction. They describe the former
single-file, all-TCP implementation and do **not** validate the current selection, per-file
limits, restart naming or early-finalization contract. New evidence must be supplied separately.

- The proxy and standalone decoder were built together with locked dependencies. Production
  method-3 decryption uses the existing pinned AWS-LC provider; RustCrypto AES is a dev-only
  independent encryption oracle. The workspace crypto ownership policy remains unchanged.
- Real loopback SOCKS/TCP exchange covered fragmented SYN/ACK, two key epochs, coalesced frames,
  malformed ciphertext followed by valid data, compact non-Protobuf data, and ordinary TCP.
  Both directions arrived byte-for-byte unchanged, including half-close behavior. The recording
  reproduced every observed byte and both keys with contiguous offsets and a complete footer.
- The actual decoder produced 11 message/region records with 5 intentionally unsupported/failed
  items, zero source-integrity errors, complete source, and exit 2. A supported-only six-packet
  replay produced six successes, zero failures, zero integrity errors, and exit 0.
- A synthetic legacy schema decoded the expected named message fields into the single message
  object and emitted its schema digest. The supplied rocom `proto_v2` directory compiled and was
  used by the actual decoder; synthetic traffic need not match those real message definitions.
- Removing the footer marked the source incomplete. A directional offset gap retained failure
  evidence and still emitted the independent second connection. Existing output was refused
  with exit 1 and remained byte-identical. Original source files remained unchanged.
- `--check-config` created no capture; the same real traffic with recording disabled created
  no files and did not alter the earlier recording. Both proxy runs exited normally.
- `cargo test -p ferrum2-rocom -p ferrum2-config --features ferrum2-rocom/decode --locked`:
  101 tests passed across eight suites. The recorder-only library suite passed five tests.
- `cargo test -p ferrum2-client --all-features --no-run --locked` passed (compile-only).
  `cargo test -p ferrum2-m0-harness --test rocom_recording_e2e --test workspace_policy --locked`
  passed 21 tests, including the real proxy recording regression.
- `cargo clippy -p ferrum2-rocom -p ferrum2-config -p ferrum2-client -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings`
  and `cargo fmt --all -- --check` passed.
- No real game traffic, live TUN adapter, route/DNS/WFP mutation, or privileged host qualification
  was performed. TUN integration is compile-verified, not live-host-qualified.
