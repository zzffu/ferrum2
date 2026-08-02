# TEST-0007 — M6 SOCKS5 UDP ASSOCIATE evidence

- **Status:** Approved
- **Milestone:** M6
- **Spec:** `docs/specs/SPEC-0007-m6-socks5-udp-associate.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M6-MUST-01 config compatibility | preserved client fixture/value/side-effect table plus explicit/disabled/range negatives | T02 product |
| M6-MUST-02 control lifetime | public SOCKS command interface tests and paused-time client setup/control-close table | T01/T02 |
| M6-MUST-03 UDP wire | borrowed decode/encode IPv4/IPv6/domain table, exact truncation/RSV/FRAG/erratum bounds | T01 protocol |
| M6-MUST-04 endpoint authorization | request-hint table plus same-IP/different-port/wrong-IP/invalid-first race snapshots | T02 security |
| M6-MUST-05 SIP022 ordering | live-ID collision table and existing packet/replay/binding tests composed inside runtime reservation | T02 security |
| M6-MUST-06 resources/shutdown | session/permit/queue/allocated-byte owner snapshots and control/idle/cancel/forced/rebind table | T02 runtime |
| M6-MUST-07 observability | existing family identity with client-role deltas and secret/endpoint/target sentinels | T02 operator |
| M6-MUST-08 product/interop | three-method local process matrix and same-SHA external UDP `12/12` with FerrumClient binary rows | T02/T03 release |

## T01 SOCKS interface evidence

- Keep every existing greeting/CONNECT/reply/negative row byte-exact；the CONNECT-only core
  `Inbound` path must still reject `BIND` and `UDP ASSOCIATE` with `REP=07`。
- Through the new command interface, prove fragmented TCP request reads, zero/nonzero ports
  across valid address encodings, malformed hints, single success/failure reply ownership
  and retained control stream。
- Table-drive standalone UDP IPv4/IPv6/domain encode/decode, empty/max payload, each header
  truncation, nonzero RSV, every nonzero FRAG class, bad ATYP/domain/port and erratum-3198
  IPv6 overhead。Errors expose no packet/address value。

```powershell
cargo test -p ferrum2-socks5 --locked
cargo clippy -p ferrum2-socks5 --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 composed product evidence

- Preserved config fixtures prove absent `[udp]` remains disabled；explicit empty/enabled/
  disabled/min/max/invalid sections prove role-specific defaults and zero-resource check mode。
- Public-interface and paused-time tables prove setup rollback、advisory address/port pin、first-invalid
  non-pin、concurrent endpoint race、live session-ID collision 0..8、buffer/queue/session
  pressure、response commit ordering、idle/control EOF/cancel/forced cleanup and metrics。
- Real processes send three datagrams for every method through
  application SOCKS UDP → ferrum2-client → SIP022 UDP → ferrum2-server → direct echo；focused
  rows cover IPv6/domain target, wrong source, FRAG drop, disabled command, control close,
  saturation and restart/rebind without a full cross product。
- Existing TCP local E2E、server UDP、runtime UDP and lifecycle tests remain regression gates。

```powershell
cargo test -p ferrum2-config -p ferrum2-shadowsocks -p ferrum2-runtime -p ferrum2-client --locked
cargo test -p ferrum2-socks5 --locked
cargo test -p ferrum2-m0-harness --test config_cli --test socks_udp_local_e2e --locked
cargo clippy -p ferrum2-config -p ferrum2-shadowsocks -p ferrum2-client --all-targets --all-features --locked -- -D warnings
cargo +1.85.0 check --workspace --all-targets --locked
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 external substitution and qualification

Keep the 12 fixed `M2-UDP-INT` IDs, methods, references, three-datagram payloads, deadlines,
failure continuation and cleanup. Replace only the six FerrumClient process adapters: spawn
the composed client with explicit bounded `[udp]`, then reuse the exact SOCKS UDP exerciser
already cross-validated against sing-box and shadowsocks-rust in the six ReferenceClient rows。
The protocol example remains local protocol-API evidence；do not add a matrix or provider。

```powershell
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo clippy -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Integration and hosted gates

Run serially on one accepted integration SHA:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

After separate explicit authorization, one automatic push run/attempt for that SHA must pass
quality/Full/security/process、Rust 1.85、Windows MSVC、Linux GNU/musl、TCP regression、
UDP `12/12`+cleanup and the repository final qualification summary。Existing performance
output may run as repository regression but M6 adds no throughput/resource threshold。

## Stop rules

- Any source-pinning/open-relay、wire/auth/replay、unbounded allocation/queue、owner leak、
  preserved-config、Full/MSRV/platform/interop/budget or blocking-review failure blocks M6。
- Provider unavailable、skipped row、wrong SHA/run/attempt or absent remote authorization is
  not PASS。Old M2/M5 results are regression history only。
- One full Architect/QA review and one targeted re-review are the default bound。
