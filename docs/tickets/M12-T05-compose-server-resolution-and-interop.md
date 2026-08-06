---
id: M12-T05
milestone: M12
status: done
depends_on: [M12-T04]
owns:
  - .github/workflows/m0.yml
  - Cargo.lock
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-server/Cargo.toml
  - bins/ferrum2-server/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/resolver.rs
  - crates/ferrum2-dns/src/runtime_owner.rs
  - crates/ferrum2-dns/tests/tagged_upstreams.rs
  - tests/m0-harness/Cargo.toml
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/external_support/mod.rs
  - tests/m0-harness/src/qualification/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - tests/interop/versions.toml
---

# M12-T05 — Compose server resolution and interop

## Outcome

Select a tagged DNS resolver and its optional server-direct detour for authenticated TCP/UDP domain
targets，preserve the existing connector/deadline/candidate seams and prove real process behavior against
pinned external DNS software。

## Dependency boundary

The server adds only the existing workspace `ferrum2-dns` direct edge required to compose T03's public
resolver/owner API。The existing lock package row and workspace-policy dependency assertion may change
only to record that local edge；no root dependency、new package identity or provider is added。
`run.rs` may declare the sibling `dns_egress.rs` module directly，so `main.rs` remains out of scope。

ADR-0031's selected-profile trust injection is implemented only as the default-off
`ferrum2-dns/__interop-test-root` feature。It embeds the already reviewed M12 synthetic CA and still
verifies certificate chain、time and configured name；it adds no config、CLI、environment、runtime root
input or insecure verifier。Normal/default/release builds remain WebPKI-only。Only the isolated DNS
qualification build may enable it，and that target directory must be deleted after the run。

The existing `external_support` provider/process owner and `qualification_contract` test seam are the
only authorized external-runner paths；T05 must extend them rather than create a second harness。
`.github/workflows/m0.yml` may change only in one isolated single-parent control-only commit before any
Rust/product commit，to provision the exact pinned CoreDNS/BIND artifacts and make the existing interop
job require the DNS qualification result。The existing control commit may be amended before the first
product commit so its isolated client/server build enables `ferrum2-dns/__interop-test-root`；it remains
one control commit。It must not change triggers、performance/manual-dispatch semantics、unrelated jobs or
test-footprint policy，and later product commits must inherit the amended blob unchanged。

The existing client `run.rs` test module has one bounded T05 lease to repair the hosted-only DNS proxy
readiness race exposed before formal review。Only the failing test and an already-shared test helper may
change；client product behavior、configuration and public surfaces remain out of scope。

The inherited T03 `tagged_upstreams.rs` has one bounded test-only lease for the same hosted Linux socket
allocation class。Reuse the existing DNS-test network serialization/paired-address pattern；do not change
resolver、transport or lifecycle product behavior。

The shared `runtime_owner.rs` has one bounded T05 repair lease for the hosted-only sequential-query
failure reproduced before formal review。After each completed lookup/query has reaped its registered
tasks，release that command's admission permit before waking its caller；do not change admission limits、
deadlines、fallback、thread ownership or shutdown behavior。

Formal Architect/QA review grants one additional bounded T05 repair lease to the existing harness
manifest and shared DNS command seam。The harness may add only the already pinned
`hickory-proto.workspace = true` dev edge so `local_support` can replace its handwritten DNS fixture
codec with Hickory；the lock and exact workspace-policy sets may record only that edge。Server A/AAAA
resolution may add one address-lookup command that owns one selected-plan snapshot，one admission
permit，one task set and one absolute `dns.timeout_ms` deadline across both record types。It must
preserve the outer TCP/UDP phase deadlines，A-before-AAAA ordering，the 16-candidate cap，and existing
fail-closed/no-fallback behavior。No package identity，provider，retry，cache，second harness or public
configuration surface is authorized。

Exact candidate `4dcd89fa879873dc25ae9f5c1a3ef2635261ac76` receives one bounded hosted-quality
test-only repair lease in `local_e2e.rs`。Run `31110243307/1` passed CoreDNS/BIND interoperability、
test-footprint、MSRV and all three platforms，but Linux quality observed the DNS case reading one
unrelated active child while `fixed_two_hop_tcp_chain_uses_distinct_credentials_and_reaps` was still
running。After the DNS case has reaped its own client/server，reuse the existing
`hold_process_spawns_at_or_below(baseline)` pattern through the global-count and exact-rebind probes。
Do not change product code、the signal-group helper、any other caller or workflow；a new remote mutation
still requires separate authorization。

## Acceptance

- [x] DNS-present server uses authenticated inbound/network/original target for first/final selection；
      DNS detour and application outbound may name different direct tags，while DNS-absent system
      resolver、IP bypass、pre-resolution outbound route and 16 candidates remain exact。
- [x] Actual client→server→target TCP/UDP cases use distinct synthetic answers to prove selected action；
      empty/wrong/timeout/exhausted results never connect/forward or fall back。
- [x] Existing qualification provider pins/hashes/licenses CoreDNS 1.14.6 and BIND 9.20.26 without a
      second harness or public-network DNS dependency。
- [x] CoreDNS UDP/TCP/DoT/DoH and BIND-to-ferrum UDP/TCP matrices pass positive、NXDOMAIN/NODATA、EDNS/
      truncation、TLS/HTTP negatives through both direct and real client Shadowsocks detours and cleanup。
- [x] Direct/indirect loop、success/failure cycles、redaction、zero Hickory/process owners and exact
      DNS/detour/upstream/target rebind pass；`TEST-0013` T05、Rust 1.88、footprint and blocking reviews
      pass。

## Validation

Final candidate `853ad9728aa9cc3dedfc8d565db3264d8f1df398` passed the exact TCP graceful-
shutdown case (`1/1`，parent Codex survived)、the complete local E2E suite with 2 and 8 test threads
(`10/10` each)、workspace all-features tests、format/diff checks and schema 3 footprint integrity。
Numeric footprint was reviewed and accepted as `REVIEW_REQUIRED`：code/tests `18238/39723`，ratio
`2.178035`，delta `+316/+2014`，case/support/fixture `+932/+1082/+0`。

Automatic hosted run `31111849601/1` passed exact-SHA CoreDNS/BIND interoperability、quality、footprint、
Rust 1.88 and Windows MSVC/Linux GNU/Linux musl；aggregate qualification job `92652824614` reported
`PASS` with TCP `12/12`、UDP `12/12`、DNS and cleanup all passing。Architect returned `PASS` and QA
returned `PASS_WITH_NOTES` with no blocking finding。Candidate was integrated locally at
`12bde8ba8894ede1bcc4ed664931bb7bf6d782c1`。

The earlier immutable run `31110243307/1` on `4dcd89fa879873dc25ae9f5c1a3ef2635261ac76`
remains failed：interop、footprint、MSRV and platforms passed，while quality exposed one unrelated
concurrent child during the DNS global cleanup probe。The bounded one-line spawn-serialization repair
produced the final candidate above。The single authorized non-force candidate push was consumed；it did
not authorize another push、manual workflow dispatch、PR、tag、package、release or publication。

## Rollback / risk

Rollback restores system resolution and removes DNS external rows；client proxy may remain only if
server DNS config is rejected。Main risk is granting a fresh deadline after lookup or accidentally
routing DNS bootstrap/application targets through the wrong outbound plan。
