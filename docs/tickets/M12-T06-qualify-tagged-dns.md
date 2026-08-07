---
id: M12-T06
milestone: M12
status: done
depends_on: [M12-T05]
owns:
  - .github/workflows/m0.yml
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - Cargo.lock
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M12-*.md
  - docs/milestones/M12-tagged-dns-resolution-and-proxy.md
  - docs/roadmap.md
  - docs/test-plans/TEST-0013-m12-tagged-dns-resolution-and-proxy.md
  - docs/tickets/M12-T06-qualify-tagged-dns.md
  - tests/m0-harness/tests/workspace_policy.rs
  - tools/ferrum2-m4-qualification/Cargo.toml
  - tools/ferrum2-m4-qualification/src/m4_support/mod.rs
---

# M12-T06 — Qualify tagged DNS

## Outcome

Qualify one exact M12 integration SHA with focused DNS evidence、all repository gates、three platforms、
existing SIP022 plus new DNS interoperability and separately authorized performance/resource evidence。

## Acceptance

- [x] T01～T05 focused commands and serial Full/MSRV/docs/lifecycle pass on the accepted exact SHA；
      ticket-only evidence is not substituted。
- [x] Rust 1.88、Windows MSVC、Linux GNU/musl、existing SIP022 TCP/UDP `12/12` each plus cleanup and
      direct/detoured CoreDNS/BIND DNS interoperability pass without SHA/run/attempt splicing。
- [x] Schema 3 integrity passes and numeric footprint signals are accepted、reduced or honestly
      reforecast；blocking Architect/QA findings are zero。
- [x] Only after separate explicit authorizations，one non-force push runs automatic qualification and
      one exact-SHA manual dispatch runs required performance/resource evidence。
- [x] Failed exact-SHA evidence remains visible；each changed SHA receives at most one authorized push
      and manual dispatch，with no unchanged-SHA rerun、duplicate dispatch、PR、tag、package、release or
      publication inferred。

## Bounded performance repair lease

Pre-remote review of exact local candidate `af7361ca0185b390b206a7d651629c7f8326b456`
accepted the product architecture、local Full/MSRV/lifecycle evidence and numeric footprint，but
Architect `M12-T06-ARCH-001` and QA `M12-T06-QA-001` independently found that the existing manual
`performance` job still runs only the legacy M4 TCP throughput/resource workload。It therefore cannot
produce the DNS-roots-idle、direct query load、detoured query load、bounded task/RSS and drain evidence
required by `TEST-0013`。

This ticket receives one bounded repair lease to extend the existing `m4-qualification` process/resource
seam and the existing manual job only。The tool may add one `dns-resource` mode，reuse its current
hosted identity、process guard、`/proc` sampler、evidence writer and exact-SHA marker，and use the already
workspace-pinned `hickory-proto` codec for synthetic DNS messages。The manifest、lock and exact
workspace-policy assertions may record only that existing dependency edge。The workload must start
the existing client/server binaries with DNS roots enabled，record an idle baseline，exercise separate
direct and real Shadowsocks-detoured DNS paths under fixed concurrency，record bounded task/fd/RSS
samples，drain and reap all owners，and prove exact listener/upstream rebind。

No product runtime/config surface、second workflow/job/harness/provider、new package identity、public
DNS dependency、performance threshold or claim is authorized。The failed pre-remote candidate remains
visible；no remote authorization was consumed，and authorization is not transferred to the repaired SHA。

## Evidence-driven production repair extension

The exact integrated SHA `17f412be0195b6bc7cd2be7944b64d808442f66f` reproduced the hosted
detoured-DNS failure locally：the server FD count grew monotonically from 16 to 219 in about one
second while its OS task count stayed at 18。Each completed DNS query discarded its client
`PreparedClientUdp` and created a new SIP022 UDP session，while the server correctly retained each
session until its UDP idle deadline。Raising the qualification ceiling would therefore hide a real
production resource regression。

On 2026-08-07 the user authorized all work required to close M12 and required root-cause repair before
continuation。This lease is extended only to reuse idle client DNS UDP associations by exact concrete
detour plan in `dns_egress.rs`，add one focused regression assertion in the existing client test，and
teach the existing qualification mode that a bounded stable connection pool is quiescent before exact
process reap/rebind。No config surface、protocol state machine、second pool/provider or threshold increase
is authorized。

## Validation

Exact product `c06386e9344c07d86ea4a3b63dc73f37f20ceb0e` passed T01～T05 focused reruns；format、
strict workspace Clippy、workspace binary build/all-features tests、Rust 1.88 check/build/test、the
ignored 100+ lifecycle row、workspace docs and diff check。The canonical milestone footprint command
passed integrity and returned the reviewed numeric signal described below。

## Result

- **Identity:** product `c06386e9344c07d86ea4a3b63dc73f37f20ceb0e`，tree
  `4b963c89be0c2709077e3da4076adf0e122d3fe7`。Remote `codex/integration/m12` points exactly to the
  product；the dedicated local closeout commit is a docs-only descendant。
- **Repair:** manual run `31134561696/1` on `17f412be0195b6bc7cd2be7944b64d808442f66f` failed the
  detoured-DNS server owner ceiling。Exact local reproduction showed server FDs rising `16 -> 219` in
  about one second while tasks stayed at `18`。Commit `c06386e9` reuses an idle client SIP022 UDP
  association only for the same static server and exact concrete hop plan；I/O failure discards it and
  the existing UDP manager remains the capacity owner。The sequential regression observes one server
  session，and selector/saturation/rebind cases pass。
- **Footprint/review:** schema 3 integrity/change pass。Code/tests are `18940/39748`，ratio `2.098627`；
  case/support/fixture growth is `6211/1081/0`。The numeric `REVIEW_REQUIRED` signal is accepted because
  it represents independent DNS transport、negative、lifecycle、interop and resource evidence；no fixture、
  second harness、copied DNS codec or second SIP022 data plane was added。Post-repair architecture and QA
  audits report `PASS` with zero blocking finding。
- **Automatic qualification:** push run
  [`31143886273/1`](https://github.com/zzffu/ferrum2/actions/runs/31143886273) completed `success` on the
  exact product。Quality `92759272186`、test-footprint `92759272219`、MSRV `92759272222`、Windows MSVC
  `92759272313`、Linux GNU `92759272198`、Linux musl `92759272250`、interop `92759272257` and
  qualification `92760068203` all succeeded；performance `92759272750` was correctly skipped for the
  push event。Exact markers report SIP022 TCP/UDP `12/12` each plus cleanup、all 12 DNS interop cases、
  DNS cleanup and aggregate PASS for SHA/run/attempt。
- **Manual performance/resource:** workflow-dispatch run
  [`31144255549/1`](https://github.com/zzffu/ferrum2/actions/runs/31144255549) completed all nine jobs
  `success`。Performance job `92760357350` reports ferrum/reference medians
  `137553510/478270805`、ratio `0.287605910`、10 trials；`10000` sessions、`180` samples、RSS windows
  `6/6` and drain PASS；DNS direct `4564`、detoured `4450` queries、48 samples、RSS windows `12/12`、
  bounds/drain/rebind PASS。All five completion markers and the cleanup step bind
  `c06386e9344c07d86ea4a3b63dc73f37f20ceb0e/31144255549/1`。The ratio is diagnostic only。
- **Boundary:** failed run `31134561696/1` remains visible and uncredited。The repaired SHA received one
  non-force push and one manual dispatch；no unchanged-SHA rerun or duplicate dispatch occurred。No PR、
  tag、package、release or publication was performed。

## Rollback / risk

Qualification evidence is immutable and exact-SHA bound。Any future repair、rerun、remote mutation or
publication requires new scope；the closeout commit does not replace the qualified product identity。
