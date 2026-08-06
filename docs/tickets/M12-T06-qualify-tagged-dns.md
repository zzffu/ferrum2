---
id: M12-T06
milestone: M12
status: active
depends_on: [M12-T05]
owns:
  - .github/workflows/m0.yml
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

- [ ] T01～T05 focused commands and serial Full/MSRV/docs/lifecycle pass on the accepted exact SHA；
      ticket-only evidence is not substituted。
- [ ] Rust 1.88、Windows MSVC、Linux GNU/musl、existing SIP022 TCP/UDP `12/12` each plus cleanup and
      direct/detoured CoreDNS/BIND DNS interoperability pass without SHA/run/attempt splicing。
- [ ] Schema 3 integrity passes and numeric footprint signals are accepted、reduced or honestly
      reforecast；blocking Architect/QA findings are zero。
- [ ] Only after separate explicit authorizations，one non-force push runs automatic qualification and
      one exact-SHA manual dispatch runs required performance/resource evidence。
- [ ] No rerun、second push/dispatch、PR、tag、package、release or publication is inferred。

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

## Validation

Run `TEST-0013` T06 focused reruns and its serial integration gate。Remote commands remain blocked until
the user grants exact authorization。

## Rollback / risk

Qualification evidence is immutable and exact-SHA bound。Any failed/partial provider result remains
visible；repair、rerun or new remote mutation requires a new approved scope。
