---
id: M15-T05
milestone: M15
status: done
depends_on:
  - M15-T04
owns:
  - crates/ferrum2-tun/src/**
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/tun.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/egress/udp.rs
  - bins/ferrum2-client/src/run/tests.rs
  - crates/ferrum2-observability/src/**
  - crates/ferrum2-observability/tests/**
  - tests/m0-harness/tests/architecture.rs
  - tests/platform/qualify_windows_tun.ps1
---

# M15-T05 — Compose TUN UDP mappings and DNS hijack

## Outcome

Accept externally routed IPv4/IPv6 unfragmented UDP through one bounded five-tuple mapping，select one
terminal mode/plan at the first classification-eligible datagram and reuse the existing
`ClientUdpAssociation` and `DnsProxy::answer` paths。Deepen the association's ingress-neutral transitions
once so SOCKS、DNS and TUN do not assemble three security-sensitive mutation loops。

## Acceptance

- [x] Mapping admission、generation、expiry、no-live-eviction、aggregate bytes、queue/drop and accepted-
      activity ordering match SPEC-0016 for both families and MTU boundaries。
- [x] An absent tuple first yields a provisional candidate with no mapping；the client caller returns one
      opaque terminal token/payload bound or drop，and only the owner thread rechecks generation/capacity and
      commits before exact-once first-datagram release。Route/hijack/reject mode and plan remain client-owned；
      `ferrum2-tun` cannot inspect them。Stale/duplicate decisions fail closed。
- [x] First valid route candidate creates one fixed owned plan/association；later datagrams do not re-enter
      ordinary policy or selector，while expiry permits current selection。
- [x] Selector A → over-limit/queue-full no-commit → switch B → valid candidate uses B；after commitment，
      switch C does not affect the live mapping。Rejected candidates create no terminal/activity/SS owner。
- [x] `ClientUdpAssociation` owns one shared reserve/encode/send and receive/authenticate/pop transition；
      wrong target/session/generation responses and invalid inner packets cannot inject or commit state。
- [x] DNS hijack calls `DnsProxy::answer` for accepted requests，keeps ordinary mode terminal，drops malformed
      requests without fallback and creates no Shadowsocks association。Reject retains only a bounded
      tombstone and creates no network owner。
- [x] Saturation and Wintun ring-full drop one complete datagram、do not block the stack thread、do not update
      accepted idle and recover after capacity/expiry；grace/force reaps all mappings and bytes。
- [x] Real IPv4/IPv6 one-hop/chain/selector、DNS、reject、over-limit、binding、expiry and cleanup/rebind rows
      pass。Hosted `windows-tun-e2e` emits the exact `profile=transport functional=16/16 cleanup=PASS`
      SHA/run/attempt marker；a local controller run is diagnostic only。

## Validation

```powershell
cargo test -p ferrum2-tun udp_ --locked
cargo test -p ferrum2-client tun_udp --locked
cargo test -p ferrum2-client tun_dns --locked
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
pwsh -NoProfile -File tests/platform/qualify_windows_tun.ps1 -Mode udp # local diagnostic only
cargo test --workspace --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: `da38170947b8c708d230d14970c4a63f802accf3` / tree
  `53923f6f22fd8c5b35664ba887ad216a0af94fa5` / parent
  `352999160be919520dfa8edf3624ae4c9007d08f`。
- Review: the primary completed the final product and bounded two-file repair review after fresh isolated-VM
  transport evidence；no blocking finding remained。The post-VM repair only made the existing UDP bridge
  compile on unsupported targets and changed no Windows behavior。
- Notes: focused、workspace、MSRV、GNU/musl、Windows-target、strict Clippy、architecture and policy gates
  passed。Fresh VM candidate `352999160be919520dfa8edf3624ae4c9007d08f` emitted
  `profile=transport functional=16/16 cleanup=PASS sha=352999160be919520dfa8edf3624ae4c9007d08f run_id=vm run_attempt=3`
  with zero guest/host residue。
  Its first hosted run [`31360038841/1`](https://github.com/zzffu/ferrum2/actions/runs/31360038841)
  independently passed the Windows transport job but exposed one Linux-only `PACKET_QUANTUM` cfg error；the
  run was not rerun。The exact descendant run
  [`31360570556/1`](https://github.com/zzffu/ferrum2/actions/runs/31360570556) then passed every required job
  and emitted `profile=transport functional=16/16 cleanup=PASS sha=da38170947b8c708d230d14970c4a63f802accf3
  run_id=31360570556 run_attempt=1`；performance correctly skipped。
  Footprint integrity and ratio passed；numeric `REVIEW_REQUIRED` `+693/+0/+0` was accepted as bounded
  product/platform evidence in existing files，with the oversized architecture test retained as debt。No
  force-push、rerun、PR、tag、package、release or publication occurred。

## Rollback / risk

Remove UDP mapping admission/composition while retaining TCP and the T03 foundation。Principal risks are
committing before the plan-specific size check，duplicating SIP022 UDP transitions，accepting a stale response
after slot reuse，or letting queue pressure refresh idle/unbound memory。Fragment support、65,507-byte TUN
datagrams and per-datagram route selection remain out of scope。
