---
id: M15-T04
milestone: M15
status: done
depends_on:
  - M15-T03
owns:
  # Primary-only control lease; the product Engineer keeps these paths read-only.
  - .github/workflows/m0.yml
  - tests/m0-harness/tests/workspace_policy.rs
  # Product Engineer lease.
  - crates/ferrum2-tun/src/**
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/tun.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/context.rs
  - bins/ferrum2-client/src/run/routing.rs
  - bins/ferrum2-client/src/run/tests.rs
  - crates/ferrum2-config/src/**
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-observability/src/**
  - crates/ferrum2-observability/tests/**
  - tests/m0-harness/tests/architecture.rs
  - tests/platform/qualify_windows_tun.ps1
---

# M15-T04 — Compose TUN TCP through existing policy and egress

## Outcome

Accept externally routed IPv4/IPv6 TCP through the TUN flow interface and compose the existing ordered
route/sniff、DNS answerer、client TCP egress and relay lifecycle。The ticket moves the SOCKS-local terminal
selection into one binary-private two-caller module and generalizes the existing DNS-over-TCP adapter once；
it does not publish egress types or copy policy/parser code。

A primary-owned control predecessor adds one closed `workflow_dispatch` target selector before product
work is accepted：normal push/PR and the existing default performance dispatch retain the foundation
profile，while an explicit `windows-tun-tcp` dispatch maps only to controller mode `tcp` and its exact marker。
The product Engineer keeps workflow/policy files read-only；unknown targets and marker mismatches fail closed。

## Acceptance

- [x] One TUN TCP five-tuple creates at most one bounded stream；local handshake semantics、flow ceiling、
      timeout、generation and owner accounting match SPEC-0016。
- [x] Client terminal mapping moves rather than copies；SOCKS behavior and visibility stay exact，and TUN
      TCP sniff rules are accepted only for TUN-only inbound sets。
- [x] Route direct/one-hop/two-hop/selector snapshots use `ClientEgressEngine::open_tcp` and one existing
      relay path；selected open/handshake/I/O failure never evaluates later policy/member/final。
- [x] TLS/HTTP/DNS sniff uses the one parser and one absolute bounded prefix，and every byte is replayed once。
- [x] DNS hijack uses one generalized existing framing loop plus `DnsProxy::answer`，creates no Shadowsocks
      owner and never falls back；reject creates no egress owner。
- [x] Queue saturation closes the advertised receive window without accepted-byte loss；reverse partial
      writes retain bytes；FIN/reset/half-close/idle/grace/force order is deterministic and bounded。
- [x] Real privileged IPv4/IPv6 route、fixed chain、selector snapshot、TLS/HTTP sniff、DNS hijack、reject and
      selected-failure rows pass with exact cleanup/rebind。Hosted `windows-tun-e2e` emits the exact
      `profile=tcp tcp=8/8 cleanup=PASS` SHA/run/attempt marker；a local controller run is diagnostic only。

## Validation

```powershell
cargo test -p ferrum2-tun tcp_ --locked
cargo test -p ferrum2-client tun_tcp --locked
cargo test -p ferrum2-client socks --locked
cargo test -p ferrum2-runtime relay_lifecycle --locked
cargo test -p ferrum2-config --test config_contract --locked tun_
cargo test -p ferrum2-m0-harness --test architecture --locked
pwsh -NoProfile -File tests/platform/qualify_windows_tun.ps1 -Mode tcp # local diagnostic only
cargo test --workspace --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
git diff --check
```

## Result

- Commit: `a7d25a21009a7d2ced6e2c68f8f8b957e389300b` / tree
  `0d428e9abe8c8c78ccd26efbdeb7a49bbd64e141` / parent
  `594eed6a0a3a730d3aab3ceeaabb567fa9f90b7e`。
- Review: fresh isolated-VM `tcp=8/8` passed first；the subsequent exact-candidate Architect and QA reviews
  both returned `PASS` with zero blocker、major or minor finding。
- Notes: local focused、workspace、MSRV、Windows-target、Clippy and architecture gates passed。The exact VM
  marker was `profile=tcp tcp=8/8 cleanup=PASS sha=a7d25a2… run_id=vm run_attempt=1` with zero residue。
  Hosted run [`31344321422/1`](https://github.com/zzffu/ferrum2/actions/runs/31344321422) then passed every
  required job and emitted the same exact marker with its hosted run identity。Footprint integrity and ratio
  passed；numeric `REVIEW_REQUIRED` `+1750/+0/+0` was accepted as necessary mutation/platform evidence in
  existing files，with the oversized architecture test file retained as debt。No force-push、rerun、PR、tag、
  package、release or publication occurred。

## Rollback / risk

Remove TCP admission/composition while retaining T03's rejecting foundation。Primary risks are accepting
locally before an upstream failure without an explicit reset，prefix loss/duplication，queue-full byte loss，
or a copied policy/DNS driver。Any need for paused-SYNACK or upstream-confirmed connect semantics is a new
contract and dependency decision，not an in-ticket expansion。
