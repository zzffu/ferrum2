---
id: M15-T04
milestone: M15
status: active
depends_on:
  - M15-T03
owns:
  # Primary-only control lease; the product Engineer keeps these paths read-only.
  - .github/workflows/m0.yml
  - tests/m0-harness/tests/workspace_policy.rs
  - crates/ferrum2-tun/src/**
  - bins/ferrum2-client/src/run/tun.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/context.rs
  - bins/ferrum2-client/src/run/routing.rs
  - bins/ferrum2-client/src/run/tests.rs
  - crates/ferrum2-config/src/**
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-observability/src/**
  - crates/ferrum2-observability/tests/**
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

- [ ] One TUN TCP five-tuple creates at most one bounded stream；local handshake semantics、flow ceiling、
      timeout、generation and owner accounting match SPEC-0016。
- [ ] Client terminal mapping moves rather than copies；SOCKS behavior and visibility stay exact，and TUN
      TCP sniff rules are accepted only for TUN-only inbound sets。
- [ ] Route direct/one-hop/two-hop/selector snapshots use `ClientEgressEngine::open_tcp` and one existing
      relay path；selected open/handshake/I/O failure never evaluates later policy/member/final。
- [ ] TLS/HTTP/DNS sniff uses the one parser and one absolute bounded prefix，and every byte is replayed once。
- [ ] DNS hijack uses one generalized existing framing loop plus `DnsProxy::answer`，creates no Shadowsocks
      owner and never falls back；reject creates no egress owner。
- [ ] Queue saturation closes the advertised receive window without accepted-byte loss；reverse partial
      writes retain bytes；FIN/reset/half-close/idle/grace/force order is deterministic and bounded。
- [ ] Real privileged IPv4/IPv6 route、fixed chain、selector snapshot、TLS/HTTP sniff、DNS hijack、reject and
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

- Commit: —
- Review: —
- Notes: hosted execution requires the candidate to descend from the reviewed primary control checkpoint，
  then a later exact-ref `dispatch_target=windows-tun-tcp` authorization。

## Rollback / risk

Remove TCP admission/composition while retaining T03's rejecting foundation。Primary risks are accepting
locally before an upstream failure without an explicit reset，prefix loss/duplication，queue-full byte loss，
or a copied policy/DNS driver。Any need for paused-SYNACK or upstream-confirmed connect semantics is a new
contract and dependency decision，not an in-ticket expansion。
