+++
id = "M2-T06"
title = "Prove the focused IPv6 UDP real-process path"
milestone = "M2"
status = "ready"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M2-T04", "M2-T05"]
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = ["crates/ferrum2-shadowsocks/examples/udp_protocol_client.rs", "tests/m0-harness/tests/udp_local_e2e.rs", ".github/workflows/m0.yml"]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "The Cargo-managed UDP protocol client keeps its IPv4 Shadowsocks server endpoint and accepts a validated nonzero-port IPv6 direct target without changing wire, key, timeout, or fixed qualification output behavior",
  "One repository-owned ignored AES-128 real-process row sends exactly three distinct datagrams through the IPv4 ferrum2-server UDP ingress to an IPv6-only loopback echo target and proves payload plus exact embedded IPv6 response-source equality",
  "The focused row proves one direct-session socket, reaps the protocol-client and server processes plus echo owner, and rebinds the server TCP/UDP port and IPv6 echo port before emitting its sole redacted PASS marker",
  "Normal Windows quick/full evidence compiles but does not execute or credit the release-only IPv6 row; there is no runtime IPv4 fallback or successful skip path",
  "The Linux quality job builds the example, proves the exact ignored test exists once, executes it once with exact/no-capture semantics, and fails closed unless one PASS marker and one exact SHA/run/attempt completion marker are present",
  "Focused product, qualification-contract, authoritative quick/full, ticket/milestone budget, exact-SHA Architect/QA review, and one authorized six-job hosted qualification all pass without changing the frozen ADR/spec or public UDP inbound scope"
]
+++

# M2-T06: Prove the focused IPv6 UDP real-process path

## Outcome

Close the frozen M2-AC-06 evidence gap with one reproducible real-process row:
IPv4 Shadowsocks UDP ingress through the composed ferrum2 server to an IPv6-only
direct UDP echo target. The row is release-only evidence and does not add an IPv6
server listener or a public client UDP inbound.

## In scope

- Relax only the Cargo-managed `udp_protocol_client` target-family precheck so its
  existing bounded session can encode an IPv6 target while connecting to the existing
  IPv4 Shadowsocks server endpoint.
- Extend the existing UDP process harness with one ignored AES-128 row that executes
  exactly three deterministic datagrams, checks ordered echo payloads, one IPv6
  direct-source socket, the example's exact embedded response source, child/echo
  ownership, and TCP/UDP/IPv6 rebind cleanup.
- Extend Linux `quality` to build the example, reject a missing/duplicate exact test,
  execute the ignored row once, and emit an exact SHA/run/attempt completion marker
  only after its single product PASS marker is observed.

## Out of scope

- Product protocol, crypto, replay, runtime, server-listener, configuration, or public
  API changes.
- An IPv6 Shadowsocks listener, SOCKS5 `UDP ASSOCIATE`, another method/address matrix,
  new external interoperability cases, or changes to the fixed TCP/UDP 12-case plans.
- Runtime skip/fallback counted as PASS, contract weakening, another test harness,
  rerun/spliced hosted evidence, or any publication/release action.

## Contract references

- `SPEC-0003` M2-AC-06 and its focused IPv6 local-product requirement.
- `TEST-0003` T04 process matrix and same-SHA hosted platform completion rule.
- M2-T04 acceptance criterion 4 plus `ARCH-M2-T04-N01` /
  `QA-M2-T04-N01`.
- Close findings `ARCH-M2-CLOSE-001` and `QA-M2-CLOSE-001`; both are derivatives of
  canonical release root `M2-CLOSE-IPV6-001`.

## Primary evidence

- `ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps` is the one
  primary real-process evidence item. It is ignored by normal local gates and has no
  successful runtime skip path.
- The Linux `quality` exact-count/exact-run marker audit is the distinct platform
  layer required because the Windows host cannot execute the IPv6 loopback row.
- Existing three-method IPv4 composition, packet/address tables, and twelve-case
  external interoperability remain regression evidence; they are not duplicated.

## Validation commands

```powershell
cargo build --workspace --bins --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test -p ferrum2-m0-harness --test udp_local_e2e --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python .agents/skills/milestone-workflow/scripts/workflow.py run-validation quick --cwd .
python .agents/skills/milestone-workflow/scripts/workflow.py run-validation full --cwd .
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha> --json
python .agents/skills/milestone-workflow/scripts/workflow.py validate
git diff --check
```

On the IPv6-capable Linux quality runner only:

```bash
cargo test -p ferrum2-m0-harness --test udp_local_e2e \
  ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps \
  --locked -- --ignored --exact --nocapture
```

## Ownership and risks

- One Engineer owns only the three declared paths; Team Lead owns ticket/status,
  runtime ledger, integration, evidence documents, authorization, and remote action.
- The echo socket must be IPv6-only so an IPv4-mapped fallback cannot satisfy the row.
  Diagnostics and markers omit PSKs, ports, peers, session IDs, and packet IDs.
- PASS is emitted only after the example exits successfully, the echo owner observes
  the exact payload triplet from one IPv6 source, the server is reaped, all sockets
  rebind, and the active-child registry returns to baseline.
- Missing example artifacts, zero/duplicate test selection, IPv6 unavailability,
  timeout, payload/source mismatch, child leak, or cleanup failure fail the hosted
  quality job. Windows continues to record the row as **NOT EXECUTED**.

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Required reviewer role/profile and verdict:
- Exact candidate SHA:
- Integrated commit:
