+++
id = "M2-T06"
title = "Prove the focused IPv6 UDP real-process path"
milestone = "M2"
status = "done"
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

- **Ticket branch/candidate:** `codex/ticket/m2-t06` at
  `d1c12627632112826fe3dee884caf5facb291e48`.
- **Owned changes:** `.github/workflows/m0.yml`,
  `crates/ferrum2-shadowsocks/examples/udp_protocol_client.rs`, and
  `tests/m0-harness/tests/udp_local_e2e.rs`; no product protocol, crypto,
  replay, runtime, listener, configuration, or public inbound contract changed.
- **Bounded review cycle:** Architect and QA full reviews at
  `f4fabe8277ef16c41b637a060f48c84418a3fd2f` returned `BLOCK` with
  `ARCH-M2-CLOSE-001` and `QA-M2-CLOSE-001`. After the single evidence repair,
  both targeted reviews at `d1c1262` returned `PASS` and resolved their exact IDs.
- **Reviewer profiles:** configured Architect
  `gpt-5.6-sol/high` and QA `gpt-5.6-sol/medium`; actual serving profiles were
  not exposed and remain unverified.
- **Integrated and remotely qualified product/control SHA:**
  `7907cda05a56e1c3b85af2dd8faeb85a385154b7`. Its control paths are
  tree-equivalent to reviewed `9528679a89853fe7df62b368c6b84c585c811071`,
  and its three T06 paths are tree-equivalent to reviewed `d1c1262`.
- **Local exact-SHA gates:** authoritative quick `3/3`, full `4/4`, workflow
  `75/75`, qualification contract `13/13`, policy `17/17`, and UDP local
  `3 passed / 1 ignored` all passed. Ticket budget passed at code/tests
  delta `0/120`, allowance `120`; milestone budget passed at `3994/3475`,
  allowance `4114`. The Windows host did not execute or credit the ignored
  IPv6 row.
- **Hosted qualification:** the separately authorized single fast-forward push
  of exact `7907cda` to `origin/codex/integration/m2` triggered
  [run `30425476328` attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30425476328).
  All six expected jobs succeeded. Quality executed
  `ipv4_ingress_ipv6_direct_target_round_trips_three_datagrams_and_reaps`
  exactly once with `1 passed / 0 ignored`; its product marker appeared once
  with `datagrams=3` and payload/source/cleanup all `PASS`, and its completion
  marker appeared once with the exact SHA/run/attempt.
- **Regression/interop:** the same run reported provider setup zero, TCP
  `12/12` plus cleanup PASS, UDP `12/12` plus cleanup PASS, and final
  qualification/cleanup status zero. Canonical root `M2-CLOSE-IPV6-001` is
  resolved; no rerun, evidence splice, second push, PR, tag, release, or
  publication occurred.
