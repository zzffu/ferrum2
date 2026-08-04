---
id: M11-T02
milestone: M11
status: done
depends_on: [M11-T01]
owns:
  - crates/ferrum2-shadowsocks/src/lib.rs
  - crates/ferrum2-shadowsocks/tests/tcp_flow_contract.rs
  - bins/ferrum2-client/src/run.rs
---

# M11-T02 — Compose fixed TCP chains

## Outcome

Open one selected immutable TCP plan in hop order with each concrete outbound's effective credential，
reusing the existing SIP022 client state machine under one connection owner。

## Acceptance

- [x] A mixed-method/distinct-PSK table proves raw dial A、request B through A and final target through
      B；swapped/skipped hop or credential fails。
- [x] The minimum transport composition seam nests existing `ClientFlow` owners without another cipher/
      protocol implementation、dependency or detached per-hop relay task。
- [x] Outer/inner tamper、wrong credential、unavailable/later-hop failure and cancellation terminate the
      full stack with zero retry/fallback/application forwarding and preserved selector state。
- [x] Per-layer buffers、half-close、abortive terminal、deadline and zeroization behavior remain bounded；
      an open flow keeps its selected plan while a later flow may observe a selector switch。
- [x] `TEST-0012` T02、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T02 commands，then repository Full commands before integration。

## Result

- Commit: exact ticket candidate `f1475d90fec87663c882d0ed877c92c1e5d4f6a1`；integrated product
  `e0952534cdcb213d70ad8cb90d8f8913c2db5110`。
- Review: final exact Architect and QA both `PASS_WITH_NOTES`；all
  `ARCH-M11-T02-001..004` and `M11T02-QA-001..003` correctness findings are resolved。
- Notes: `tcp_flow_contract` `9/9`、both client exact rows `1/1`、focused packages `110/110`、
  candidate and integration serial Full、Clippy、format、build、docs and 100+ lifecycle pass；integration
  lifecycle is `1/1` in `135.81s`。Per-hop identity-distinct PSKs close the same-method credential-index
  mutation。A Windows-only TCP-reserved/UDP-bind fixture race was reproduced with `WSAEACCES 10013`，
  repaired by binding UDP port zero first and passed `20/20` exact repetitions。Schema 3 integrity and
  ratio `1.686583` pass；the expected `run.rs` file-size signal remains numeric `REVIEW_REQUIRED` and is
  accepted without adding a helper、dependency or product scope。

## Rollback / risk

Rollback restores one-hop TCP composition while retaining T01 only if chain configs fail closed at run。
The main risk is inner failure being flattened into apparent success or leaving an outer owner live。
