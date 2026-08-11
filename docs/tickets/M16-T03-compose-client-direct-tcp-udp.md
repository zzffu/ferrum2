---
id: M16-T03
milestone: M16
status: done
depends_on:
  - M16-T02
owns:
  - crates/ferrum2-runtime/src/connector.rs
  - crates/ferrum2-runtime/src/udp.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run/egress/
  - bins/ferrum2-client/src/run/io.rs
  - bins/ferrum2-client/src/run/observation.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/tun.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
---

# M16-T03 — Compose shared client direct TCP and UDP

## Outcome

Deepen the one binary-private client egress engine so SOCKS、TUN and DNS callers can execute a singleton
direct plan as bounded raw TCP/UDP while every existing Shadowsocks one-hop/chain path remains unchanged。
This ticket deliberately runs without product-owned capture；T04 later injects the Windows binder at the
socket seam established here。

## Acceptance

- [x] Extend the T02 closed `ClientOutboundContext` Direct branch from its pre-socket refusal to raw execution。
      `ClientEgressEngine` alone receives the binary-private closed SOCKS/TUN/DNS request origin plus selected
      plan/original target，dispatches kind and applies binding policy；callers remain kind-agnostic and never
      resolve/bind/create raw sockets。No process-wide TUN-presence check、public trait or second dispatcher exists。
- [x] TUN numeric and SOCKS numeric/domain direct TCP reaches the original target，relays exact bytes and
      half-close，and creates zero SIP022 flow/crypto owner；selected failures never fallback。
- [x] Direct UDP reuses existing bounded resolver/socket/session/cancellation ownership，sends raw payload，
      admits only bound responses and preserves TUN mapping/SOCKS association selection lifetime and limits。
- [x] Direct payload bounds do not subtract SIP022 overhead；invalid/over-limit first datagrams commit no
      mapping/session/activity and a later valid candidate reselects as specified by M15。
- [x] Windows TUN-selected direct whose immutable original target is IPv6 fails before resolver/socket creation
      for TCP and UDP with auto-route off or on，and never falls back unpinned。SOCKS/non-Windows direct
      IPv6 and M15 manual-route IPv6 proxy/reject/DNS behavior remain unchanged。
- [x] In one mixed Windows graph，SOCKS and TUN use the same direct tag for IPv6 TCP and UDP under both auto-
      route states：SOCKS succeeds，TUN fails before resolver/socket，and neither selected failure inspects a
      sibling selector、later rule/final or fallback。DNS origin applies the IPv4 physical-first-hop rule only
      with auto-route on；the exact auto-route-off M15-compatible IPv6 proxy/absent/direct-detour DNS omission
      row retains zero new managed-network state query or mutation。
- [x] DNS no-detour and direct detour normalize to the same direct socket path；proxy detours remain exact。
      No caller retains a raw system connect/bind path that would bypass the future binder。
- [x] Static/rule/final/selector process witnesses cover direct and proxy for SOCKS and memory-device TUN
      IPv4/IPv6 TCP/UDP，including zero proxy-endpoint traffic on direct。
- [x] Planned `m16_redaction` client tests inject target、endpoint、DNS name、tag、packet and secret sentinels
      through direct errors/observations and prove none reaches errors、logs、traces or metric labels。
- [x] Focused runtime/client/process tests、Full-impact architecture guard and footprint disposition pass。

## Validation

```sh
cargo test -p ferrum2-runtime direct_ --locked
cargo test -p ferrum2-client direct_tcp --locked
cargo test -p ferrum2-client direct_udp --locked
cargo test -p ferrum2-client dns_egress --locked
cargo test -p ferrum2-client m16_redaction --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked direct_
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e --locked direct_
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
sh scripts/test-budget.sh ticket --base <accepted-M16-T02-sha> --candidate <candidate-sha>
git diff --check <accepted-M16-T02-sha>..<candidate-sha>
```

## Result

- Accepted base: `bf0a3cb5dc72611952e6874fa7a619d47de3dc0c`。
- Initial candidate: `30f0a6dc9f45ce1d573e8310f081fa2ab1660dea`（tree
  `89a660bf828086e9d48f7d62d35e69dfd09aa4ea`，parent
  `bf0a3cb…`）。Initial Architect `PASS_WITH_NOTES` with `0/0/1` blocker/major/minor，retaining
  `M16-T03-ARCH-001` for the missing MemoryDevice-to-binary TUN process-evidence join。Initial QA
  `PASS_WITH_NOTES` with `0/0/1`，retaining `QA-M16-T03-001` for deterministic Direct UDP raw-limit、
  outstanding-queue and resolver-candidate evidence，plus two non-finding notes。
- Bounded repair: `9f05d94fb143bc37728c7386a628b1216d8c4106`（tree
  `417337dbf48bb88ee06598f3e7d0ea3562762212`，parent `30f0a6d…`），exactly three files、
  `+286/-8`。RED reproduced the concrete four-argument Direct UDP helper mismatch and the absent
  MemoryDevice family/carrier composition guard；GREEN reused the existing resolver/socket traits and private
  test seams without a public API、second manager/dispatcher or T04 capture/binder work。
- Targeted review: Architect `PASS` with `0/0/0` and one accepted note that the non-Cartesian private
  MemoryDevice/binary composition proof is the correct boundary；QA `PASS_WITH_NOTES` with `0/0/0` and only
  the accepted footprint note。Both prior minor findings are closed。
- The first authorized push placed docs-closeout descendant `52beb46368e9baebb1b9757b3d07b446a2d9fab3`
  on `master`。Automatic run `31454190132/1` is preserved failed and was not rerun：quality alone failed on
  Linux Clippy because the Windows-only `DirectIpv6Unsupported` construction left its enum variant
  unconditional；qualification then failed derivatively with `QUALITY_RESULT=failure`，while every other
  substantive job passed。
- Root diagnosed this as a test/gate portability issue。Exact repair
  `85bf3fcc2a12bc1aaa2753bf56023c7850c25d2f`（tree
  `535faddde4d020681655528c3c9eedbd170eb1b4`，parent `52beb463…`）changes exactly two client files、
  `+4/-2`，cfg-gating the variant and its exhaustive SOCKS arm without changing behavior。Architect and QA
  both returned `PASS_WITH_NOTES` with `0/0/0` and one note each：the local Windows host lacked the Linux
  cross-Clippy C toolchain，so hosted Linux Clippy remained authoritative。
- Validation: runtime `direct_` `4`；client `direct_` `4`、`direct_udp` `1`、`direct_tcp` `1`、DNS `7`、
  redaction `1`；full `ferrum2-tun` `15`；full client serial `53`；Direct TCP/UDP real-process E2E `1+1`；
  architecture `19`；workspace all-target check、workspace Clippy `-D warnings`、format、diff and normal hook
  all PASS。The first parallel full-client attempt hit a transient existing Windows UDP bind `WSAEACCES 10013`；
  its row then passed in isolation and the credited serial full run passed `53/53` with zero client/server/
  Cargo/Rust residue。The portability repair retained Direct `4/4`、full client serial `53/53` and architecture
  `19/19`，and passed local workspace check、workspace Clippy `-D warnings`、format、diff and normal hook。
- Footprint: integrity PASS；numeric `REVIEW_REQUIRED` is accepted for necessary mutation-sensitive evidence
  in existing seams，with no support/fixture/new harness。Final code/tests `30341/52324`，ratio
  `1.724531 PASS`，case/support/fixture `46575/5152/597`，ticket deltas `+1133/0/0` and code growth `+245`。
- Remote boundary: an ordinary authorized non-force push advanced `master` from `52beb463…` to `85bf3fcc…`
  with exact readback。Replacement automatic run `31454813712/1` on exact `85bf3fcc…` completed SUCCESS：
  quality、qualification、interop、test-footprint、MSRV、Linux GNU/musl、Windows MSVC and Windows TUN E2E
  all passed；push-event performance jobs skipped by design and are not claimed。Required future non-force
  pushes，including performance-related pushes，remain authorized；dispatch/rerun、force-push、PR、tag、
  package、release and publication remain unauthorized without separate explicit authority。

## Rollback / risk

Rollback restores the all-Shadowsocks dispatch while leaving the accepted config ticket to be reverted with
it if necessary。The dominant risk is duplicating existing direct UDP/session ownership；reuse and owner-count
evidence are required。
