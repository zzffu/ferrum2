# ferrum2-platform-windows Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-platform-windows` is the Windows x86_64 trust boundary for Wintun loading, adapter/session ownership, managed network state, underlay binding, packet I/O, and teardown. Its only internal Ferrum2 dependency is the platform-neutral `ferrum2-net`; runtime, DNS, configuration, RuleSet, and TUN orchestration must remain callers. Non-Windows implementations are fail-closed stubs; keep their API aligned without simulating success.

`src/windows/core` owns pure and injected contracts, grouped by loader, managed state, network,
notification, strict-route, and session concepts. `src/windows/live` is the only concrete backend;
the Windows root must not grow parallel concept modules or glob-reexport a second ownership surface.

The crate denies unsafe code globally and grants two exact reviewed boundaries: `src/windows/live`
owns every real Win32/Wintun call, while `src/windows/core/raw.rs` contains only safe wrappers around
Windows union and row-layout access used by core logic and hosted tests. Do not add unsafe
code anywhere else or widen either allowance. Every unsafe block must make its FFI, pointer-length,
aliasing, callback-lifetime, thread-safety, byte-order, or handle-ownership invariant evident. Use
RAII for handles, session state, and received packets; `EndSession` must not overlap an active wait.

DLL loading is security-sensitive. Preserve rejection of network/reparse paths, held directory/file identity, the pinned DLL size and SHA-256, System32-scoped dependency loading, and the required export set. Pin changes require reviewed provenance. Platform errors stay redacted; never retain paths, identities, Win32 messages, or network data.

Adapter creation is transactional. Setup failures and cancellation must roll back owned state in reverse order, surface cleanup conflicts, and avoid deleting state no longer matching the journal. Preserve DAD readiness ordering, managed route/DNS readback, underlay snapshot validation, and notification cancellation races.

The managed transaction is family-neutral: IPv4 and IPv6 addresses, MTU state, DAD, capture routes,
DNS leases, and optional strict-route WFP objects must each have exact owned-state readback plus
ownership-safe reverse rollback. Do not scan or classify unrelated external routes. Route,
interface, and address notifications cover both families and publish ordinary network generations;
they must not tear down the long-lived managed plane. Underlay binding is target-aware and
generation-checked; do not restore a unique-default-route assumption. A full send ring returns an
explicit drop outcome without retry or session failure.

## Focused Verification

Run on ordinary Linux or Windows x86_64:

```text
cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked
cargo check -p ferrum2-platform-windows --all-features --locked
```

The explicit no-default-feature library suite is hosted-safe on ordinary Linux and hosted Windows.
Linux exercises target-neutral logic and unsupported-target behavior; hosted Windows additionally
exercises injected operation seams. `live-backend` is the positive production capability and remains
enabled by default and by `--all-features`; hosted test commands must disable default features so the
live Windows module is absent from their dependency graph. Tests must not call `Adapter::create` or
invoke route, address, DNS, WFP, interface, or Hyper-V mutators. Live correctness qualification
remains in the pinned local Hyper-V guest. Live performance may run directly on Windows only through
the repository's dedicated host performance runner, from an already elevated shell, with explicit
network-mutation acknowledgement and per-run transactional ownership/recovery. That runner must not
change default routes, host DNS, WFP, physical adapters, WLAN, sing-box, or unrelated resources.
Hosted unit tests prove transaction semantics, not live-driver behavior; CI must not claim privileged
TUN evidence.
