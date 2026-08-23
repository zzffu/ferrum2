# ferrum2-wintun Contributor Notes

This file refines the repository-level `AGENTS.md` for this crate.

## Scope and Boundaries

`ferrum2-wintun` is the Windows x86_64 trust boundary for Wintun loading, adapter/session ownership, managed network state, underlay binding, packet I/O, and teardown. Non-Windows implementations are fail-closed stubs; keep their API aligned without simulating success.

The crate denies unsafe code globally and grants one reviewed exception to `windows.rs`. Do not broaden it. Every unsafe block must make its FFI, pointer-length, aliasing, callback-lifetime, thread-safety, byte-order, or handle-ownership invariant evident. Use RAII for handles, session state, and received packets; `EndSession` must not overlap an active wait.

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

Run on Windows x86_64:

```text
cargo test -p ferrum2-wintun --locked --no-run
```

Execute every Wintun/WFP test and live adapter profile only in the pinned local Hyper-V guest;
ordinary injected-operation tests do not prove live-driver behavior. The local qualification runner
must restore the approved checkpoint, stage host-built artifacts, export evidence, restore the same
checkpoint again, and leave the VM Off. CI must not claim privileged TUN evidence.
