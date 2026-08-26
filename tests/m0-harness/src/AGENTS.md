# M0 Harness Source Guidelines

Code here is test-harness infrastructure, never product implementation. Keep `local_support` and
`external_support` as the stable ownership façades and keep the qualification binary thin.

Helpers must expose observable process, socket, configuration, or evidence behavior without importing
concrete Ferrum2 crates.
