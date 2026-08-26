# Test Tree Guidelines

Keep this tree limited to cross-package fixtures, black-box workspace tests, platform qualification,
and performance evidence contracts. Product implementation and crate-owned unit fixtures belong in
their owning package.

Choose the narrowest test layer that observes the contract: stable shared inputs under `fixtures`,
portable process behavior in `m0-harness`, hosted interoperability metadata in `interop`, controller
contracts in `performance_*`, and privileged workflows in `platform`.

Do not make ordinary test discovery execute privileged, hosted-provider, or performance workloads.
