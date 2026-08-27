# Performance Candidate Controller Test Guidelines

These Python unit tests validate candidate-side plan, trial, summary, topology, and bundle-identity
contracts without running benchmarks or privileged networking. Keep fixtures bounded and use explicit
module imports so tests cannot accidentally accept ambient helpers.

Assert exact schema versions, required fields, lineage hashes, and failure behavior. Workload execution
belongs to the external performance workflow, not this test suite.

The runner source-capture contract must prove its canonical Lab closure capture precedes every
PowerShell module or owner load, the bootstrap executes its captured bytes, the runner has no local
capture/stage helpers, and guest file maps use the same locked snapshot. These are offline
control-plane assertions; never invoke the runner here.
