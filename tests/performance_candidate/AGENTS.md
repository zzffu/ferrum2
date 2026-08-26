# Performance Candidate Controller Test Guidelines

These Python unit tests validate candidate-side plan, trial, summary, topology, and bundle-identity
contracts without running benchmarks or privileged networking. Keep fixtures bounded and use explicit
module imports so tests cannot accidentally accept ambient helpers.

Assert exact schema versions, required fields, lineage hashes, and failure behavior. Workload execution
belongs to the external performance workflow, not this test suite.
