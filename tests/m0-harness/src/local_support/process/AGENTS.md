# Process Contract Guidelines

`contract.rs` contains focused tests for the process owner's rollback, capture, registration, and reap
semantics. Keep fault injection deterministic and assert externally visible ownership outcomes.

Do not duplicate the production harness implementation or assert private source layout.
