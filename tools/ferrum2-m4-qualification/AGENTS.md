# M4 Qualification Guidelines

## Purpose and Interfaces

`m4-qualification` is a bounded qualification executable, not production runtime code. Its modes are `throughput`, `resource`, `dns-resource`, `profile-workload`, and `self-check`. Keep argument parsing and execution fail-closed: reject unsupported modes, unbounded durations, malformed identities, unsafe paths, and incomplete readiness evidence before starting work.

The `profile-workload` JSONL schema is consumed by `tools/performance_candidate.py`, its tests, and the performance workflow. Coordinate changes across those consumers. Preserve one complete record per trial, explicit parent/candidate identity, metric units, correctness status, and deterministic cleanup. This producer records observations; adoption and regression thresholds belong in the reviewed candidate policy, not here.

## Build and Verification

Use locked commands:

```text
cargo build -p ferrum2-m4-qualification --bin m4-qualification --locked
cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check
python3 -B -m unittest discover -s tests/performance_candidate -v
```

Run `self-check` after changes to parsing, bounds, process control, readiness files, raw evidence, or resource accounting. Add mutation cases that demonstrate malformed input is rejected rather than tests that freeze implementation text.

## Process and Evidence Safety

Cap captured output and worker counts, apply timeouts to probes and drains, and reap every process and thread on all error paths. Write evidence only to caller-selected, validated locations; avoid secrets and plaintext in output. Keep platform-specific assumptions explicit. The repository-level `AGENTS.md` continues to apply.
